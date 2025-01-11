# Compliance Officer Agent - ReACT Implementation  

"""
Compliance Officer Agent Module

This agent generates regulatory-compliant SAR narratives using ReACT prompting.
It takes risk analysis results and creates structured documentation for 
FinCEN submission.
"""

import json
import re
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

try:
    from src.foundation_sar import (
        ComplianceOfficerOutput,
        ExplainabilityLogger, 
        CaseData,
        RiskAnalystOutput,
        TransactionData,
        CustomerData,
        AccountData
    )
except ImportError:
    from foundation_sar import (
        ComplianceOfficerOutput,
        ExplainabilityLogger, 
        CaseData,
        RiskAnalystOutput,
        TransactionData,
        CustomerData,
        AccountData
    )

# Load environment variables
load_dotenv()

class ComplianceOfficerAgent:
    """
    Compliance Officer agent using ReACT prompting framework.
    
    Generates regulatory-compliant SAR narratives under strict BSA/AML standards,
    enforces 120-word limits, provides regulatory citations, and verifies narrative completeness.
    """
    
    def __init__(self, openai_client, explainability_logger, model="gpt-4"):
        """Initialize the Compliance Officer Agent
        
        Args:
            openai_client: OpenAI client instance
            explainability_logger: Logger for audit trails
            model: OpenAI model to use
        """
        self.client = openai_client
        self.logger = explainability_logger
        self.model = model
        
        self.system_prompt = """You are a Senior BSA/AML Compliance Officer responsible for generating formal, regulatory-compliant Suspicious Activity Report (SAR) narratives for submission to the Financial Crimes Enforcement Network (FinCEN).

You must operate using the ReACT (Reasoning + Action) prompting framework:

[REASONING PHASE]
1. Evaluate the Risk Analyst's findings, classification typology, confidence score, and key indicators.
2. Review customer identity, transaction patterns, chronological sequence, locations, and monetary thresholds.
3. Determine mandatory, evidence-based BSA/AML regulatory citations matching the observed conduct:
   - For SAR filing authority: 31 CFR 1020.320 or 31 U.S.C. 5318(g) (mandatory for all filings).
   - If Structuring: 31 U.S.C. 5324 or 31 CFR 1010.314 (evading CTR threshold).
   - If Sanctions: 31 CFR Part 500 et seq. or 50 U.S.C. 1701-1706 (OFAC regulations).
   - If Fraud / Money Laundering: 18 U.S.C. 1956 or 18 U.S.C. 1957.
   Only cite statutes supported by the factual conduct.
4. Verify all five core FinCEN reporting elements (Who, What, When, Where, Why) are covered.

[ACTION PHASE]
1. Draft a concise, factual, objective SAR narrative strictly adhering to the word limit (maximum 120 words).
2. MANDATORY AMOUNT REPORTING: You MUST include the ACTUAL suspicious transaction amounts or aggregate total (e.g., "totaling $29,400.00 across 3 deposits of $9,800.00"). Do NOT merely cite the $10,000 threshold without reporting the actual amounts involved.
3. OBJECTIVE SUSPICION LANGUAGE: Use qualified, objective suspicion language (e.g., "conduct is consistent with potential structuring", "exhibits patterns indicative of rapid fund layering") instead of absolute legal conclusions like "is designed to evade". Ground any demographic or account recency context in documented baseline behavior rather than treating it as standalone evidence of laundering.
4. Perform a rigorous completeness check verifying that Who, What, When, Where, and Why are factually established.

NARRATIVE CONSTRAINTS:
- Strict Word Limit: The narrative must NOT exceed 120 words under any circumstance.
- Non-empty: Must provide a substantive narrative.
- Tone: Formal, objective regulatory compliance report.

You must respond ONLY with a valid JSON object matching the following structure:
```json
{
    "narrative": "Concise SAR narrative covering who, what (with exact amounts), when, where, and why, strictly 120 words or fewer.",
    "narrative_reasoning": "Explanation of ReACT reasoning and action steps taken to draft the narrative.",
    "regulatory_citations": ["31 CFR 1020.320", "31 USC 5324"],
    "completeness_check": true
}
```
Do not include any prose outside the JSON code block."""

    def generate_compliance_narrative(self, case_data: CaseData, risk_analysis: RiskAnalystOutput) -> ComplianceOfficerOutput:
        """
        Generate regulatory-compliant SAR narrative using ReACT framework.
        
        Args:
            case_data: CaseData instance containing case history.
            risk_analysis: RiskAnalystOutput from the Risk Analyst Agent.
            
        Returns:
            Validated ComplianceOfficerOutput object.
            
        Raises:
            ValueError: If word count exceeds 120 words or JSON parsing / substantive validation fails.
        """
        if case_data is None or risk_analysis is None:
            raise ValueError("case_data and risk_analysis cannot be None")

        start_time = time.perf_counter()
        user_prompt = self._build_compliance_prompt(case_data, risk_analysis)
        case_id = getattr(case_data, "case_id", "UNKNOWN_CASE")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                max_tokens=800,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            response_content = response.choices[0].message.content
        except Exception as api_err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.logger:
                self.logger.log_reasoning(
                    agent_type="ComplianceOfficer",
                    step_name="generate_compliance_narrative",
                    prompt=user_prompt,
                    reasoning=f"OpenAI API call failed: {str(api_err)}",
                    parsed_output={},
                    execution_time_ms=elapsed_ms,
                    success=False,
                    metadata={"case_id": case_id}
                )
            raise ValueError(f"OpenAI API call failed: {str(api_err)}")

        try:
            json_str = self._extract_json_from_response(response_content)
            parsed_data = json.loads(json_str)

            narrative = parsed_data.get("narrative", "")
            word_count = len(narrative.split())
            if word_count > 120:
                raise ValueError(f"Generated narrative exceeds 120 word limit ({word_count} words)")
            if not narrative or not narrative.strip():
                raise ValueError("Generated narrative cannot be empty")

            citations = parsed_data.get("regulatory_citations", [])
            completeness = parsed_data.get("completeness_check", False)

            # Substantive compliance validation
            validation = self._validate_narrative_compliance(
                narrative=narrative,
                regulatory_citations=citations,
                completeness_check=completeness,
                case_data=case_data,
                case_id=case_id
            )
            if not validation["is_compliant"]:
                unmet = []
                if not validation["is_length_valid"]:
                    unmet.append(f"word count {word_count} not in range [10, 120]")
                if not validation.get("has_subject", True):
                    unmet.append("missing subject identity (customer name or ID)")
                if not validation.get("has_activity", True):
                    unmet.append("missing transactional activity description")
                if not validation.get("has_timeframe", True):
                    unmet.append("missing dates or timeframe reference")
                if not validation["has_actual_amounts"]:
                    unmet.append("missing actual transaction amounts (or threshold-only/trivial amounts)")
                if not validation.get("has_indicators", True):
                    unmet.append("missing suspicious indicators or pattern description")
                if not validation["has_valid_citations"]:
                    unmet.append("missing or invalid regulatory citations")
                if not validation["completeness_valid"]:
                    unmet.append("completeness check failed or false positive")
                raise ValueError(f"Substantive compliance validation failed: {', '.join(unmet)}")

            output = ComplianceOfficerOutput(**parsed_data)

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.logger:
                self.logger.log_reasoning(
                    agent_type="ComplianceOfficer",
                    step_name="generate_compliance_narrative",
                    prompt=user_prompt,
                    reasoning=output.narrative_reasoning,
                    parsed_output=output.model_dump(),
                    execution_time_ms=elapsed_ms,
                    success=True,
                    metadata={"case_id": case_id}
                )
            return output

        except ValueError as ve:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if "exceeds 120 word limit" in str(ve) or "Substantive compliance" in str(ve) or "cannot be empty" in str(ve):
                if self.logger:
                    self.logger.log_reasoning(
                        agent_type="ComplianceOfficer",
                        step_name="generate_compliance_narrative",
                        prompt=user_prompt,
                        reasoning=str(ve),
                        parsed_output={"raw_response": response_content},
                        execution_time_ms=elapsed_ms,
                        success=False,
                        metadata={"case_id": case_id}
                    )
                raise
            else:
                if self.logger:
                    self.logger.log_reasoning(
                        agent_type="ComplianceOfficer",
                        step_name="generate_compliance_narrative",
                        prompt=user_prompt,
                        reasoning=f"JSON parsing failed: {str(ve)}",
                        parsed_output={"raw_response": response_content},
                        execution_time_ms=elapsed_ms,
                        success=False,
                        metadata={"case_id": case_id}
                    )
                raise ValueError(f"Failed to parse Compliance Officer JSON output: {str(ve)}")
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.logger:
                self.logger.log_reasoning(
                    agent_type="ComplianceOfficer",
                    step_name="generate_compliance_narrative",
                    prompt=user_prompt,
                    reasoning=f"JSON parsing failed: {str(e)}",
                    parsed_output={"raw_response": response_content},
                    execution_time_ms=elapsed_ms,
                    success=False,
                    metadata={"case_id": case_id}
                )
            raise ValueError(f"Failed to parse Compliance Officer JSON output: {str(e)}")

    def _extract_json_from_response(self, response_content: str) -> str:
        """Extract JSON content from LLM response"""
        if not response_content or not response_content.strip():
            raise ValueError("No JSON content found")

        # Check for markdown code blocks (```json ... ``` or ``` ... ```)
        code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response_content, re.IGNORECASE)
        if code_block_match:
            candidate = code_block_match.group(1).strip()
            if candidate.startswith("{") and candidate.endswith("}"):
                return candidate

        # Look for the outermost JSON object braces { ... }
        start_idx = response_content.find("{")
        end_idx = response_content.rfind("}")

        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return response_content[start_idx:end_idx + 1].strip()

        raise ValueError("No JSON content found")

    def _format_risk_analysis_for_prompt(self, risk_analysis: RiskAnalystOutput) -> str:
        """Format risk analysis results for compliance prompt"""
        indicators = ", ".join(risk_analysis.key_indicators) if risk_analysis.key_indicators else "None listed"
        return f"""Risk Classification: {risk_analysis.classification}
Confidence Score: {risk_analysis.confidence_score:.2f}
Assessed Risk Level: {risk_analysis.risk_level}
Key Indicators: {indicators}
Analyst Reasoning: {risk_analysis.reasoning}"""

    def _format_transactions_for_compliance(self, transactions: List[TransactionData]) -> str:
        """Format transaction records for compliance prompt"""
        if not transactions:
            return "No transactions associated with this case."
        lines = []
        for idx, txn in enumerate(transactions, start=1):
            loc_str = f" at {txn.location}" if txn.location else ""
            method_str = f" via {txn.method}" if txn.method else ""
            lines.append(
                f"{idx}. {txn.transaction_date}: ${txn.amount:,.2f} {txn.transaction_type}{loc_str}{method_str}"
            )
        return "\n".join(lines)

    def _build_compliance_prompt(self, case_data: CaseData, risk_analysis: RiskAnalystOutput) -> str:
        """Construct full prompt for compliance narrative generation with factual conflict resolution."""
        cust = case_data.customer
        tx_text = self._format_transactions_for_compliance(case_data.transactions)
        risk_summary = self._format_risk_analysis_for_prompt(risk_analysis)
        total_tx_amount = sum(t.amount for t in case_data.transactions)
        tx_count = len(case_data.transactions)
        
        # Calculate approximate age from DOB and transaction date to protect factual integrity
        age_str = "N/A"
        if cust.date_of_birth:
            try:
                birth_year = int(cust.date_of_birth.split("-")[0])
                ref_year = 2024
                if case_data.transactions and case_data.transactions[0].transaction_date:
                    ref_year = int(case_data.transactions[0].transaction_date.split("-")[0])
                age_str = f"~{ref_year - birth_year} years old (born {cust.date_of_birth})"
            except Exception:
                age_str = f"DOB {cust.date_of_birth}"

        prompt = f"""=== CASE DOSSIER FOR SAR NARRATIVE: {case_data.case_id} ===
Subject Information:
- Name: {cust.name} (ID: {cust.customer_id})
- Date of Birth: {cust.date_of_birth} ({age_str})
- SSN (Last 4): {cust.ssn_last_4}
- Address: {cust.address}
- Risk Rating: {cust.risk_rating}

Transaction Summary:
- Total Suspicious Volume: ${total_tx_amount:,.2f} across {tx_count} transaction(s)

Transaction Activity:
{tx_text}

Risk Analyst Findings:
{risk_summary}

Please apply ReACT methodology:
1. REASONING: Analyze how the subject, transactions, and risk findings satisfy BSA/AML SAR requirements. Identify applicable regulatory citations. Prioritize verified subject records (DOB, age, occupation) over analytical assertions. If analyst claims contradict verified records (e.g. labeling a middle-aged customer as elderly), prioritize verified records and do NOT reproduce false or contradictory claims.
2. ACTION: Draft a precise, regulatory-compliant narrative of 120 words or fewer. You MUST state the ACTUAL transaction amounts or total (${total_tx_amount:,.2f}) and use qualified, objective suspicion language. Perform a completeness check. Output pure JSON."""
        return prompt

    def _validate_narrative_compliance(
        self,
        narrative: str,
        regulatory_citations: Optional[List[str]] = None,
        completeness_check: Optional[bool] = None,
        case_data: Optional[Any] = None,
        case_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate narrative meets regulatory requirements with strict case-grounded substantive checks."""
        words = narrative.strip().split()
        word_count = len(words)
        is_not_empty = bool(narrative and narrative.strip() and word_count >= 5)
        is_length_valid = 10 <= word_count <= 120

        # Require case_data with transactions for source-grounded validation
        if case_data is None:
            return {
                "word_count": word_count,
                "is_not_empty": is_not_empty,
                "is_length_valid": is_length_valid,
                "has_subject": False,
                "has_activity": False,
                "has_timeframe": False,
                "has_dollar_amount": False,
                "has_actual_amounts": False,
                "has_indicators": False,
                "has_valid_citations": False,
                "elements_complete": False,
                "completeness_valid": False,
                "is_compliant": False,
                "rejection_reason": "Missing case_data: Source-grounded compliance validation requires case data."
            }

        # Extract transactions and customer
        case_txns = getattr(case_data, 'transactions', None) or (case_data.get('transactions') if isinstance(case_data, dict) else None)
        if not case_txns:
            return {
                "word_count": word_count,
                "is_not_empty": is_not_empty,
                "is_length_valid": is_length_valid,
                "has_subject": False,
                "has_activity": False,
                "has_timeframe": False,
                "has_dollar_amount": False,
                "has_actual_amounts": False,
                "has_indicators": False,
                "has_valid_citations": False,
                "elements_complete": False,
                "completeness_valid": False,
                "is_compliant": False,
                "rejection_reason": "Missing transactions in case_data: Source-grounded compliance validation requires transactions."
            }

        # 1. Subject check: Grounded in customer name or ID
        customer = getattr(case_data, 'customer', None) or (case_data.get('customer') if isinstance(case_data, dict) else None)
        if customer:
            cust_name = getattr(customer, 'name', None) or (customer.get('name') if isinstance(customer, dict) else '')
            cust_id = getattr(customer, 'customer_id', None) or (customer.get('customer_id') if isinstance(customer, dict) else '')
            name_parts = [p for p in cust_name.split() if len(p) > 2]
            has_subject = bool(
                (cust_id and cust_id in narrative) or
                (cust_name and cust_name in narrative) or
                any(part in narrative for part in name_parts)
            )
        else:
            has_subject = bool(re.search(r"CUST_\w+|Customer\b|Subject\b|[A-Z][a-z]+ [A-Z][a-z]+", narrative))

        # 2. Activity check: Must describe financial/transactional activity
        has_activity = bool(re.search(
            r"\b(?:deposit|deposits|deposited|wire|wires|wired|transfer|transfers|transferred|withdrawal|withdrawals|cash|payment|check)\b",
            narrative,
            re.IGNORECASE
        ))

        # 3. Timeframe check: Grounded in case transaction dates
        case_dates = [
            getattr(t, 'transaction_date', None) or (t.get('transaction_date') if isinstance(t, dict) else None)
            for t in case_txns
        ]
        case_dates = [d for d in case_dates if d]
        if not case_dates:
            min_case_date = ""
            max_case_date = ""
        else:
            min_case_date = min(case_dates)
            max_case_date = max(case_dates)

        narrative_dates = re.findall(r"\b(\d{4}-\d{2}-\d{2})\b", narrative)
        has_temporal_wording = bool(re.search(
            r"\b(?:between\b.+?\band\b|from\b.+?\bto\b|consecutive|daily|over\s+\w+\s+days?|period)\b",
            narrative,
            re.IGNORECASE
        ))

        if narrative_dates:
            # EVERY extracted date must fall within case range [min_case_date, max_case_date] or match transaction dates
            all_dates_valid = all(
                (min_case_date <= d <= max_case_date) or (d in case_dates)
                for d in narrative_dates
            )
            has_timeframe = all_dates_valid
        else:
            has_timeframe = has_temporal_wording

        # 4. Actual amounts check: Strict case-grounded verification
        dollar_matches = re.findall(r"\$\s*([\d,]+(?:\.\d{2})?)", narrative)
        found_amounts = []
        for dm in dollar_matches:
            try:
                found_amounts.append(float(dm.replace(',', '')))
            except ValueError:
                pass

        if not found_amounts:
            has_actual_amounts = False
        else:
            # Standard statutory thresholds
            statutory_thresholds = {10000.0, 3000.0, 5000.0}
            
            # Cannot be ONLY statutory thresholds or trivial amounts
            is_trivial_only = all(amt <= 10.0 for amt in found_amounts)
            is_threshold_only = all(amt in statutory_thresholds for amt in found_amounts)

            if is_trivial_only or is_threshold_only:
                has_actual_amounts = False
            else:
                # Extract all transaction amounts
                raw_amts = [
                    float(getattr(t, 'amount', None) or (t.get('amount') if isinstance(t, dict) else 0.0))
                    for t in case_txns
                ]
                case_cents = [round(abs(a) * 100) for a in raw_amts if abs(a) > 0.001]
                total_cents = sum(case_cents)
                min_cents = min(case_cents) if case_cents else 0

                # Pre-calculate reachable subset sums up to total_cents using set reachability
                non_threshold_found = [a for a in found_amounts if a not in statutory_thresholds]
                
                if not non_threshold_found:
                    has_actual_amounts = False
                else:
                    # Helper to check if a specific non-threshold amount is supported
                    def is_amount_supported(amt_val):
                        target_c = round(amt_val * 100)
                        # Exact or near match individual transaction
                        if any(abs(target_c - tc) <= 5 for tc in case_cents):
                            return True
                        # Exact or near match total
                        if abs(target_c - total_cents) <= 5:
                            return True
                        # Range bound: Cannot exceed total or be lower than minimum
                        if target_c > total_cents + 5 or target_c < min_cents - 5:
                            return False
                        # Check subset sum using candidate filtering and set accumulation
                        candidates = [tc for tc in case_cents if tc <= target_c + 5]
                        if not candidates:
                            return False
                        reachable = {0}
                        for c in candidates:
                            reachable.update([s + c for s in reachable if s + c <= target_c + 5])
                            if any(abs(s - target_c) <= 5 for s in reachable):
                                return True
                        return False

                    # EVERY non-threshold amount must be grounded in the case
                    all_amounts_supported = all(is_amount_supported(amt) for amt in non_threshold_found)
                    has_actual_amounts = all_amounts_supported

        # 5. Indicators check: Must describe suspicious characteristics
        has_indicators = bool(re.search(
            r"\b(?:structur\w*|layering\w*|evad\w*|circumvent\w*|sanction\w*|fraud\w*|deviat\w*|inconsistent\w*|unusual\w*|velocity\w*|prohibited\w*|threshold avoidance|shell)\b",
            narrative,
            re.IGNORECASE
        ))

        # 6. Applicable Citations check: Must reference legitimate BSA/AML/OFAC complete statutory authorities
        complete_citation_patterns = [
            r"31\s+CFR\s+(?:§\s*)?1020\.320(?!\d)\b",
            r"31\s+CFR\s+(?:§\s*)?1010\.311(?!\d)\b",
            r"31\s+CFR\s+(?:§\s*)?1010\.312(?!\d)\b",
            r"31\s+CFR\s+(?:§\s*)?1010\.314(?!\d)\b",
            r"31\s+CFR\s+(?:§\s*)?1020\.311(?!\d)\b",
            r"31\s+CFR\s+Part\s+50[01](?:\s+et\s+seq\.)?\b",
            r"31\s+CFR\s+(?:§\s*)?501\.603(?!\d)\b",
            r"12\s+CFR\s+(?:§\s*)?21\.11(?!\d)\b",
            r"31\s+U\.?S\.?C\.?\s+(?:§\s*)?5324(?!\d)\b",
            r"31\s+U\.?S\.?C\.?\s+(?:§\s*)?5318(?:\([a-z0-9]+\))?(?!\d)\b",
            r"31\s+U\.?S\.?C\.?\s+(?:§\s*)?5313(?!\d)\b",
            r"18\s+U\.?S\.?C\.?\s+(?:§\s*)?1956(?!\d)\b",
            r"18\s+U\.?S\.?C\.?\s+(?:§\s*)?1957(?!\d)\b",
            r"18\s+U\.?S\.?C\.?\s+(?:§\s*)?1343(?!\d)\b",
            r"18\s+U\.?S\.?C\.?\s+(?:§\s*)?1344(?!\d)\b",
            r"50\s+U\.?S\.?C\.?\s+(?:§\s*)?1701(?:\s+et\s+seq\.)?\b",
            r"FinCEN\s+SAR\s+Instructions\b",
        ]
        combined_citation_pattern = "|".join(f"(?:{p})" for p in complete_citation_patterns)

        narrative_citations_valid = bool(re.search(combined_citation_pattern, narrative, re.IGNORECASE))

        list_citations_valid = False
        if regulatory_citations:
            # Every citation in the list must match a complete statutory authority; fabricated entries rejected
            valid_list = [
                cit for cit in regulatory_citations
                if re.match(r"^\s*(?:" + combined_citation_pattern + r")\s*$", cit.strip(), re.IGNORECASE)
            ]
            list_citations_valid = len(valid_list) > 0 and len(valid_list) == len(regulatory_citations)

        has_valid_citations = narrative_citations_valid or list_citations_valid

        # 7. Substantive completeness
        elements_complete = (
            is_not_empty and
            is_length_valid and
            has_subject and
            has_activity and
            has_timeframe and
            has_actual_amounts and
            has_indicators and
            has_valid_citations
        )

        if completeness_check is None:
            completeness_valid = elements_complete
        else:
            completeness_valid = (completeness_check is True and elements_complete)
        is_compliant = elements_complete and completeness_valid

        return {
            "word_count": word_count,
            "is_not_empty": is_not_empty,
            "is_length_valid": is_length_valid,
            "has_subject": has_subject,
            "has_activity": has_activity,
            "has_timeframe": has_timeframe,
            "has_dollar_amount": bool(found_amounts),
            "has_actual_amounts": has_actual_amounts,
            "has_indicators": has_indicators,
            "has_valid_citations": has_valid_citations,
            "elements_complete": elements_complete,
            "completeness_valid": completeness_valid,
            "is_compliant": is_compliant
        }

# ===== REACT PROMPTING HELPERS =====

def create_react_framework():
    """Helper function showing ReACT structure"""
    return {
        "reasoning_phase": [
            "Review risk analysis findings",
            "Assess regulatory requirements", 
            "Identify compliance elements",
            "Plan narrative structure"
        ],
        "action_phase": [
            "Draft concise narrative",
            "Include specific details",
            "Reference activity patterns",
            "Use regulatory language"
        ]
    }

def get_regulatory_requirements():
    """Key regulatory requirements for SAR narratives"""
    return {
        "word_limit": 120,
        "required_elements": [
            "Customer identification",
            "Suspicious activity description", 
            "Transaction amounts and dates",
            "Why activity is suspicious"
        ],
        "terminology": [
            "Suspicious activity",
            "Regulatory threshold",
            "Financial institution",
            "Money laundering",
            "Bank Secrecy Act"
        ],
        "citations": [
            "31 CFR 1020.320 (BSA)",
            "12 CFR 21.11 (SAR Filing)",
            "FinCEN SAR Instructions"
        ]
    }

# ===== TESTING UTILITIES =====

def test_narrative_generation():
    """Test the agent with sample risk analysis"""
    print("🧪 Testing Compliance Officer Agent")
    print("Compliance Officer ready for pipeline execution.")

def validate_word_count(text: str, max_words: int = 120) -> bool:
    """Helper to validate word count"""
    word_count = len(text.split())
    return word_count <= max_words

if __name__ == "__main__":
    print("✅ Compliance Officer Agent Module")
    print("ReACT prompting for regulatory narrative generation")
    test_narrative_generation()
