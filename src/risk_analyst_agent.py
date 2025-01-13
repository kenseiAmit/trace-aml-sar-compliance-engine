# Risk Analyst Agent - Chain-of-Thought Implementation

"""
Risk Analyst Agent Module

This agent performs suspicious activity classification using Chain-of-Thought reasoning.
It analyzes customer profiles, account behavior, and transaction patterns to identify
potential financial crimes.
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
        RiskAnalystOutput, 
        ExplainabilityLogger, 
        CaseData,
        AccountData,
        TransactionData,
        CustomerData
    )
except ImportError:
    from foundation_sar import (
        RiskAnalystOutput, 
        ExplainabilityLogger, 
        CaseData,
        AccountData,
        TransactionData,
        CustomerData
    )

# Load environment variables
load_dotenv()

class RiskAnalystAgent:
    """
    Risk Analyst agent using Chain-of-Thought reasoning.
    
    Performs systematic financial crime analysis, classifying suspicious activity patterns,
    generating structured JSON output, logging every step for compliance auditability.
    """
    
    def __init__(self, openai_client, explainability_logger, model="gpt-4"):
        """Initialize the Risk Analyst Agent
        
        Args:
            openai_client: OpenAI client instance
            explainability_logger: Logger for audit trails
            model: OpenAI model to use
        """
        self.client = openai_client
        self.logger = explainability_logger
        self.model = model
        
        self.system_prompt = """You are an experienced Financial Crime Risk Analyst with deep expertise in BSA/AML regulations and anti-money laundering investigations.

Your task is to analyze cases for suspicious activity using a systematic Chain-of-Thought (step-by-step) reasoning methodology.

Follow this 5-step Chain-of-Thought analysis framework:
1. Data Review: Systematically examine customer background, KYC risk profile, account history, and transaction records.
2. Pattern Recognition: Identify specific anomalies, transaction velocity, counterparty concerns, and red flags.
3. Regulatory Mapping: Map observed patterns against established typologies and regulatory guidelines.
4. Risk Quantification: Assess the overall severity, potential financial crime impact, and probability.
5. Classification Decision: Formulate the final classification, assign a calibrated confidence score (0.0 to 1.0), and specify risk level.

You must classify each case into exactly ONE of the following classification categories:
- Structuring: Transactions designed to evade BSA currency reporting thresholds (e.g., repeatedly depositing cash just under $10,000).
- Sanctions: Involving sanctioned entities, jurisdictions, Specially Designated Nationals (SDNs), or high-risk geographic corridors.
- Fraud: Identity theft, account takeover, unauthorized disbursements, or deceptive transactional behavior.
- Money_Laundering: Complex schemes, layering, rapid fund movement across unrelated accounts, trade-based money laundering, or shell entities.
- Other: Suspicious behavioral anomalies or regulatory red flags not fitting standard categories.

Risk levels must be one of: "Low", "Medium", "High", "Critical".

In your reasoning summary, return concise, labeled findings covering each dimension:
[Review] <concise findings on customer/KYC and account baseline>; [Patterns] <specific anomalies, counterparty signals, velocity>; [Regulation] <applicable BSA/AML statutes or typologies>; [Severity] <impact and risk level rationale>; [Classification] <final typology decision and confidence calibration>.

You must respond ONLY with a valid JSON object matching the following structure:
```json
{
    "classification": "Structuring | Sanctions | Fraud | Money_Laundering | Other",
    "confidence_score": 0.85,
    "reasoning": "[Review] ...; [Patterns] ...; [Regulation] ...; [Severity] ...; [Classification] ...",
    "key_indicators": ["indicator 1", "indicator 2", "indicator 3"],
    "risk_level": "Low | Medium | High | Critical"
}
```
Do not include any narrative outside the JSON block. Ensure your JSON is completely valid and parseable."""

    def analyze_case(self, case_data: CaseData) -> RiskAnalystOutput:
        """
        Perform risk analysis on a case using Chain-of-Thought reasoning.
        
        Args:
            case_data: CaseData instance containing customer, accounts, and transactions.
            
        Returns:
            Validated RiskAnalystOutput object.
            
        Raises:
            ValueError: If input is invalid or JSON parsing/validation fails.
        """
        if case_data is None:
            raise ValueError("case_data cannot be None")

        start_time = time.perf_counter()
        user_prompt = self._format_case_for_prompt(case_data)
        case_id = getattr(case_data, "case_id", "UNKNOWN_CASE")

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.3,
                max_tokens=1000,
                messages=messages
            )
            response_content = response.choices[0].message.content
        except Exception as api_err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.logger:
                self.logger.log_reasoning(
                    agent_type="RiskAnalyst",
                    step_name="case_analysis",
                    prompt=user_prompt,
                    reasoning=f"OpenAI API call failed: {str(api_err)}",
                    parsed_output={},
                    execution_time_ms=elapsed_ms,
                    success=False,
                    metadata={"case_id": case_id}
                )
            raise ValueError(f"OpenAI API call failed: {str(api_err)}")

        # Attempt to parse response with bounded regeneration recovery
        max_attempts = 2
        current_content = response_content
        last_error = None

        for attempt in range(max_attempts):
            try:
                json_str = self._extract_json_from_response(current_content)
                parsed_data = json.loads(json_str)
                output = RiskAnalystOutput(**parsed_data)

                elapsed_ms = (time.perf_counter() - start_time) * 1000
                if self.logger:
                    self.logger.log_reasoning(
                        agent_type="RiskAnalyst",
                        step_name="case_analysis",
                        prompt=user_prompt,
                        reasoning=output.reasoning,
                        parsed_output=output.model_dump(),
                        execution_time_ms=elapsed_ms,
                        success=True,
                        metadata={"case_id": case_id, "attempt": attempt + 1}
                    )
                return output

            except Exception as parse_err:
                last_error = parse_err
                if attempt == 0 and max_attempts > 1:
                    # Bounded regeneration: ask model to regenerate strictly compliant JSON
                    try:
                        recovery_prompt = (
                            f"Your previous response failed parsing/schema validation: {str(parse_err)}. "
                            "Please regenerate the analysis and return ONLY a strictly valid JSON object complying exactly with the required schema."
                        )
                        retry_messages = [
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": user_prompt},
                            {"role": "assistant", "content": current_content or ""},
                            {"role": "user", "content": recovery_prompt}
                        ]
                        retry_resp = self.client.chat.completions.create(
                            model=self.model,
                            temperature=0.1,
                            max_tokens=1000,
                            messages=retry_messages
                        )
                        current_content = retry_resp.choices[0].message.content
                        continue
                    except Exception:
                        pass
                break

        # Terminal failure contract: log failure and raise ValueError without fabricating fake results
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        if self.logger:
            self.logger.log_reasoning(
                agent_type="RiskAnalyst",
                step_name="case_analysis",
                prompt=user_prompt,
                reasoning=f"JSON parsing failed: {str(last_error)}",
                parsed_output={"raw_response": current_content},
                execution_time_ms=elapsed_ms,
                success=False,
                metadata={"case_id": case_id, "terminal_error": str(last_error)}
            )
        raise ValueError(f"Failed to parse Risk Analyst JSON output: {str(last_error)}")

    def _extract_json_from_response(self, response_content: str) -> str:
        """Extract JSON content from LLM response
        
        Handles markdown code blocks, embedded JSON, and raises ValueError if absent.
        """
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

    def _format_accounts(self, accounts: List[AccountData]) -> str:
        """Format account information for prompt inclusion"""
        if not accounts:
            return "No accounts associated with this case."
        lines = []
        for acc in accounts:
            lines.append(
                f"- Account ID: {acc.account_id}, Type: {acc.account_type}, "
                f"Balance: ${acc.current_balance:,.2f}, "
                f"Avg Monthly Balance: ${acc.average_monthly_balance:,.2f}, "
                f"Status: {acc.status}"
            )
        return "\n".join(lines)

    def _format_transactions(self, transactions: List[TransactionData]) -> str:
        """Format transaction records for prompt inclusion"""
        if not transactions:
            return "No transactions associated with this case."
        lines = []
        for idx, txn in enumerate(transactions, start=1):
            counterparty_str = f" to/from {txn.counterparty}" if txn.counterparty else ""
            loc_str = f" at {txn.location}" if txn.location else ""
            method_str = f" via {txn.method}" if txn.method else ""
            lines.append(
                f"{idx}. {txn.transaction_date}: {txn.transaction_type} ${txn.amount:,.2f} - {txn.description}{counterparty_str}{loc_str}{method_str}"
            )
        return "\n".join(lines)

    def _format_case_for_prompt(self, case_data: CaseData) -> str:
        """Format case data for the analysis prompt"""
        cust = case_data.customer
        total_tx_amount = sum(t.amount for t in case_data.transactions)
        tx_count = len(case_data.transactions)
        
        accounts_text = self._format_accounts(case_data.accounts)
        tx_text = self._format_transactions(case_data.transactions)
        
        prompt = f"""=== CASE FILE: {case_data.case_id} ===
Customer Information:
- Customer ID: {cust.customer_id}
- Name: {cust.name}
- Date of Birth: {cust.date_of_birth}
- SSN Last 4: {cust.ssn_last_4}
- Address: {cust.address}
- Customer Since: {cust.customer_since}
- Current Risk Rating: {cust.risk_rating}

Associated Accounts:
{accounts_text}

Transaction History ({tx_count} records, Total Amount: ${total_tx_amount:,.2f}):
{tx_text}

Please evaluate this case step-by-step using the 5-step Chain-of-Thought methodology and return your structured JSON assessment."""
        return prompt

# ===== PROMPT ENGINEERING HELPERS =====

def create_chain_of_thought_framework():
    """Helper function showing Chain-of-Thought structure"""
    return {
        "step_1": "Data Review - Examine all available information",
        "step_2": "Pattern Recognition - Identify suspicious indicators", 
        "step_3": "Regulatory Mapping - Connect to known typologies",
        "step_4": "Risk Quantification - Assess severity level",
        "step_5": "Classification Decision - Determine final category"
    }

def get_classification_categories():
    """Standard SAR classification categories"""
    return {
        "Structuring": "Transactions designed to avoid reporting thresholds",
        "Sanctions": "Potential sanctions violations or prohibited parties",
        "Fraud": "Fraudulent transactions or identity-related crimes",
        "Money_Laundering": "Complex schemes to obscure illicit fund sources", 
        "Other": "Suspicious patterns not fitting standard categories"
    }

# ===== TESTING UTILITIES =====

def test_agent_with_sample_case():
    """Test the agent with a sample case"""
    print("🧪 Testing Risk Analyst Agent")
    customer = CustomerData(
        customer_id="CUST_DEMO",
        name="Demo Customer",
        date_of_birth="1985-05-15",
        ssn_last_4="5555",
        address="100 Wall Street, New York, NY",
        customer_since="2018-03-01",
        risk_rating="High"
    )
    account = AccountData(
        account_id="ACC_DEMO",
        customer_id="CUST_DEMO",
        account_type="Checking",
        opening_date="2018-03-01",
        current_balance=25000.0,
        average_monthly_balance=5000.0,
        status="Active"
    )
    transactions = [
        TransactionData(
            transaction_id="TX_DEMO_1",
            account_id="ACC_DEMO",
            transaction_date="2025-01-10",
            transaction_type="Cash_Deposit",
            amount=9800.0,
            description="Branch Cash Deposit",
            method="Cash",
            location="Downtown Branch"
        ),
        TransactionData(
            transaction_id="TX_DEMO_2",
            account_id="ACC_DEMO",
            transaction_date="2025-01-11",
            transaction_type="Cash_Deposit",
            amount=9900.0,
            description="Branch Cash Deposit",
            method="Cash",
            location="Airport Branch"
        )
    ]
    case = CaseData(
        case_id="CASE_DEMO",
        customer=customer,
        accounts=[account],
        transactions=transactions,
        case_created_at=datetime.now().isoformat(),
        data_sources={"crm": "core_banking"}
    )
    print(f"Created sample case: {case.case_id} with {len(transactions)} transactions.")

if __name__ == "__main__":
    print("🔍 Risk Analyst Agent Module")
    print("Chain-of-Thought reasoning for suspicious activity classification")
    test_agent_with_sample_case()
