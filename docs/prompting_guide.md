# TRACE Prompting Guide: Agent Reasoning and Planning

This guide documents the prompt engineering methodologies implemented in TRACE (Transactional Risk Analysis & Compliance Engine) for financial crime detection and regulatory filing.

---

## 1. System Prompting Strategy

TRACE utilizes a two-stage agentic workflow where each agent is assigned a specialized institutional persona, explicit decision boundaries, and rigid output contracts.

### Stage 1: Risk Analyst Agent (Chain-of-Thought)
- **Role**: Senior Financial Crime & Anti-Money Laundering (AML) Investigator.
- **Objective**: Conduct comprehensive transactional risk assessments across five typologies: `Structuring`, `Money_Laundering`, `Sanctions`, `Fraud`, and `Other`.
- **Reasoning Method**: Step-by-step Chain-of-Thought (CoT) prompting enforcing labeled findings:
  1. `[Review]`: Customer profile, account baselines, and documented activity.
  2. `[Patterns]`: Concrete transactional observations (velocity, amounts, locations, counterparties).
  3. `[Regulation]`: Relevant statutory obligations (BSA, 31 CFR, 18 U.S.C., OFAC).
  4. `[Severity]`: Objective risk tier (`Low`, `Medium`, `High`, `Critical`).
  5. `[Classification]`: Definitive typology selection and confidence score.

#### Prompt Template Structure:
```text
System Prompt:
You are a Senior AML Compliance Analyst at a premier financial institution.
Your duty is to objectively evaluate transactional patterns against historical baselines
and regulatory frameworks. Provide structured reasoning with labeled sections:
[Review], [Patterns], [Regulation], [Severity], [Classification].

User Prompt:
CUSTOMER PROFILE:
- Name: {customer_name}
- ID: {customer_id}
- Risk Rating: {risk_rating}
- Occupation: {occupation}
- Annual Income: ${annual_income}

TRANSACTION HISTORY ({count} transactions):
{transaction_table_with_counterparties_and_locations}

REQUIRED JSON OUTPUT:
{
  "classification": "Structuring" | "Money_Laundering" | "Sanctions" | "Fraud" | "Other",
  "confidence_score": 0.0 - 1.0,
  "risk_level": "Low" | "Medium" | "High" | "Critical",
  "reasoning": "[Review] ... [Patterns] ... [Regulation] ... [Severity] ... [Classification] ...",
  "key_indicators": ["...", "..."]
}
```

---

## 2. Stage 2: Compliance Officer Agent (ReACT Prompting)

- **Role**: FinCEN Regulatory Compliance Officer.
- **Objective**: Synthesize Risk Analyst findings into a legally defensible, concise Suspicious Activity Report (FinCEN Form 111) narrative under 120 words.
- **Reasoning Method**: ReACT (Reasoning + Acting) execution cycle:
  1. `Thought`: Evaluate which statutory authorities apply based on the confirmed typology and transaction facts.
  2. `Action`: Query regulatory provisions (`31 CFR 1020.320`, `31 U.S.C. 5324`, `31 CFR 1010.311`, `18 U.S.C. 1956`, etc.).
  3. `Observation`: Retrieve exact statutory standards and verify case facts (dates, amounts, counterparties).
  4. `Final Narrative`: Synthesize the SAR narrative adhering strictly to FinCEN standards:
     - Clear identification of subject and timeframe.
     - Exact dollar figures and ranges derived directly from transaction records.
     - Qualified suspicion phrasing (e.g., "is consistent with potential structuring").
     - Length strictly under 120 words.
     - Accurate statutory citations.

#### ReACT Narrative Constraints:
- Derives numerical amounts and ranges directly from verified transaction records.
- Distinguishes CTR evasion (`31 CFR 1010.311` / `31 U.S.C. 5324`) from SAR reporting authority (`31 CFR 1020.320`).
- Avoids definitive accusations ("committed crime"), maintaining qualified suspicion ("indicates patterns consistent with").

---

## 3. Robust JSON Parsing & Schema Recovery

When LLMs return Markdown fences or malformed JSON, TRACE applies a bounded regeneration loop (up to 3 attempts):
1. Strips markdown fences (` ```json ... ``` `).
2. Balances braces and extracts substrings bounded by `{` and `}`.
3. Validates against Pydantic models (`RiskAnalystOutput` / `ComplianceOfficerOutput`).
4. If validation fails, submits the parsing error back to the model with an explicit correction prompt.
5. If terminal failure occurs, escalates to `MANUAL_REVIEW_REQUIRED` without fabricating misleading default classifications or confidence scores.
