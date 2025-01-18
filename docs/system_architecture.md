# TRACE Architecture Documentation

## Overview
The **Transactional Risk Analysis & Compliance Engine (TRACE)** is an agentic AI system designed to automate financial crime detection and regulatory filing under the Bank Secrecy Act (BSA) and USA PATRIOT Act. TRACE couples Chain-of-Thought reasoning with ReACT (Reasoning + Acting) narrative generation, guarded by an auditable human authorization gate.

```
                           +------------------------+
                           |  Customer & Txn Data   |
                           +------------------------+
                                       |
                                       v
                           +------------------------+
                           |   Customer Screening   |
                           +------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| STAGE 1: Risk Analyst Agent (Chain-of-Thought Reasoning)                     |
| - Evaluates transaction velocity, counterparty risk, and threshold patterns |
| - Produces structured labeled findings: Review, Patterns, Regulation,       |
|   Severity, Classification, and Normalized Confidence Score                 |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| MANDATORY AUTHORIZATION GATE (Human-in-the-Loop)                             |
| - Strictly separates automated screening from filing authorization          |
| - Policy screening only filters non-suspicious cases; qualifying cases       |
|   default to PENDING_REVIEW until explicit human review                     |
| - Persists structured AUTH_* event to audit log prior to Stage 2            |
+-----------------------------------------------------------------------------+
               |                                               |
        [If APPROVED]                                   [If REJECTED / PENDING]
               |                                               |
               v                                               v
+---------------------------------------+             +-----------------------+
| STAGE 2: Compliance Officer Agent     |             | Stage 2 Bypassed      |
| (ReACT Prompting Framework)           |             | - Zero LLM API calls  |
| - Conduct-grounded regulatory citations|            | - Audit trail retained|
| - Strict word limit (<= 120 words)    |             | - Avoids cost/compute |
| - Substantive multi-factor validation |             +-----------------------+
+---------------------------------------+
               |
               v
+-----------------------------------------------------------------------------+
| FinCEN Form 111 SAR Generation & Cryptographic Verification                 |
| - Verifies authorization integrity (matching case ID, customer ID, AUTH_*)   |
| - Produces dual JSON and text filings                                       |
| - Cryptographic SHA-256 tamper-evident checksum                              |
+-----------------------------------------------------------------------------+
```

## Agent Design & Prompting Frameworks

### 1. Risk Analyst Agent (Chain-of-Thought)
- **Role**: Evaluates customer transaction histories, account profiles, and counterparty entities to identify suspicious typologies.
- **Prompting Methodology**: Zero-shot Chain-of-Thought prompting instructing the model to work systematically through:
  1. Transaction velocity and volumetric anomalies.
  2. Counterparty sanction status and relationship analysis.
  3. Proximity to statutory thresholds ($10,000 CTR limit).
  4. Structured labeled findings: `[Review]`, `[Patterns]`, `[Regulation]`, `[Severity]`, and `[Classification]`.
- **Fault-Tolerant Recovery**: Implements bounded schema-guided regeneration upon parsing or JSON extraction failure. Preserves raw model output and error context if unrecoverable, returning a terminal failure contract without fabricating synthetic classifications.

### 2. Mandatory Human Authorization Gate
- **Architecture**: Positioned strictly between Stage 1 risk screening and Stage 2 compliance generation.
- **Policy Invariant**: Automated rules alone never authorize a SAR filing. Automated screening filters non-qualifying cases (`decision = "REJECTED"`), while qualifying cases remain `PENDING_REVIEW` until an authorized compliance officer renders an explicit `APPROVED` or `REJECTED` decision.
- **Audit Persistence**: Every authorization decision generates a unique `AUTH_*` event recorded in `workflow_integration.jsonl` prior to invoking Stage 2.

### 3. Compliance Officer Agent (ReACT)
- **Role**: Synthesizes investigative findings into a concise, legally defensible FinCEN Form 111 SAR narrative.
- **Prompting Methodology**: ReACT (Reasoning + Acting) framework:
  1. **Thought / Reasoning**: Evaluates statutory reporting triggers under 31 CFR 1020.320 and specific criminal codes (e.g., 31 U.S.C. 5324 for structuring; 18 U.S.C. 1956 for money laundering).
  2. **Action**: Drafts objective, qualified narrative text stating verified monetary amounts and establishing essential reporting elements (Who, What, When, Where, Why).
  3. **Verification**: Assesses word count (<= 120 words) and ensures conduct-grounded citations.

### 4. Substantive Compliance Validation
Before any narrative is accepted or packaged into a filing:
- **Subject Verification**: Verifies customer name or customer ID appears in the narrative.
- **Activity Grounding**: Ensures transactional verbs (deposit, wire, transfer) are present.
- **Temporal Specificity**: Confirms explicit dates or temporal patterns.
- **Actual Monetary Amounts**: Enforces actual transaction amounts or aggregate totals, rejecting threshold-only figures ($10,000 alone) or trivial amounts ($1).
- **Qualified Language**: Requires objective, qualified suspicion phrasing ("is consistent with potential structuring") rather than unqualified assertions of intent.
- **Supported Citations**: Rejects fabricated or conduct-mismatched citations.

### 5. Cryptographic Verification & Tamper-Evidence
Every generated SAR includes a SHA-256 verification checksum:
$$\text{Checksum} = \text{SHA256}(\text{SAR\_ID} \parallel \text{Case\_ID} \parallel \text{Customer\_ID} \parallel \text{Narrative})$$
This ensures cryptographic tamper-evidence between JSON records, human-readable text filings, and downstream audit logs.
