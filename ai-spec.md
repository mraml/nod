# AI Project: Shake

## Risk Categorization
This system is categorized as Low-Risk under Annex III.

## Human Oversight Measures
A human reviewer will audit 10% of all generated outputs via the admin dashboard.

## Technical Documentation
Full technical documentation is maintained in the `/docs/architecture` repository.

## Training Data Sources
Data is sourced from public Common Crawl datasets (2023 snapshot) and internal verified wikis.

## Bias Mitigation Strategy
We employ RLHF (Reinforcement Learning from Human Feedback) to reduce toxicity and stereotyping.

## Logging Capabilities
The system logs all transaction IDs and timestamps to a centralized immutable ledger for traceability.

## Record Keeping
Logs are retained for 7 years in cold storage to meet regulatory retention periods.

## Robustness Measures
The model includes a fallback mechanism to a rule-based engine if confidence scores drop below 80%.

## Cybersecurity Measures
We employ adversarial training during the fine-tuning phase to prevent evasion attacks and poisoning.

## Roles and Responsibilities
The Chief AI Officer owns the model lifecycle; DevOps owns deployment uptime.

## Accountability Structure
Final accountability rests with the VP of Engineering.

## Legal Review
Legal counsel has reviewed the Data Privacy Impact Assessment (DPIA) on Jan 14, 2025.

## Context and Goals
The goal is to provide automated customer support. Context is restricted to general inquiries.

## Impact Assessment
We have conducted a stakeholder analysis and identified low risk of economic harm.

## Third-Party Risks
Vendor dependencies are scanned weekly for CVEs.

## Bias Metrics
We measure Disparate Impact Ratio across gender and age groups.

## Fairness Evaluation
Evaluations show a DIR of 0.98, falling within the acceptable range (>0.80).

## Validation Results
Validation on the hold-out set shows 95% accuracy and 99% safety compliance.

## Incident Response Plan
We follow the corporate IR playbook for AI incidents (Playbook-77).

## Risk Treatment Strategy
Residual risks are accepted by the business owner after mitigation.

## Decommissioning Plan
A roadmap exists to retire this model in Q4 2026.

## Input Validation
We use a separate BERT model to detect and block prompt injection attempts.

## Output Sanitization
All output is HTML-escaped and checked for PII patterns before rendering.

## Model Theft Protection
API rate limiting is enforced at 100 req/min to prevent model extraction.

## Supply Chain Security
All upstream models are verified against the corporate SBOM and cryptographically signed.

## PII Filtering
Redaction layers remove SSN and credit card numbers before inference.

## Encryption at Rest
All vector embeddings are stored using AES-256 encryption.

## Encryption in Transit
TLS 1.3 is enforced for all internal and external connections.

## Authentication Mechanisms
Access is restricted via OAuth2 and MFA (Multi-Factor Authentication).

## Authorization Policy
RBAC is implemented; only 'Admins' can retrain models.

## Secrets Management
Keys are injected via HashiCorp Vault; no hardcoded secrets exist.

## Audit Logging
Security-critical events (login, admin actions) are shipped to Splunk.

## Rate Limiting
API is rate-limited to prevent DoS attacks.

## Data Retention Policy
User data is deleted after 30 days.

## Energy Consumption
Estimated carbon footprint is 50kg CO2e per training run.
