# **Project: GreenField AI (Fully Compliant Spec)**

This specification is designed to demonstrate full compliance with EU AI Act, NIST AI RMF, OWASP LLM Top 10, and standard Security Baselines.

## **1\. EU AI Act Alignment (High-Risk)**

### **Risk Categorization**

This system is categorized as **High-Risk** under Annex III (Biometric/Employment/Critical Infra). We acknowledge this classification and adhere to strict conformity assessments.

### **Training Data Sources**

Data is sourced from the "Common Crawl 2024" (filtered subset), internal verified corporate wikis, and licensed partner datasets (Legal-Corp-Data v2).

### **Bias Mitigation Strategy**

We employ a multi-stage strategy: 1\) Pre-training data filtration for toxic patterns, 2\) RLHF (Reinforcement Learning from Human Feedback) with diverse demographic labelers, and 3\) Post-processing bias detection.

### **Technical Documentation**

Full technical documentation (compliant with Annex IV) is maintained in the internal Git repository under `/docs/technical` and generated via Sphinx.

### **Logging Capabilities**

The system generates immutable logs for every inference event, capturing input hash, output hash, timestamp, and model version, enabling full traceability of functioning.

### **Record Keeping**

Logs are retained for a minimum of 10 years in Write-Once-Read-Many (WORM) storage to comply with regulatory retention periods.

### **Human Oversight Measures**

We implement a "Human-in-the-loop" (HITL) mechanism. Any output with a confidence score below 0.85 is routed to a human subject matter expert for review before release.

### **Robustness Measures**

The model includes fallback mechanisms to deterministic rule-engines if stochastic outputs drift. We test against common distribution shifts and noise.

### **Cybersecurity Measures**

We employ adversarial training to defend against poisoning. The model infrastructure is protected by a WAF and strictly segmented networks.

## **2\. NIST AI RMF (Govern, Map, Measure, Manage)**

### **Roles and Responsibilities**

* **Chief AI Officer:** Accountable for overall system safety.  
* **ML Ops Lead:** Responsible for daily monitoring and drift detection.  
* **Legal Counsel:** Responsible for regulatory alignment reviews.

### **Accountability Structure**

Final accountability rests with the VP of Engineering. An escalation path exists from the Safety Team directly to the Ethics Committee.

### **Legal Review**

This spec and the underlying model architecture were reviewed by the Legal & Compliance team on Q1 2025 (Ref: TICKET-LEG-99).

### **Context and Goals**

The goal is to summarize legal documents for internal staff. The context is strictly low-latency, high-accuracy professional settings.

### **Impact Assessment**

A stakeholder impact assessment was conducted. Risks include "hallucination of case law." Impact is mitigated by citing sources.

### **Third-Party Risks**

We track all upstream base models (e.g., Llama-3) and libraries (PyTorch, HuggingFace) via Software Composition Analysis (SCA).

### **Bias Metrics**

We measure demographic parity difference (DPD) and equal opportunity difference (EOD) across protected groups (Gender, Race).

### **Fairness Evaluation**

Evaluations indicate a DPD of \< 0.05, which falls within our acceptable fairness threshold. Reports are generated weekly.

### **Validation Results**

Validation on the "LegalBench" hold-out set demonstrates 96% accuracy and 99.9% refusal of unsafe prompts.

### **Incident Response Plan**

We follow the "AI Incident Playbook v2." Triggers include model collapse or toxic output bursts. Response time target is \< 1 hour.

### **Risk Treatment Strategy**

We apply a "Mitigate" strategy for bias risks (via RLHF) and an "Avoid" strategy for medical advice (via refusals).

### **Decommissioning Plan**

A roadmap exists to retire this model version 6 months after the release of the next major version, with data sanitization procedures in place.

## **3\. OWASP LLM Top 10 Defenses**

### **Input Validation**

We use a dedicated BERT-based classifier (`PromptGuard`) to detect and block Prompt Injection attacks and Jailbreak attempts before they reach the LLM.

### **Output Sanitization**

All model outputs are sanitized to remove executable code blocks (unless requested) and escaped to prevent XSS in the frontend.

### **Model Theft Protection**

API access is rate-limited (100 req/min). We use watermarking on generated text to detect unauthorized scraping or model distillation.

### **Supply Chain Security**

All model weights are cryptographically signed (Sigstore) and verified against a Software Bill of Materials (SBOM) before deployment.

### **PII Filtering**

A PII-redaction layer (Presidio) runs on both inputs and outputs to detect and mask SSNs, emails, and phone numbers.

## **4\. Security Baseline**

### **Data Retention Policy**

User input data is retained for 30 days for debugging, then permanently deleted. Training data is retained for the life of the model.

### **Encryption at Rest**

All databases, object storage buckets (S3), and persistent volumes are encrypted using **AES-256**.

### **Encryption in Transit**

All data in motion is encrypted using **TLS 1.3** with strong ciphers. HTTP is disabled; HTTPS is enforced.

### **Authentication Mechanisms**

Strict authentication is enforced via **OAuth 2.0** / OpenID Connect (OIDC). Multi-Factor Authentication (MFA) is required for admin access.

### **Authorization Policy**

We use Role-Based Access Control (RBAC). Only the "Data Scientist" role can trigger training runs; only "Read-Only" users can query.

### **Secrets Management**

No secrets are hardcoded. API keys and database credentials are injected at runtime via **HashiCorp Vault**.

### **Audit Logging**

Security-critical events (login failures, key access, admin changes) are logged to a centralized SIEM (Splunk/DataDog).

### **Rate Limiting**

The API gateway enforces per-user and per-IP rate limits to prevent Denial of Service (DoS) attacks and resource exhaustion.

### **Energy Consumption**

We estimate carbon emissions at 500kg CO2e per training run. We schedule training during off-peak hours to utilize greener energy grids.

