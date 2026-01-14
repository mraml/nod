# **Project: FinBot Sentinel (Compliant Example)**

## **1\. EU AI Act Compliance**

### **Risk Categorization**

This system is categorized as **High-Risk** under Annex III (Credit scoring evaluation). It undergoes strict conformity assessments.

### **Human Oversight Measures**

We implement a "Human-in-the-loop" strategy. All loan denials are routed to a loan officer for final review.

### **Technical Documentation**

Full technical documentation (Annex IV) is stored in the `/docs/tech` folder and referenced in the SBOM.

### **Data Governance**

**Training Data Sources:** We use the FICO-2023 sanitized dataset. **Bias Mitigation Strategy:** We apply re-weighting techniques to ensure demographic parity across protected groups.

## **2\. NIST AI RMF Alignment**

### **Map: Context and Goals**

The goal is to automate initial credit screening. Context is strictly regulated financial services.

### **Measure: Bias Metrics**

We use Disparate Impact Ratio (DIR) and Equal Opportunity Difference (EOD) as our primary fairness metrics.

### **Manage: Incident Response Plan**

If the model drifts beyond 5%, the **Circuit Breaker** protocol is triggered, reverting to the rule-based legacy engine.

## **3\. OWASP Top 10 Defenses**

### **Input Validation**

All user inputs are sanitized. We use `LLM-Guard` to detect and block **Prompt Injection** attempts.

### **Output Sanitization**

Outputs are parsed to remove potential XSS vectors and ensure JSON strictness.

### **PII Filtering**

A PII-redaction layer runs on all outputs to prevent data leakage of social security numbers.

## **4\. Security Baseline**

### **Encryption at Rest**

All database volumes and model weights are encrypted using **AES-256**.

### **Encryption in Transit**

All API traffic is secured via **TLS 1.3**.

### **Authentication Mechanisms**

Access is restricted to service accounts using **OAuth2** flows.

### **Secrets Management**

No hardcoded keys. All API keys are injected via HashiCorp Vault at runtime.

