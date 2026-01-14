# **nod: The AI Spec Compliance Gatekeeper**

**nod** is a platform-agnostic, rule-based linter that ensures AI/LLM specifications contain critical security and compliance elements **before** any agentic or automated development begins.

![Nod Gatekeeper](https://github.com/mraml/nod/actions/workflows/nod-gatekeeper.yml/badge.svg)


## **🚀 The Core Philosophy: "The Final Nod"**

Automated agents and agentic workflows (like Ralph, AutoGPT, or custom CI/CD builders) are powerful but "compliance-blind." They build exactly what is in the specification.

**nod** ensures that the specification contains the required elements to align with regulatory standards and frameworks before an agent ever touches it.

* **Agnostic Integration:** Works as a pre-requisite for *any* agentic development tool or manual coding process.  
* **Shift-Left Security:** Identifies missing risk assessments, OWASP vulnerabilities, or oversight mechanisms at the design phase.  
* **Deterministic Guardrails:** Replaces vague human "vibes" with a strict, rule-based audit trail.

## **✨ Key Features**

* **Scaffolding (`--init`):** Instantly generate a compliant Markdown template based on active rules.  
* **Agent Context (`--export`):** Export compliance rules as a "System Prompt" to constrain AI agents during generation.  
* **Policy-as-Code:** Define your compliance standards in simple YAML.  
* **Gap Severity Model:** Categorizes issues as **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW** to help security teams prioritize.  
* **SARIF Output:** Native integration with GitHub Advanced Security and GitLab Security Dashboards.  
* **Exception Management:** Formalize risk acceptance using a `.nodignore` file.  
* **Attestation Artifacts:** Generates a signed `nod-attestation.json` providing a tamper-proof audit trail.  
* **Remote Rule Registry:** Point `nod` to a URL to always use the latest industry-standard rules.

## **⚠️ Important Disclaimer**

**nod** verifies the *presence and alignment* of policy elements within a specification. It is a blueprint auditor; it does not guarantee the security of the final running code, which requires independent runtime auditing. A "green light" from **nod** means the **intent** matches the policy.

## **🛠️ Installation**

**nod** is a single-file Python tool. You can drop it directly into your repo or install it via your pipeline setup.

**Requirements:** Python 3.8+, `PyYAML`

```
pip install pyyaml
```

## **📖 Usage Lifecycle**

**nod** is designed to support the entire specification lifecycle, from blank page to final audit.

### **1\. Start: The Blank Page Problem (`--init`)**

Don't know what headers strict compliance requires? Let `nod` build the skeleton for you.

```
# Generate a spec with all headers for EU AI Act, NIST, and OWASP
python nod.py ai-spec.md --init --rules rules.yaml
```

### **2\. Build: Agentic Context Injection (`--export`)**

If you are using an AI Agent (like Ralph, Claude, or GPT) to write your spec or code, feed it the rules first.

```
# Export rules as a System Prompt constraint block
python nod.py --export --rules rules.yaml
```

*Output Example:*

```
SYSTEM COMPLIANCE CONSTRAINTS
POLICY VERSION: 1.1.0
...
### FORBIDDEN (DO NOT GENERATE):
- PATTERN 'real-time biometric identification': Prohibited (Art 5)...
```

### **3\. Audit: The Gatekeeper**

Run the scan to verify the work. Use `--strict` to ensure headers aren't just empty placeholders.

```
# Local Scan
python nod.py ai-spec.md --strict --min-severity HIGH
```

### **4\. Fix: Self-Healing Workflow**

If the audit fails, `nod` generates `nod-attestation.json`. Pass this file to your agent. It contains a `remediation_summary` specifically formatted for LLMs to understand *exactly* what they missed and how to fix it using the provided template URLs.

### **5\. Exceptions: Managing Waivers**

If a rule doesn't apply (e.g., "Energy Consumption" on a trivial model), document it in `.nodignore`:

```
# .nodignore
# Exception ID: ENV-001
Energy Consumption
```

These will appear as `[EXCEPTION]` in the report rather than `[FAIL]`.

## **⚙️ Configuration (`rules.yaml`)**

**nod** comes with a comprehensive registry of profiles:

1. **EU AI Act:** Articles 6, 10, 11, 12, 14, 15 (High-Risk classifications).  
2. **NIST AI RMF:** Govern, Map, Measure, Manage functions.  
3. **OWASP LLM Top 10:** Prompt Injection, Data Leakage, Model Theft.  
4. **Security Baseline:** Encryption, Access Control, Secrets Management.

## **🚦 CI/CD Integration (GitHub Actions)**

Add this to `.github/workflows/nod-gatekeeper.yml` to guard your main branch and see results in the GitHub Security tab:

```
name: AI Compliance Gatekeeper
on: [pull_request]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    permissions:
      security-events: write # Required for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install pyyaml
      - name: Run nod (Generate SARIF)
        run: |
          # Don't fail immediately, let SARIF upload happen first
          python nod.py ai-spec.md --rules rules.yaml --output sarif > nod-results.sarif || true
      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nod-results.sarif
      - name: Gatekeeper Check
        run: |
          # Now fail the build if criteria aren't met
          python nod.py ai-spec.md --rules rules.yaml --strict --min-severity HIGH
```

## **🏷️ Badges & Live Status**

Add this to your `README.md` to show if your specs are currently passing the gate.

```
![Nod Gatekeeper](https://github.com/<username>/<repo>/actions/workflows/nod-gatekeeper.yml/badge.svg)
```

## **🛡️ License**

Apache 2.0

