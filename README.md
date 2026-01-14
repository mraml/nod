# **nod: The AI Spec Compliance Gatekeeper**

**nod** is a platform-agnostic, rule-based linter that ensures AI/LLM specifications contain critical security and compliance elements **before** any agentic or automated development begins.

![Nod Gatekeeper](https://github.com/<username>/<repo>/actions/workflows/nod-gatekeeper.yml/badge.svg)

## **🚀 The Core Philosophy: "The Final Nod"**

Automated agents and agentic workflows (like Ralph, AutoGPT, or custom CI/CD builders) are powerful but "compliance-blind." They build exactly what is in the specification.

**nod** ensures that the specification contains the required elements to align with regulatory standards and frameworks before an agent ever touches it.

* **Agnostic Integration:** Works as a pre-requisite for *any* agentic development tool or manual coding process.  
* **Shift-Left Security:** Identifies missing risk assessments, OWASP vulnerabilities, or oversight mechanisms at the design phase.  
* **Deterministic Guardrails:** Replaces vague human "vibes" with a strict, rule-based audit trail.

## **✨ Key Features**

* **Policy-as-Code:** Define your compliance standards in simple YAML.  
* **Gap Severity Model:** Categorizes issues as **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW** to help security teams prioritize.  
* **SARIF Output:** Native integration with GitHub Advanced Security and GitLab Security Dashboards via `--output sarif`.  
* **Exception Management:** Formalize risk acceptance using a `.nodignore` file to document approved deviations.  
* **Attestation Artifacts:** Generates a signed `nod-attestation.json` providing a tamper-proof audit trail.  
* **Remote Rule Registry:** Point `nod` to a URL to always use the latest industry-standard rules.  
* **Agent-Friendly Remediation:** Failures provide specific "hints" that downstream AI agents can use to self-correct the spec.

## **⚠️ Important Disclaimer**

**nod** verifies the *presence and alignment* of policy elements within a specification. It is a blueprint auditor; it does not guarantee the security of the final running code, which requires independent runtime auditing. A "green light" from **nod** means the **intent** matches the policy.

## **🛠️ Installation**

**nod** is a single-file Python tool. You can drop it directly into your repo or install it via your pipeline setup.

**Requirements:** Python 3.8+, `PyYAML`

```
pip install pyyaml
```

## **📖 Usage**

### **1\. Basic & Strict Scans**

Run a local audit against a Markdown spec. Use `--strict` to ensure headers aren't just empty placeholders.

```
# Basic Scan
python nod.py specs/model-card.md --rules rules.yaml

# Strict Mode (Recommended)
python nod.py specs/model-card.md --rules rules.yaml --strict
```

### **2\. Enforcing Severity Gates**

Control the "Gatekeeper" level. Block builds only on **HIGH** or **CRITICAL** issues, allowing **MEDIUM** gaps to pass with a warning.

```
python nod.py specs/model-card.md --min-severity HIGH
```

### **3\. Output Formats (JSON & SARIF)**

Generate artifacts for audit trails or security dashboards.

```
# Generate a JSON attestation for downstream agents
python nod.py specs/model-card.md --output json > nod-attestation.json

# Generate SARIF for GitHub Security tab
python nod.py specs/model-card.md --output sarif > results.sarif
```

### **4\. Managing Exceptions (`.nodignore`)**

If a specific rule does not apply (e.g., "Energy Consumption" on a trivial model), document the exception formally in a `.nodignore` file in your root directory.

```
# .nodignore
# Format: Rule_ID
Energy Consumption
```

These will appear as `[EXCEPTION]` in the audit report rather than `[FAIL]`.

## **⚙️ Configuration (`rules.yaml`)**

**nod** comes with a comprehensive registry of profiles:

1. **EU AI Act:** Articles 6, 10, 11, 12, 14, 15 (High-Risk classifications).  
2. **NIST AI RMF:** Govern, Map, Measure, Manage functions.  
3. **OWASP LLM Top 10:** Prompt Injection, Data Leakage, Model Theft.  
4. **Security Baseline:** Encryption, Access Control, Secrets Management.

You can point to a remote registry to keep rules up to date:

```
python nod.py specs/model-card.md --rules [https://security.my-org.com/nod-rules-v1.yaml](https://security.my-org.com/nod-rules-v1.yaml)
```

## **🚦 CI/CD Integration (GitHub Actions)**

Add this to `.github/workflows/nod-audit.yml` to guard your main branch and see results in the Security tab:

```
name: AI Compliance Gatekeeper
on: [pull_request]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    permissions:
      security-events: write # Required for SARIF upload
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
          python nod.py specs/ai-prd.md --rules rules.yaml --output sarif > nod-results.sarif || true
      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nod-results.sarif
      - name: Gatekeeper Check
        run: |
          # Now fail the build if criteria aren't met
          python nod.py specs/ai-prd.md --rules rules.yaml --strict --min-severity HIGH
```

## **🏷️ Badges & Live Status**

While **nod** provides static badges for policy alignment (like the ones at the top of this file), most teams prefer a **Live Status Badge** that updates automatically with every commit.

Add this to your `README.md` to show if your specs are currently passing the gate:

```
![Nod Gatekeeper](https://github.com/<username>/<repo>/actions/workflows/nod-audit.yml/badge.svg)
```

*Note: Replace `<username>`, `<repo>`, and `nod-audit.yml` with your actual repository details and workflow filename. This badge will turn Green ✅ or Red ❌ dynamically based on the build status.*

## **🛡️ License**

Apache 2.0

