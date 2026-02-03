![Nod Gatekeeper](https://github.com/mraml/nod/actions/workflows/nod-gatekeeper.yml/badge.svg)

# **nod: The AI Spec Compliance Gatekeeper**

**nod** is a platform-agnostic, rule-based linter that ensures AI/LLM specifications contain critical security and compliance elements **before** any agentic or automated development begins.

## **🚀 The Core Philosophy: "The Final Nod"**

Automated agents and agentic workflows (like Ralph, AutoGPT, or custom CI/CD builders) are powerful but "compliance-blind." They build exactly what is in the specification.

**nod** ensures that the specification contains the required elements to align with regulatory standards and frameworks before an agent ever touches it.

* **Agnostic Integration:** Works as a pre-requisite for *any* agentic development tool or manual coding process.  
* **Shift-Left Security:** Identifies missing risk assessments, OWASP vulnerabilities, or oversight mechanisms at the design phase.  
* **Deterministic Guardrails:** Replaces vague human "vibes" with a strict, rule-based audit trail.

## **✨ Key Features**

* **Directory Scanning:** Scan a single file OR an entire folder of specs (Distributed Compliance).  
* **Compliance Reporting:** Generate executive summaries (`--output compliance`) with % completion metrics.  
* **Code-to-Spec Verification (Drift Detection):** 🆕  
  * **Reality Checks:** Verify if claims in the Spec (e.g., "Database: Postgres") actually exist in the code (e.g., `requirements.txt`).  
  * **Drift Reporting:** Flag contradictions between documentation and implementation files.  
* **Deep Validation:**  
  * **Field Patterns:** Validate specific values (e.g., "Retention: 30 days") using regex.  
  * **Structure:** Ensure sections contain specific subsections (`must_contain`).  
  * **Cross-References:** Validate links between Threats and Controls across documents.  
* **Requirement Modes:** Enforce rules in *at least one* file (default) or *every* file (`in_all_files`).  
* **Scaffolding (`--init`):** Instantly generate a compliant Markdown template based on active rules.  
* **Auto-Fix (`--fix`):** Automatically append missing headers and compliance boilerplate.  
* **Agent Context (`--export`):** Export rules as a "System Prompt" to constrain AI agents.  
  * Supports `.cursorrules` and `.windsurfrules`.  
* **Integrity Signing:** Cryptographically sign artifacts using HMAC-SHA256.  
* **Gap Severity Model:** Categorizes issues as **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW**.  
* **SARIF Output:** Native integration with GitHub Advanced Security and GitLab Security Dashboards.  
* **Exception Management:** Formalize risk acceptance using a `.nodignore` file.  
* **Remote Rule Registry:** Securely fetch industry-standard rules via HTTPS with strict SSL verification.  
* **Community Rules Library:** https://github.com/mraml/nod-rules

## **⚠️ Important Disclaimer**

**nod** verifies the *presence and alignment* of policy elements within a specification. It is a blueprint auditor; it does not guarantee the security of the final running code, which requires independent runtime auditing. A "green light" from **nod** means the **intent** matches the policy.

## **🛠️ Installation**

**nod** can be used via GitHub Actions.

## **📖 Usage Lifecycle**

**nod** is designed to support the entire specification lifecycle, from blank page to final audit.

### **1\. Start: The Blank Page Problem (`--init`)**

Don't know what headers strict compliance requires? Let `nod` build the skeleton for you.

```
# Generate a spec with all headers for EU AI Act, NIST, and OWASP
nod ai-spec.md --init --rules rules.yaml

```

### **2\. Build: Agentic Context Injection (`--export`)**

If you are using an AI Agent (like Ralph, Claude, or GPT) to write your spec or code, feed it the rules first.

```
# Export rules as a System Prompt constraint block
nod --export --rules rules.yaml

# Generate Cursor/Windsurf rules
nod --export cursor

```

### **3\. Audit: The Gatekeeper**

Run the scan to verify the work. Use `--strict` to ensure headers aren't just empty placeholders.

```
# Directory Mode (Scans all .md/.json files in /docs)
nod docs/ --strict --min-severity HIGH

# Generate Manager Report
nod docs/ --output compliance

```

### **4\. Maintain: Auto-Fix (`--fix`)**

Did you miss a new requirement? `nod` can append the missing sections for you.

```
nod docs/ --fix --rules rules.yaml

```

### **5\. Secure: Integrity Signing**

To verify that an audit result hasn't been tampered with, set the `NOD_SECRET_KEY` environment variable. `nod` will include an HMAC signature in the output.

```
export NOD_SECRET_KEY="my-secret-ci-key"
nod ai-spec.md --output json
# Output includes "signature": "a1b2c3..."

```

### **6\. Baseline: Freeze & Verify**

Lock your compliance state to detect drift.

```
# Freeze current state to nod.lock
nod docs/ --freeze

# Verify current state against lockfile (CI/CD)
nod docs/ --verify

```

## **💡 CLI Power Tips**

* **Registry Shorthand:** Skip manually downloading files. Use `registry:name` to fetch from the official library.

```
nod docs/ --rules registry:owasp-llm
```

*   
  **Silent Mode (`-q`):** Suppress banner art and success messages. Perfect for clean CI logs.

```
nod docs/ -q --strict
```

*   
  **File Output (`--save-to`):** Save reports directly to a file without piping.

```
nod docs/ --output sarif --save-to report.sarif
```

## **🧠 Advanced Rule Logic**

**nod** supports sophisticated rule definitions in `rules.yaml` to handle complex compliance scenarios.

### **Reality Checks (Drift Detection)**

Ensure that what is written in the Spec actually exists in the Code.

```
reality_checks:
  # Check if the DB defined in Spec matches requirements.txt
  - spec_pattern: "Database:\\s*(\\w+)"     # Captures 'Postgres'
    target_file: "requirements.txt"          # Scans this file
    reality_pattern: "(?i)\\1"               # Looks for 'Postgres' (case-insensitive)
    severity: "HIGH"

  # Check if Isolation claims match Dockerfile
  - spec_pattern: "Isolation:\\s*(\\w+)"     # Captures 'Alpine'
    target_file: "Dockerfile"
    reality_pattern: "(?i)FROM.*\\1"         # Looks for 'FROM ... Alpine'
    severity: "CRITICAL"

```

### **Enforcement Modes**

Control *where* a requirement must appear.

```
- id: "## Data Privacy"
  mode: "in_all_files"  # Must exist in EVERY file scanned (e.g., footer policy)
  # Default mode is "at_least_one" (Distributed compliance)

```

### **Field Validation**

Go beyond headers. Check for specific content patterns.

```
- id: "## Data Retention"
  must_match:
    - pattern: "Retention Period: \d+ (days|years)"
      message: "Must specify numeric retention period"

```

### **Cross-Reference Validation**

Ensure traceabilty between documents (e.g., Threats must have Controls).

```
cross_references:
  - source: "Threat T-(\d+)"
    must_have: "Control C-\1"

```

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
      
      # Run nod using the Official Action
      - name: Run nod Gatekeeper
        uses: mraml/nod@v2.1.0
        with:
          target: 'docs/' 
          rules: 'rules.yaml'
          strict: 'true'
          min_severity: 'HIGH'
          output_format: 'sarif'
          output_file: 'nod-results.sarif'

      # Upload results to Security Tab
      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: nod-results.sarif

```

## **🤝 Contributing**

We welcome contributions\! Please see [CONTRIBUTING.md](https://www.google.com/search?q=CONTRIBUTING.md) for details on how to add new rules or features.

If you find **nod** useful for your organization, please consider **starring the repository** to help others find it.

## **🏷️ Badges & Live Status**

Add this to your `README.md` to show if your specs are currently passing the gate.

```
![Nod Gatekeeper](https://github.com/<username>/<repo>/actions/workflows/nod-gatekeeper.yml/badge.svg)

```

## **🤖 Transparency**

**nod** was developed with the assistance of AI tools. While the core logic is deterministic and rule-based, the codebase and documentation were accelerated using Large Language Models.

## **🛡️ License**

Apache 2.0








