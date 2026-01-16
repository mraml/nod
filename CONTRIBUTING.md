# **Contributing to nod**

First off, thank you for considering contributing to **nod**\! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

## **🤝 How Can You Help?**

### **1\. Expanding the Rules Registry**

The most impactful way to help is by adding new Compliance Profiles to the `defaults/` folder.

* **New Standards:** Are we missing *ISO 42001* or *HIPAA*? Create a new `.yaml` file.  
* **Improvements:** Improve the regex patterns in existing rules to reduce false positives.

**Rule Contribution Checklist:**

* Create a new file in `defaults/` (e.g., `iso_42001.yaml`).  
* Use the `profiles` key structure.  
* Ensure every requirement has a `severity` and `remediation`.  
* (Optional) Add `article` or `control_id` metadata for traceability.

### **2\. Reporting Bugs**

Found a bug? Please open an issue\!

* **Title:** Clear summary of the issue.  
* **Context:** What OS/Python version?  
* **Reproduction:** Provide a snippet of the spec file that caused the error.

### **3\. Submitting Pull Requests**

1. Fork the repo and create your branch from `main`.  
2. Run tests locally: `python nod.py tests/spec_compliant.md --strict`.  
3. Ensure the code style matches (standard Python 3.10+).  
4. Update the `nod-project-spec.md` if you added a new feature.

## **🏗️ Development Setup**

```
# Clone your fork
git clone [https://github.com/YOUR-USERNAME/nod.git](https://github.com/YOUR-USERNAME/nod.git)
cd nod

# Install dependencies
pip install pyyaml

# Run a test scan
python nod.py tests/spec_compliant.md
```

Thank you for helping us make AI development safer and more compliant\! 🛡️

