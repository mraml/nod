from typing import Dict, Any
from datetime import datetime
from .utils import clean_header

SARIF_SCORE_MAP = {
    "CRITICAL": "9.0", "HIGH": "7.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"
}

SARIF_LEVEL_MAP = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"
}

def generate_agent_prompt(results: Dict[str, Any]) -> str:
    """Generates a summary string for AI agents to fix gaps."""
    gaps = []
    for p in results.values():
        for c in p.get("checks", []):
            if c["status"] == "FAIL":
                name = c.get("label") or c['id']
                ref = c.get("control_id") or c.get("article") or ""
                ref_str = f"[{ref}]" if ref else ""
                gaps.append(f"- [{c['severity']}] {name} {ref_str}: {c.get('remediation', '')}")
    return "\n".join(gaps) if gaps else "No gaps."

def gen_sarif(attestation: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Generates SARIF JSON output for security dashboards."""
    rules = []
    runs = []
    rmap = {}
    
    for data in attestation["results"].values():
        for c in data["checks"]:
            rule_id = c["id"]
            if rule_id not in rmap:
                rmap[rule_id] = len(rules)
                props = {"severity": c["severity"]}
                if c.get("article"):
                    props["article"] = c["article"]
                if c.get("control_id"):
                    props["compliance-ref"] = c["control_id"]
                    props["security-severity"] = SARIF_SCORE_MAP.get(c["severity"], "1.0")
                if c.get("type") == "contradiction":
                    props["tags"] = ["drift", "spec-contradiction"]
                
                desc = c.get("label") or rule_id
                rules.append({
                    "id": rule_id,
                    "name": desc,
                    "shortDescription": {"text": c.get("remediation", desc)},
                    "properties": props
                })
            
            if c["status"] in ["FAIL", "EXCEPTION"]:
                uri = c.get("source") if c.get("source") and c.get("source") != "unknown" else path
                level = SARIF_LEVEL_MAP.get(c["severity"], "note")
                msg = f"Gap: {c.get('remediation')}" if c["status"] == "FAIL" else "Exception via .nodignore"
                
                result = {
                    "ruleId": rule_id,
                    "ruleIndex": rmap[rule_id],
                    "level": level,
                    "message": {"text": msg},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": c.get("line", 1)}}}]
                }
                if c["status"] == "EXCEPTION":
                    result.update({"kind": "review", "suppressions": [{"kind": "external"}]})
                runs.append(result)
    
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nod",
                    "version": attestation.get("version", "1.0.0"),
                    "rules": rules
                }
            },
            "results": runs
        }]
    }

def gen_report(attestation: Dict[str, Any]) -> str:
    """Generates a human-readable text report."""
    out = []
    contradictions = []

    for data in attestation["results"].values():
        chks = data.get("checks", [])
        pct = int((len([c for c in chks if c["status"] != "FAIL"]) / len(chks) * 100) if chks else 0)
        out.append(f"{data['label']} Report ({datetime.utcnow().strftime('%Y-%m-%d')})\nStatus: {pct}% Compliant\n")
        
        for c in chks:
            # Separate Contradictions/Drift for special section
            if c.get("type") == "contradiction" and c["status"] == "FAIL":
                contradictions.append(f"⚠️  {c['remediation']} (Line {c.get('line')} in {c.get('source')})")
                continue

            icon = {"FAIL": "❌", "EXCEPTION": "⚪", "SKIPPED": "⏭️"}.get(c["status"], "✅")
            ref = c.get("article") or c.get("control_id")
            name = c.get("label") or clean_header(c['id'])
            out.append(f"{icon} {f'{ref}: ' if ref else ''}{name}")
            
            if c["status"] == "FAIL":
                out.append(f"   MISSING: {c.get('remediation','')}")
            elif c["status"] == "PASS" and c.get("source") and c["source"] != "unknown":
                out.append(f"   Ev: {c['source']}:{c.get('line')}")
            out.append("")
        out.append("-" * 40)
    
    # Append Drift Report if contradictions found
    if contradictions:
        out.append("\n" + "="*40)
        out.append("📊 POTENTIAL CODE CONTRADICTIONS (DRIFT)")
        out.append("="*40)
        out.extend(contradictions)
        out.append("")

    return "\n".join(out)
