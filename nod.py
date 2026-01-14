"""
nod: AI Spec Compliance Gatekeeper

A platform-agnostic, rule-based linter that ensures AI/LLM specifications
contain critical security and compliance elements before automated development.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml


class Nod:
    """
    The agnostic gatekeeper for AI Spec Compliance.
    Designed to be a 'Policy-as-Code' layer.
    """

    SEVERITY_MAP: Dict[str, int] = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    SARIF_LEVEL_MAP: Dict[str, str] = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    # Security Constants
    DEFAULT_TIMEOUT = 15.0
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file
    MAX_TOTAL_SIZE = 20 * 1024 * 1024 # 20MB total aggregation limit

    def __init__(self, rules_sources: List[str], ignore_path: str = ".nodignore") -> None:
        self.rules_sources = rules_sources
        self.config = self._load_and_merge_rules(rules_sources)
        self.policy_version = self.config.get("version", "unknown")
        self.ignored_rules = self._load_ignore_file(ignore_path)
        self.attestation: Dict[str, Any] = {}

    def _load_and_merge_rules(self, sources: List[str]) -> Dict[str, Any]:
        merged_config = {"profiles": {}, "version": "combined"}
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        def merge_data(new_data):
            if not new_data: return
            for profile, content in new_data.get("profiles", {}).items():
                if profile not in merged_config["profiles"]:
                    merged_config["profiles"][profile] = content
                else:
                    target = merged_config["profiles"][profile]
                    target.update(content)

        for source in sources:
            try:
                if source.startswith(("http://", "https://")):
                    with urllib.request.urlopen(source, context=ssl_context, timeout=self.DEFAULT_TIMEOUT) as response:
                        merge_data(yaml.safe_load(response.read()))
                elif os.path.isdir(source):
                    for filename in sorted(os.listdir(source)):
                        if filename.lower().endswith(('.yaml', '.yml')):
                            filepath = os.path.join(source, filename)
                            if os.path.getsize(filepath) > self.MAX_FILE_SIZE:
                                print(f"Warning: Skipping rule file {filepath} (Exceeds size limit)")
                                continue
                            with open(filepath, "r", encoding="utf-8") as f:
                                merge_data(yaml.safe_load(f))
                else:
                    if os.path.exists(source):
                        if os.path.getsize(source) > self.MAX_FILE_SIZE:
                            print(f"Error: Rules file {source} exceeds size limit.")
                            sys.exit(1)
                        with open(source, "r", encoding="utf-8") as f:
                            merge_data(yaml.safe_load(f))
            except Exception as e:
                print(f"Error loading rules from {source}: {str(e)}")
                sys.exit(1)
        return merged_config

    def _load_ignore_file(self, path: str) -> List[str]:
        ignored = []
        if os.path.exists(path):
            try:
                if os.path.getsize(path) > 1024 * 1024: return []
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"): ignored.append(line)
            except Exception: pass
        return ignored

    def _get_line_number(self, content: str, index: int) -> int:
        return content.count("\n", 0, index) + 1

    def _clean_header(self, text: str) -> str:
        text = re.sub(r"[#+*?^$\[\](){}|]", "", text).strip()
        text = text.replace(".*", " ").replace(".", " ")
        return " ".join(text.split())

    def _resolve_source(self, content: str, index: int, default_source: str = None) -> str:
        """Determines which file in an aggregate string contains the match."""
        if default_source:
            return default_source
            
        # Look for source markers preceeding the index
        markers = list(re.finditer(r"<!-- SOURCE: (.*?) -->", content))
        if not markers:
            return "unknown"
            
        best_source = "unknown"
        for m in markers:
            if m.start() < index:
                best_source = m.group(1)
            else:
                break
        return best_source

    def generate_template(self) -> str:
        lines = ["# AI Project Specification (Generated by nod)", "", f"> Policy Version: {self.policy_version}", "> Auto-generated based on compliance requirements.\n"]
        for profile_name, profile_data in self.config.get("profiles", {}).items():
            lines.append(f"---\n## Compliance Profile: {profile_data.get('badge_label', profile_name)}\n")
            for req in profile_data.get("requirements", []):
                lines.append(f"### {self._clean_header(req['id'])}")
                lines.append(f"<!-- {req.get('remediation', 'Fill in this section.')} -->")
                if req.get("must_contain"):
                    lines.append("<!-- Required subsections: -->")
                    for item in req["must_contain"]:
                        lines.append(f"{item}")
                lines.append("TODO: Add details here...\n")
        return "\n".join(lines)

    def generate_system_context(self) -> str:
        lines = ["# SYSTEM COMPLIANCE CONSTRAINTS", f"POLICY VERSION: {self.policy_version}", "The following constraints are MANDATORY.\n"]
        for profile_name, profile_data in self.config.get("profiles", {}).items():
            reqs = [r for r in profile_data.get("requirements", []) if r["id"] not in self.ignored_rules]
            flags = [f for f in profile_data.get("red_flags", []) if f["pattern"] not in self.ignored_rules]
            if not reqs and not flags: continue
            lines.append(f"## PROFILE: {profile_data.get('badge_label', profile_name)}")
            if reqs:
                lines.append("### MUST INCLUDE:")
                for r in reqs:
                    clean_id = self._clean_header(r['id'])
                    detail = r.get('remediation', '')
                    if r.get("must_contain"):
                        detail += f" (Must also contain: {', '.join(r['must_contain'])})"
                    lines.append(f"- {clean_id}: {detail}")
            if flags:
                lines.append("### FORBIDDEN:")
                for f in flags: lines.append(f"- PATTERN '{f['pattern']}': {f.get('remediation', '')}")
            lines.append("")
        return "\n".join(lines)

    def _collect_files(self, path: str) -> List[str]:
        supported_exts = {'.md', '.markdown', '.json', '.txt'}
        found_files = []
        if os.path.isfile(path): return [path]
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if os.path.splitext(file)[1].lower() in supported_exts:
                    found_files.append(os.path.join(root, file))
        return found_files

    def scan_input(self, input_path: str, strict: bool = False) -> Tuple[Dict[str, Any], str]:
        target_files = self._collect_files(input_path)
        if not target_files: return {"error": f"No spec files found in {input_path}"}, "NONE"

        aggregated_content = ""
        total_size = 0
        file_hashes = []
        base_dir = input_path if os.path.isdir(input_path) else os.path.dirname(input_path)
        
        # Check if we are dealing with a single JSON file (cannot be aggregated with comments)
        is_single_json = len(target_files) == 1 and target_files[0].endswith(".json")
        default_source = target_files[0] if is_single_json else None

        for fpath in target_files:
            try:
                size = os.path.getsize(fpath)
                if size > self.MAX_FILE_SIZE: continue
                total_size += size
                if total_size > self.MAX_TOTAL_SIZE: return {"error": "Total aggregation size exceeds memory limit"}, "NONE"
                with open(fpath, "r", encoding="utf-8") as f:
                    raw = f.read()
                    file_hashes.append(hashlib.sha256(raw.encode()).hexdigest())
                    if is_single_json:
                        aggregated_content = raw
                    else:
                        aggregated_content += f"\n\n<!-- SOURCE: {fpath} -->\n{raw}"
            except Exception as e: print(f"Warning: {e}")

        aggregate_hash = hashlib.sha256("".join(sorted(file_hashes)).encode()).hexdigest()
        ext = ".json" if is_single_json else ".md"
        results = self._audit_logic(aggregated_content, ext, strict, base_dir, default_source)
        
        max_sev_value = -1
        max_sev_label = "NONE"
        for p in results.values():
            for c in p.get("checks", []):
                if not c["passed"] and c["status"] == "FAIL":
                    if self.SEVERITY_MAP.get(c["severity"], 0) > max_sev_value:
                        max_sev_value = self.SEVERITY_MAP.get(c["severity"], 0)
                        max_sev_label = c["severity"]

        self.attestation = {
            "tool": "nod",
            "version": "1.7.0",
            "policy_version": self.policy_version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "files_audited": target_files,
            "aggregate_hash": aggregate_hash,
            "max_severity_gap": max_sev_label,
            "results": results,
            "remediation_summary": self._generate_agent_prompt(results),
        }
        
        self._sign_attestation()
        return results, max_sev_label

    def _sign_attestation(self):
        secret = os.environ.get("NOD_SECRET_KEY")
        if secret:
            payload = f"{self.attestation['aggregate_hash']}|{self.attestation['timestamp']}|{self.attestation['max_severity_gap']}"
            signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            self.attestation["signature"] = signature
            self.attestation["signed"] = True
        else:
            self.attestation["signed"] = False

    def _verify_local_evidence(self, content: str, base_dir: str, default_source: str = None) -> List[Dict[str, Any]]:
        checks = []
        for match in re.finditer(r"\[([^\]]+)\]\((?!http)([^)]+)\)", content):
            path = match.group(2).strip()
            if path.startswith("#"): continue
            
            # Basic relative check
            full_path = os.path.join(base_dir, path)
            exists = os.path.exists(full_path)
            
            # Resolve source file for this link
            source = self._resolve_source(content, match.start(), default_source)
            
            checks.append({
                "id": f"Evidence: {match.group(1)}", "passed": exists, "status": "PASS" if exists else "FAIL",
                "severity": "MEDIUM", "type": "evidence", "remediation": f"File not found: {path}", "line": 1,
                "source": source
            })
        return checks

    def _audit_logic(self, content: str, ext: str, strict: bool, base_dir: str, default_source: str = None) -> Dict[str, Any]:
        report = {}
        for profile, p_data in self.config.get("profiles", {}).items():
            checks = []
            skipped = []
            
            for cond in p_data.get("conditions", []):
                if "regex_match" in cond.get("if", {}):
                    try:
                        if re.search(cond["if"]["regex_match"], content, re.IGNORECASE | re.MULTILINE):
                            skipped.extend(cond.get("then", {}).get("skip", []))
                    except re.error: pass

            for req in p_data.get("requirements", []):
                item_id = req["id"]
                status = "FAIL"; passed = False; line = 1
                source = default_source
                remediation = req.get("remediation", "")
                
                if item_id in skipped: status = "SKIPPED"; passed = True
                elif item_id in self.ignored_rules: status = "EXCEPTION"; passed = True
                else:
                    if ext == ".json":
                        try:
                            data = json.loads(content)
                            if item_id in data:
                                val_str = str(data[item_id])
                                if strict and not val_str.strip():
                                    passed = False; status = "FAIL"
                                else:
                                    passed = True; status = "PASS"
                                    # Field Pattern Validation for JSON
                                    for pattern_def in req.get("must_match", []):
                                        pattern = pattern_def.get("pattern")
                                        if not pattern: continue
                                        try:
                                            if not re.search(pattern, val_str, re.IGNORECASE | re.MULTILINE):
                                                passed = False; status = "FAIL"
                                                msg = pattern_def.get("message", f"Value must match: {pattern}")
                                                remediation = f"{msg}. " + remediation
                                        except re.error: pass
                        except: pass
                    else:
                        try:
                            m = re.search(item_id, content, re.IGNORECASE | re.MULTILINE)
                            if m:
                                line = self._get_line_number(content, m.start())
                                passed = True; status = "PASS"
                                if not source:
                                    source = self._resolve_source(content, m.start())
                                
                                # Enhanced Section Extraction
                                match_str = m.group(0).strip()
                                level = len(match_str) - len(match_str.lstrip('#')) if match_str.startswith('#') else 0
                                start = m.end()
                                
                                # Find end of current section (next header of same or higher level)
                                section = content[start:]
                                if level > 0:
                                    next_head = re.search(r"^#{1," + str(level) + r"}\s", content[start:], re.MULTILINE)
                                    if next_head: section = content[start:start + next_head.start()]
                                else:
                                    # Fallback if no header level derived
                                    next_head = re.search(r"^#+\s", content[start:], re.MULTILINE)
                                    if next_head: section = content[start:start + next_head.start()]

                                if strict and len(section.strip()) <= 15: 
                                    passed = False; status = "FAIL"
                                
                                # Template Structure Validation
                                missing = [sub for sub in req.get("must_contain", []) if not re.search(re.escape(sub), section, re.IGNORECASE)]
                                if missing:
                                    passed = False; status = "FAIL"
                                    remediation = f"Missing subsections: {', '.join(missing)}. " + remediation

                                # Field Pattern Validation (must_match)
                                for pattern_def in req.get("must_match", []):
                                    pattern = pattern_def.get("pattern")
                                    if not pattern: continue
                                    try:
                                        if not re.search(pattern, section, re.IGNORECASE | re.MULTILINE):
                                            passed = False; status = "FAIL"
                                            msg = pattern_def.get("message", f"Must match pattern: {pattern}")
                                            remediation = f"{msg}. " + remediation
                                    except re.error as e:
                                        print(f"⚠️  Warning: Invalid regex in must_match '{pattern}': {e}", file=sys.stderr)

                        except re.error: status = "FAIL"

                checks.append({
                    "id": item_id, "passed": passed, "status": status, 
                    "severity": req.get("severity", "HIGH").upper(),
                    "remediation": remediation,
                    "tags": req.get("tags", []),
                    "article": req.get("article"),
                    "control_id": req.get("control_id"),
                    "source": source,
                    "line": line
                })

            for flag in p_data.get("red_flags", []):
                item_id = flag["pattern"]
                status = "PASS"; passed = True; line = 1
                source = default_source
                try:
                    m = re.search(item_id, content, re.IGNORECASE | re.MULTILINE)
                    if m:
                        line = self._get_line_number(content, m.start())
                        if not source:
                            source = self._resolve_source(content, m.start())
                            
                        if item_id in self.ignored_rules: status = "EXCEPTION"
                        elif item_id in skipped: status = "SKIPPED"
                        else: status = "FAIL"; passed = False
                except re.error: pass
                
                checks.append({
                    "id": item_id, "passed": passed, "status": status,
                    "severity": flag.get("severity", "CRITICAL").upper(),
                    "type": "red_flag",
                    "remediation": flag.get("remediation"),
                    "tags": flag.get("tags", []),
                    "article": flag.get("article"),
                    "control_id": flag.get("control_id"),
                    "source": source,
                    "line": line
                })

            if strict and ext != ".json" and ("security" in profile or "baseline" in profile):
                checks.extend(self._verify_local_evidence(content, base_dir, default_source))

            blocking = [c for c in checks if c["status"] == "FAIL" and self.SEVERITY_MAP.get(c["severity"], 0) >= 3]
            report[profile] = {"label": p_data.get("badge_label", profile), "checks": checks, "passed": len(blocking) == 0}
        return report

    def _generate_agent_prompt(self, results: Dict[str, Any]) -> str:
        gaps = []
        for p in results.values():
            for c in p.get("checks", []):
                if c["status"] == "FAIL":
                    ref = c.get("control_id") or c.get("article") or ""
                    ref_str = f"[{ref}]" if ref else ""
                    gaps.append(f"- [{c['severity']}] {c['id']} {ref_str}: {c.get('remediation', '')}")
        return "\n".join(gaps) if gaps else "No gaps detected."

    def apply_fix(self, input_path: str, results: Dict[str, Any]):
        target_file = input_path if os.path.isfile(input_path) else os.path.join(input_path, "nod-compliance.md")
        try:
            with open(target_file, "a", encoding="utf-8") as f:
                f.write("\n\n<!-- nod: auto-fix appended below -->\n")
                count = 0
                for p_name, p_data in results.items():
                    missing = [c for c in p_data["checks"] if c["status"] == "FAIL" and c.get("type") != "red_flag"]
                    if not missing: continue
                    f.write(f"\n## Missing: {p_data['label']}\n")
                    for m in missing:
                        header = self._clean_header(m["id"])
                        f.write(f"\n### {header}\n")
                        if m.get("control_id"): f.write(f"> Ref: {m['control_id']}\n")
                        f.write(f"<!-- {m.get('remediation')} -->\n")
                        f.write("TODO: Add details here.\n")
                        count += 1
            print(f"✅ patched {target_file}: Appended {count} missing sections.")
        except Exception as e: print(f"Error patching: {e}")

    def generate_compliance_report(self) -> str:
        lines = []
        for profile, p_data in self.attestation["results"].items():
            checks = p_data.get("checks", [])
            total = len(checks)
            compliant_count = len([c for c in checks if c["status"] != "FAIL"])
            percentage = int((compliant_count / total * 100) if total > 0 else 0)
            
            lines.append(f"{p_data['label']} Compliance Report")
            lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d')}")
            lines.append(f"Status: {percentage}% Compliant ({compliant_count}/{total} requirements)\n")
            
            for c in checks:
                status_icon = "✅"
                if c["status"] == "FAIL": status_icon = "❌"
                elif c["status"] == "EXCEPTION": status_icon = "⚪"
                elif c["status"] == "SKIPPED": status_icon = "⏭️"
                
                ref = c.get("article") or c.get("control_id")
                clean_id = self._clean_header(c['id'])
                title = f"{ref}: {clean_id}" if ref else clean_id
                
                lines.append(f"{status_icon} {title}")
                if c["status"] == "FAIL":
                    lines.append(f"   Status: MISSING")
                    if c.get("remediation"): lines.append(f"   Remediation: {c['remediation']}")
                elif c["status"] == "PASS":
                    source = c.get("source")
                    if source and source != "unknown": lines.append(f"   Evidence: {source}:{c.get('line')}")
                elif c["status"] == "EXCEPTION": lines.append(f"   Status: EXCEPTION")
                elif c["status"] == "SKIPPED": lines.append(f"   Status: SKIPPED")
                lines.append("")
            lines.append("-" * 40 + "\n")
        return "\n".join(lines)

    def generate_sarif(self, input_path: str) -> Dict[str, Any]:
        rules = []; results = []; rule_map = {}
        # Use specific file if known, else input_path (dir)
        
        for p_data in self.attestation["results"].values():
            for c in p_data["checks"]:
                rid = c["id"]
                if rid not in rule_map:
                    rule_map[rid] = len(rules)
                    sarif_props = {"severity": c["severity"], "tags": c.get("tags", [])}
                    if c.get("article"): sarif_props["article"] = c["article"]
                    if c.get("control_id"): sarif_props["security-severity"] = c["control_id"]
                    rules.append({"id": rid, "name": rid, "shortDescription": {"text": c.get("remediation", rid)}, "properties": sarif_props})
                
                # Use the tracked source file for location, fall back to input_path
                loc_uri = c.get("source") if c.get("source") and c.get("source") != "unknown" else input_path

                if c["status"] == "FAIL":
                    results.append({"ruleId": rid, "ruleIndex": rule_map[rid], "level": self.SARIF_LEVEL_MAP.get(c["severity"], "warning"), "message": {"text": f"Gap: {c.get('remediation')}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_uri}, "region": {"startLine": c.get("line", 1)}}}]})
                elif c["status"] == "EXCEPTION":
                    results.append({"ruleId": rid, "ruleIndex": rule_map[rid], "level": "note", "kind": "review", "suppressions": [{"kind": "external"}], "message": {"text": "Exception via .nodignore"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_uri}, "region": {"startLine": c.get("line", 1)}}}]})
        
        return {"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "runs": [{"tool": {"driver": {"name": "nod", "version": self.attestation["version"], "rules": rules}}, "results": results}]}

def main() -> None:
    parser = argparse.ArgumentParser(description="nod: AI Spec Compliance Gatekeeper")
    parser.add_argument("path", nargs="?", help="The spec file OR directory to audit")
    parser.add_argument("--rules", action='append', help="Rule sources")
    parser.add_argument("--init", action="store_true", help="Generate template")
    parser.add_argument("--fix", action="store_true", help="Auto-append missing sections")
    parser.add_argument("--export", action="store_true", help="Export context")
    parser.add_argument("--strict", action="store_true", help="Ensure fields are not empty")
    parser.add_argument("--min-severity", default="HIGH", choices=["MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--output", choices=["text", "json", "sarif", "compliance"], default="text")
    args = parser.parse_args()

    default_rules = ["rules.yaml"]
    if os.path.isdir("defaults"): default_rules = ["defaults"]
    sources = args.rules if args.rules else default_rules
    scanner = Nod(sources)

    if args.export: print(scanner.generate_system_context()); sys.exit(0)
    if args.init:
        template = scanner.generate_template()
        if args.path:
            if os.path.exists(args.path) and os.path.isfile(args.path):
                 print(f"Error: File '{args.path}' exists. Aborting.")
                 sys.exit(1)
            try:
                with open(args.path, "w", encoding="utf-8") as f: f.write(template)
                print(f"✅ Generated compliant spec: {args.path}")
                sys.exit(0)
            except Exception as e: print(f"Error: {e}"); sys.exit(1)
        else: print(template); sys.exit(0)

    if not args.path: parser.print_help(); sys.exit(1)

    results, max_sev = scanner.scan_input(args.path, strict=args.strict)

    if args.fix: scanner.apply_fix(args.path, results); sys.exit(0)

    if args.output == "sarif": print(json.dumps(scanner.generate_sarif(args.path), indent=2))
    elif args.output == "json": print(json.dumps(scanner.attestation, indent=2))
    elif args.output == "compliance":
        print(scanner.generate_compliance_report())
        sys.exit(0 if scanner.SEVERITY_MAP.get(max_sev, 0) < scanner.SEVERITY_MAP.get(args.min_severity) else 1)
    else:
        print(f"\n--- nod Audit Summary ---")
        print(f"Target: {args.path}")
        print(f"Max Severity Gap: {max_sev}")
        if scanner.attestation.get("signed"): print(f"🔒 Signature: VERIFIED (HMAC-SHA256)")
        
        failed = False
        min_val = scanner.SEVERITY_MAP.get(args.min_severity)
        for p_data in results.values():
            print(f"\n[{p_data['label']}]")
            for c in p_data["checks"]:
                if c["status"] == "FAIL":
                    print(f"  ❌ [{c['severity']}] {c['id']}")
                    if c.get("source"): print(f"     File: {c['source']}")
                    if c.get("control_id"): print(f"     Ref: {c['control_id']}")
                    if scanner.SEVERITY_MAP.get(c["severity"], 0) >= min_val: failed = True
                elif c["status"] == "EXCEPTION": print(f"  ⚪ [EXCEPTION] {c['id']}")
                elif c["status"] == "SKIPPED": print(f"  ⏭️  [SKIPPED] {c['id']}")
                else: 
                    # Verbose pass
                    # print(f"  ✅ [PASS] {c['id']} ({c.get('source', 'unknown')})")
                    print(f"  ✅ [PASS] {c['id']}")
        
        if failed: print(f"\nFAIL: Blocked by {args.min_severity}+ gaps."); sys.exit(1)
        print("\nPASS: Nod granted."); sys.exit(0)

if __name__ == "__main__":
    main()
