import os
import sys
import json
import re
import hashlib
from datetime import datetime
from typing import Dict, Any, Tuple, List
from .config import MAX_FILE_SIZE, MAX_TOTAL_SIZE
from .utils import get_line_number, resolve_source
from .reporters import generate_agent_prompt

SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

class Scanner:
    def __init__(self, config: Dict[str, Any], ignored_rules: List[str]):
        self.config = config
        self.ignored_rules = ignored_rules
        self.attestation = {}

    def _collect_files(self, path: str) -> List[str]:
        if os.path.isfile(path):
            return [path]
        found = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                if os.path.splitext(f)[1].lower() in {'.md', '.markdown', '.mdx', '.json', '.txt'}:
                    found.append(os.path.join(root, f))
        return found

    def scan_input(self, path: str, strict: bool = False, version: str = "unknown") -> Tuple[Dict[str, Any], str]:
        files = self._collect_files(path)
        if not files:
            return {"error": f"No files in {path}"}, "NONE"

        agg_content = ""
        total_size = 0
        hashes = []
        file_map = {}
        base_dir = path if os.path.isdir(path) else os.path.dirname(path)
        is_single_json = len(files) == 1 and files[0].endswith(".json")
        default_source = files[0] if is_single_json else None

        for file_path in files:
            try:
                size = os.path.getsize(file_path)
                if size > MAX_FILE_SIZE:
                    print(f"Warning: Skipping {file_path} (Size limit)", file=sys.stderr)
                    continue
                
                total_size += size
                if total_size > MAX_TOTAL_SIZE:
                    return {"error": "Total aggregation size exceeds memory limit"}, "NONE"
                
                with open(file_path, "r", encoding="utf-8") as f:
                    raw = f.read()
                    file_map[file_path] = raw
                    hashes.append(hashlib.sha256(raw.encode()).hexdigest())
                    if is_single_json:
                        agg_content = raw
                    else:
                        agg_content += f"\n\n<!-- SOURCE: {file_path} -->\n{raw}"
            except Exception as e:
                print(f"Warn: {e}", file=sys.stderr)

        agg_hash = hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()
        ext = ".json" if is_single_json else ".md"
        results = self._audit(agg_content, ext, strict, base_dir, default_source, file_map)

        max_sev_val = -1
        max_sev_label = "NONE"
        for p in results.values():
            for c in p.get("checks", []):
                if not c["passed"] and c["status"] == "FAIL":
                    val = SEVERITY_MAP.get(c["severity"], 0)
                    if val > max_sev_val:
                        max_sev_val = val
                        max_sev_label = c["severity"]

        self.attestation = {
            "tool": "nod",
            "version": "2.0.0",
            "policy_version": version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "files_audited": files,
            "aggregate_hash": agg_hash,
            "max_severity_gap": max_sev_label,
            "results": results,
            "remediation_summary": generate_agent_prompt(results)
        }
        return results, max_sev_label

    def _check_req(self, text: str, ext: str, req: Dict, strict: bool) -> Tuple[bool, int, int, str]:
        rule_id = req["id"]
        passed = False
        line = 1
        start_idx = -1
        err = ""

        if ext == ".json":
            try:
                data = json.loads(text)
                if rule_id in data:
                    val = str(data[rule_id])
                    if not strict or val.strip():
                        passed = True
                        for p in req.get("must_match", []):
                            if p.get("pattern") and not re.search(p["pattern"], val, re.I | re.M):
                                passed = False
                                err = p.get('message', 'Value mismatch')
            except Exception: pass
        else:
            try:
                match = re.search(rule_id, text, re.I | re.M)
                if match:
                    start_idx = match.start()
                    line = get_line_number(text, start_idx)
                    passed = True
                    match_str = match.group(0).strip()
                    level = len(match_str) - len(match_str.lstrip('#')) if match_str.startswith('#') else 0
                    section = text[match.end():]
                    next_pattern = r"^#{1," + str(level) + r"}\s" if level else r"^#+\s"
                    if next_match := re.search(next_pattern, section, re.M):
                        section = section[:next_match.start()]

                    if strict and len(section.strip()) <= 15: passed = False
                    
                    if passed:
                        if missing := [s for s in req.get("must_contain", []) if not re.search(re.escape(s), section, re.I)]:
                            passed, err = False, f"Missing: {', '.join(missing)}"
                        for p in req.get("must_match", []):
                            if p.get("pattern") and not re.search(p["pattern"], section, re.I | re.M):
                                passed, err = False, p.get('message', 'Pattern mismatch')
            except re.error: pass
        
        return passed, line, start_idx, err

    def _audit(self, content: str, ext: str, strict: bool, base: str, def_src: str, fmap: Dict) -> Dict:
        report = {}
        for name, data in self.config.get("profiles", {}).items():
            checks, skip, added_reqs = [], [], []
            
            for c in data.get("conditions", []):
                try:
                    if re.search(c["if"]["regex_match"], content, re.I | re.M):
                        skip.extend(c["then"].get("skip", []))
                        for r in c["then"].get("require", []):
                            if isinstance(r, str): added_reqs.append({"id": r, "severity": "HIGH", "remediation": "Conditional Req"})
                            elif isinstance(r, dict): added_reqs.append(r)
                except re.error as e: print(f"Warning: Regex error: {e}", file=sys.stderr)

            for req in data.get("requirements", []) + added_reqs:
                rule_id = req["id"]
                status, passed, line, src = "FAIL", False, 1, def_src
                remediation = req.get("remediation", "")

                if rule_id in skip: status, passed = "SKIPPED", True
                elif rule_id in self.ignored_rules: status, passed = "EXCEPTION", True
                else:
                    if req.get("mode") == "in_all_files" and fmap:
                        missing_files = []
                        for fp, txt in fmap.items():
                            p_ok, _, _, _ = self._check_req(txt, os.path.splitext(fp)[1], req, strict)
                            if not p_ok: missing_files.append(os.path.basename(fp))
                        if missing_files:
                            remediation = f"Missing in: {', '.join(missing_files)}. " + remediation
                        else: status, passed, src = "PASS", True, "all_files"
                    else:
                        p_ok, ln, idx, err = self._check_req(content, ext, req, strict)
                        if p_ok:
                            status, passed, line = "PASS", True, ln
                            if not src and idx >= 0: src = resolve_source(content, idx)
                        if err: remediation = f"{err}. " + remediation

                checks.append({"id": rule_id, "label": req.get("label"), "passed": passed, "status": status, "severity": req.get("severity", "HIGH"), "remediation": remediation, "source": src, "line": line, "control_id": req.get("control_id"), "article": req.get("article")})

            for flag in data.get("red_flags", []):
                rule_id = flag["pattern"]
                status, passed, line, src = "PASS", True, 1, def_src
                try:
                    match = re.search(rule_id, content, re.I | re.M)
                    if match:
                        line = get_line_number(content, match.start())
                        if not src: src = resolve_source(content, match.start())
                        if rule_id in self.ignored_rules: status = "EXCEPTION"
                        elif rule_id in skip: status = "SKIPPED"
                        else: status, passed = "FAIL", False
                except re.error: pass
                checks.append({"id": rule_id, "label": flag.get("label"), "passed": passed, "status": status, "severity": flag.get("severity", "CRITICAL"), "type": "red_flag", "remediation": flag.get("remediation"), "source": src, "line": line, "control_id": flag.get("control_id"), "article": flag.get("article")})

            for xref in data.get("cross_references", []):
                try:
                    for match in re.finditer(xref["source"], content, re.I | re.M):
                        expected = match.expand(xref["must_have"])
                        line = get_line_number(content, match.start())
                        passed = expected in content
                        checks.append({"id": f"XRef: {match.group(0)}->{expected}", "label": "Cross-Reference Validation", "passed": passed, "status": "PASS" if passed else "FAIL", "severity": xref.get("severity", "HIGH"), "remediation": f"Missing {expected}", "line": line, "source": resolve_source(content, match.start(), def_src)})
                except re.error: pass

            if strict and ext != ".json" and ("security" in name or "baseline" in name):
                for match in re.finditer(r"\[([^\]]+)\]\((?!http)([^)]+)\)", content):
                    path = match.group(2).strip()
                    if not path.startswith("#"):
                        exists = os.path.exists(os.path.join(base, path))
                        checks.append({"id": f"Ev: {match.group(1)}", "label": "Evidence Check", "passed": exists, "status": "PASS" if exists else "FAIL", "severity": "MEDIUM", "remediation": f"Missing: {path}", "line": 1, "source": resolve_source(content, match.start(), def_src)})

            block = [c for c in checks if c["status"] == "FAIL" and SEVERITY_MAP.get(c["severity"], 0) >= 3]
            report[name] = {"label": data.get("badge_label", name), "checks": checks, "passed": not block}
        return report
