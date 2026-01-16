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


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'


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

    # Mapping for GitHub Code Scanning (0.0-10.0)
    SARIF_SCORE_MAP: Dict[str, str] = {
        "CRITICAL": "9.0",
        "HIGH": "7.0",
        "MEDIUM": "5.0",
        "LOW": "3.0",
        "INFO": "1.0",
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
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_TOTAL_SIZE = 20 * 1024 * 1024  # 20MB

    def __init__(self, rules_sources: List[str], ignore_path: str = ".nodignore") -> None:
        """
        Initialize the scanner.

        Args:
            rules_sources: List of file paths or URLs to rule definitions.
            ignore_path: Path to the ignore file.
        """
        self.config = self._load_rules(rules_sources)
        self.policy_version = self.config.get("version", "unknown")
        self.ignored = self._load_ignore(ignore_path)
        self.attestation: Dict[str, Any] = {}

    def _load_rules(self, sources: List[str]) -> Dict[str, Any]:
        """Loads and merges rules from multiple sources (files/URLs/Dirs)."""
        merged = {"profiles": {}, "version": "combined"}
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        def merge(new_data: Dict[str, Any]) -> None:
            if not new_data:
                return
            for profile, content in new_data.get("profiles", {}).items():
                if profile not in merged["profiles"]:
                    merged["profiles"][profile] = content
                else:
                    merged["profiles"][profile].update(content)

        for source in sources:
            try:
                if source.startswith(("http://", "https://")):
                    with urllib.request.urlopen(source, context=ssl_context, timeout=self.DEFAULT_TIMEOUT) as response:
                        merge(yaml.safe_load(response.read()))
                elif os.path.isdir(source):
                    for filename in sorted(os.listdir(source)):
                        if filename.endswith(('.yaml', '.yml')):
                            file_path = os.path.join(source, filename)
                            if os.path.getsize(file_path) > self.MAX_FILE_SIZE:
                                print(f"Warning: Skipping rule {file_path} (Size limit)", file=sys.stderr)
                                continue
                            with open(file_path, "r", encoding="utf-8") as f_in:
                                merge(yaml.safe_load(f_in))
                elif os.path.exists(source):
                    if os.path.getsize(source) > self.MAX_FILE_SIZE:
                        print(f"Error: Rule file {source} too large", file=sys.stderr)
                        sys.exit(1)
                    with open(source, "r", encoding="utf-8") as f:
                        merge(yaml.safe_load(f))
            except Exception as e:
                print(f"Error loading rules from {source}: {e}", file=sys.stderr)
                sys.exit(1)
        return merged

    def _load_ignore(self, path: str) -> List[str]:
        """Loads ignored rule IDs from a file."""
        if os.path.exists(path):
            try:
                if os.path.getsize(path) <= 1024 * 1024:
                    with open(path, "r", encoding="utf-8") as f:
                        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        return []

    def _clean_header(self, text: str) -> str:
        """Normalizes regex patterns into readable headers."""
        text = re.sub(r"[#+*?^$\[\](){}|]", "", text).strip()
        text = text.replace(".*", " ").replace(".", " ")
        return " ".join(text.split())

    def _resolve_source(self, content: str, index: int) -> str:
        """Determines source file from aggregated content based on index."""
        best_source = "unknown"
        for match in re.finditer(r"<!-- SOURCE: (.*?) -->", content):
            if match.start() < index:
                best_source = match.group(1)
            else:
                break
        return best_source

    def gen_template(self) -> str:
        """Generates a Markdown template from loaded rules."""
        lines = ["# AI Project Spec (Generated by nod)", "", f"> Policy: {self.policy_version}\n"]
        for name, data in self.config.get("profiles", {}).items():
            lines.append(f"---\n## Profile: {data.get('badge_label', name)}\n")
            for req in data.get("requirements", []):
                header = req.get("label") or self._clean_header(req['id'])
                lines += [f"### {header}", f"<!-- {req.get('remediation', 'Fill section')} -->"]
                if req.get("must_contain"):
                    lines += ["<!-- Subsections: -->"] + req["must_contain"]
                lines.append("TODO: Add details...\n")
        return "\n".join(lines)

    def gen_context(self) -> str:
        """Generates a System Prompt context for AI agents."""
        lines = ["# SYSTEM COMPLIANCE CONSTRAINTS", f"POLICY: {self.policy_version}", "MANDATORY CONSTRAINTS:\n"]
        for name, data in self.config.get("profiles", {}).items():
            reqs = [r for r in data.get("requirements", []) if r["id"] not in self.ignored]
            flags = [f for f in data.get("red_flags", []) if f["pattern"] not in self.ignored]
            if not reqs and not flags:
                continue
            lines.append(f"## {data.get('badge_label', name)}")
            if reqs:
                lines.append("### REQUIRE:")
                for r in reqs:
                    name = r.get("label") or self._clean_header(r['id'])
                    lines.append(f"- {name}: {r.get('remediation','')}")
            if flags:
                lines.append("### FORBID:")
                for f in flags:
                    name = f.get("label") or f"PATTERN '{f['pattern']}'"
                    lines.append(f"- {name}: {f.get('remediation','')}")
            lines.append("")
        return "\n".join(lines)

    def _collect_files(self, path: str) -> List[str]:
        """Recursively collects supported files."""
        if os.path.isfile(path):
            return [path]
        found = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]  # Filter hidden dirs
            for f in files:
                if os.path.splitext(f)[1].lower() in {'.md', '.markdown', '.mdx', '.json', '.txt'}:
                    found.append(os.path.join(root, f))
        return found

    def scan_input(self, path: str, strict: bool = False) -> Tuple[Dict[str, Any], str]:
        """Scans input file or directory, handling aggregation."""
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
                if size > self.MAX_FILE_SIZE:
                    print(f"Warning: Skipping {file_path} (Size limit)", file=sys.stderr)
                    continue
                
                total_size += size
                if total_size > self.MAX_TOTAL_SIZE:
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
                    val = self.SEVERITY_MAP.get(c["severity"], 0)
                    if val > max_sev_val:
                        max_sev_val = val
                        max_sev_label = c["severity"]

        self.attestation = {
            "tool": "nod",
            "version": "1.8.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "files_audited": files,
            "aggregate_hash": agg_hash,
            "max_severity_gap": max_sev_label,
            "results": results,
            "remediation_summary": self._gen_prompt(results)
        }

        self._sign_attestation()
        return results, max_sev_label

    def _sign_attestation(self) -> None:
        """Signs the attestation using HMAC if key is present."""
        secret = os.environ.get("NOD_SECRET_KEY")
        if secret:
            payload = f"{self.attestation['aggregate_hash']}|{self.attestation['timestamp']}|{self.attestation['max_severity_gap']}"
            self.attestation["signature"] = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            self.attestation["signed"] = True
        else:
            self.attestation["signed"] = False

    def freeze(self, path: str = "nod.lock") -> None:
        """Freezes the current compliance state to a lockfile."""
        lock = {
            "version": self.policy_version,
            "aggregate_hash": self.attestation.get("aggregate_hash"),
            "files": self.attestation.get("files_audited", []),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        if k := os.environ.get("NOD_SECRET_KEY"):
            p = f"{lock['aggregate_hash']}|{lock['timestamp']}"
            lock["signature"] = hmac.new(k.encode(), p.encode(), hashlib.sha256).hexdigest()

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(lock, f, indent=2)
            print(f"✅ Baseline frozen to {path}")
        except Exception as e:
            print(f"Error freezing: {e}", file=sys.stderr)
            sys.exit(1)

    def verify(self, path: str = "nod.lock") -> bool:
        """Verifies current state against the frozen lockfile."""
        if not os.path.exists(path):
            print(f"Error: {path} not found.", file=sys.stderr)
            return False
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                lock = json.load(f)

            if k := os.environ.get("NOD_SECRET_KEY"):
                if not (sig := lock.get("signature")):
                    print("❌ Lockfile unsigned (Secret key present).")
                    return False
                exp = hmac.new(k.encode(), f"{lock['aggregate_hash']}|{lock['timestamp']}".encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, exp):
                    print("❌ Signature Mismatch (Tampering detected).")
                    return False
                print("🔒 Lockfile Signature Verified.")

            if self.attestation["aggregate_hash"] != lock.get("aggregate_hash"):
                print("❌ Verification Failed: Compliance Drift Detected.")
                return False

            print("✅ Verification Passed: No drift.")
            return True
        except Exception as e:
            print(f"Error verifying: {e}", file=sys.stderr)
            return False

    def _check_req(self, text: str, ext: str, req: Dict, strict: bool) -> Tuple[bool, int, int, str]:
        """Checks a single requirement against text content."""
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
            except Exception:
                pass
        else:
            try:
                match = re.search(rule_id, text, re.I | re.M)
                if match:
                    start_idx = match.start()
                    line = self._get_line_number(text, start_idx)
                    passed = True

                    # Section extraction logic
                    match_str = match.group(0).strip()
                    level = len(match_str) - len(match_str.lstrip('#')) if match_str.startswith('#') else 0
                    section = text[match.end():]
                    
                    next_pattern = r"^#{1," + str(level) + r"}\s" if level else r"^#+\s"
                    next_match = re.search(next_pattern, section, re.M)
                    if next_match:
                        section = section[:next_match.start()]

                    if strict and len(section.strip()) <= 15:
                        passed = False
                    
                    if passed:
                        if missing := [s for s in req.get("must_contain", []) if not re.search(re.escape(s), section, re.I)]:
                            passed = False
                            err = f"Missing: {', '.join(missing)}"
                        
                        for p in req.get("must_match", []):
                            if p.get("pattern") and not re.search(p["pattern"], section, re.I | re.M):
                                passed = False
                                err = p.get('message', 'Pattern mismatch')
            except re.error:
                pass
        
        return passed, line, start_idx, err

    def _audit(self, content: str, ext: str, strict: bool, base: str, def_src: str, fmap: Dict) -> Dict:
        """Main audit loop handling conditions, requirements, and red flags."""
        report = {}
        for name, data in self.config.get("profiles", {}).items():
            checks, skip = [], []
            
            # 1. Conditions
            for c in data.get("conditions", []):
                try:
                    if re.search(c["if"]["regex_match"], content, re.I | re.M):
                        skip.extend(c["then"].get("skip", []))
                        # Note: 'require' injection logic can be expanded here if needed
                except re.error as e:
                    print(f"Warning: Regex error in condition: {e}", file=sys.stderr)

            # 2. Requirements
            for req in data.get("requirements", []):
                rule_id = req["id"]
                status = "FAIL"
                passed = False
                line = 1
                src = def_src
                remediation = req.get("remediation", "")

                if rule_id in skip:
                    status, passed = "SKIPPED", True
                elif rule_id in self.ignored:
                    status, passed = "EXCEPTION", True
                else:
                    if req.get("mode") == "in_all_files" and fmap:
                        missing_files = []
                        for fp, txt in fmap.items():
                            p_ok, _, _, _ = self._check_req(txt, os.path.splitext(fp)[1], req, strict)
                            if not p_ok:
                                missing_files.append(os.path.basename(fp))
                        
                        if missing_files:
                            status = "FAIL"
                            remediation = f"Missing in: {', '.join(missing_files)}. " + remediation
                        else:
                            status, passed, src = "PASS", True, "all_files"
                    else:
                        p_ok, ln, idx, err = self._check_req(content, ext, req, strict)
                        if p_ok:
                            status, passed, line = "PASS", True, ln
                            if not src and idx >= 0:
                                src = self._resolve_source(content, idx)
                        if err:
                            remediation = f"{err}. " + remediation

                checks.append({
                    "id": rule_id,
                    "label": req.get("label"),
                    "passed": passed,
                    "status": status,
                    "severity": req.get("severity", "HIGH"),
                    "remediation": remediation,
                    "source": src,
                    "line": line,
                    "control_id": req.get("control_id"),
                    "article": req.get("article")
                })

            # 3. Red Flags
            for flag in data.get("red_flags", []):
                rule_id = flag["pattern"]
                status = "PASS"
                passed = True
                line = 1
                src = def_src
                
                try:
                    match = re.search(rule_id, content, re.I | re.M)
                    if match:
                        line = self._get_line_number(content, match.start())
                        if not src:
                            src = self._resolve_source(content, match.start())
                        
                        if rule_id in self.ignored:
                            status = "EXCEPTION"
                        elif rule_id in skip:
                            status = "SKIPPED"
                        else:
                            status, passed = "FAIL", False
                except re.error:
                    pass
                
                checks.append({
                    "id": rule_id,
                    "label": flag.get("label"),
                    "passed": passed,
                    "status": status,
                    "severity": flag.get("severity", "CRITICAL"),
                    "type": "red_flag",
                    "remediation": flag.get("remediation"),
                    "source": src,
                    "line": line,
                    "control_id": flag.get("control_id"),
                    "article": flag.get("article")
                })

            # 4. Cross-References
            for xref in data.get("cross_references", []):
                try:
                    for match in re.finditer(xref["source"], content, re.I | re.M):
                        expected = match.expand(xref["must_have"])
                        line = self._get_line_number(content, match.start())
                        passed = expected in content
                        checks.append({
                            "id": f"XRef: {match.group(0)}->{expected}",
                            "label": "Cross-Reference Validation",
                            "passed": passed,
                            "status": "PASS" if passed else "FAIL",
                            "severity": xref.get("severity", "HIGH"),
                            "remediation": f"Missing {expected}",
                            "line": line,
                            "source": self._resolve_source(content, match.start(), def_src)
                        })
                except re.error:
                    pass

            # 5. Evidence Verification
            if strict and ext != ".json" and ("security" in name or "baseline" in name):
                for match in re.finditer(r"\[([^\]]+)\]\((?!http)([^)]+)\)", content):
                    path = match.group(2).strip()
                    if not path.startswith("#"):
                        exists = os.path.exists(os.path.join(base, path))
                        checks.append({
                            "id": f"Ev: {match.group(1)}",
                            "label": "Evidence Check",
                            "passed": exists,
                            "status": "PASS" if exists else "FAIL",
                            "severity": "MEDIUM",
                            "remediation": f"Missing: {path}",
                            "line": 1,
                            "source": self._resolve_source(content, match.start(), def_src)
                        })

            block = [c for c in checks if c["status"] == "FAIL" and self.SEVERITY_MAP.get(c["severity"], 0) >= 3]
            report[name] = {"label": data.get("badge_label", name), "checks": checks, "passed": not block}
        return report

    def _gen_prompt(self, res: Dict[str, Any]) -> str:
        gaps = []
        for p in res.values():
            for c in p.get("checks", []):
                if c["status"] == "FAIL":
                    name = c.get("label") or c['id']
                    ref = c.get("control_id") or c.get("article") or ""
                    ref_str = f"[{ref}]" if ref else ""
                    gaps.append(f"- [{c['severity']}] {name} {ref_str}: {c.get('remediation', '')}")
        return "\n".join(gaps) if gaps else "No gaps."

    def apply_fix(self, path: str, res: Dict[str, Any]) -> None:
        tgt = path if os.path.isfile(path) else os.path.join(path, "nod-compliance.md")
        try:
            with open(tgt, "a", encoding="utf-8") as f:
                f.write("\n\n<!-- nod: auto-fix -->\n")
                count = 0
                for data in res.values():
                    miss = [c for c in data["checks"] if c["status"] == "FAIL" and c.get("type") != "red_flag" and not c.get("id").startswith("XRef")]
                    if miss:
                        f.write(f"\n## Missing: {data['label']}\n")
                        for m in miss:
                            header = m.get("label") or self._clean_header(m['id'])
                            f.write(f"\n### {header}\n")
                            if m.get("control_id"):
                                f.write(f"> Ref: {m['control_id']}\n")
                            f.write(f"<!-- {m.get('remediation')} -->\nTODO: Details.\n")
                            count += 1
            print(f"✅ Patched {tgt} (+{count})")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)

    def gen_sarif(self, path: str) -> Dict[str, Any]:
        rules = []
        runs = []
        rmap = {}
        for data in self.attestation["results"].values():
            for c in data["checks"]:
                rule_id = c["id"]
                if rule_id not in rmap:
                    rmap[rule_id] = len(rules)
                    props = {"severity": c["severity"]}
                    if c.get("article"):
                        props["article"] = c["article"]
                    if c.get("control_id"):
                        props["compliance-ref"] = c["control_id"]
                        props["security-severity"] = self.SARIF_SCORE_MAP.get(c["severity"], "1.0")
                    
                    desc = c.get("label") or rule_id
                    rules.append({
                        "id": rule_id,
                        "name": desc,
                        "shortDescription": {"text": c.get("remediation", desc)},
                        "properties": props
                    })
                
                if c["status"] in ["FAIL", "EXCEPTION"]:
                    uri = c.get("source") if c.get("source") and c.get("source") != "unknown" else path
                    level = self.SARIF_LEVEL_MAP.get(c["severity"], "note")
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
                        "version": self.attestation.get("version", "1.0.0"),
                        "rules": rules
                    }
                },
                "results": runs
            }]
        }

    def gen_report(self) -> str:
        out = []
        for data in self.attestation["results"].values():
            checks = data.get("checks", [])
            compliant = len([c for c in checks if c["status"] != "FAIL"])
            total = len(checks)
            pct = int((compliant / total * 100) if total else 0)
            
            out.append(f"{data['label']} Report ({datetime.utcnow().strftime('%Y-%m-%d')})\nStatus: {pct}% Compliant\n")
            for c in checks:
                icon = {"FAIL": "❌", "EXCEPTION": "⚪", "SKIPPED": "⏭️"}.get(c["status"], "✅")
                ref = c.get("article") or c.get("control_id")
                name = c.get("label") or self._clean_header(c['id'])
                out.append(f"{icon} {f'{ref}: ' if ref else ''}{name}")
                
                if c["status"] == "FAIL":
                    out.append(f"   MISSING: {c.get('remediation','')}")
                elif c["status"] == "PASS" and c.get("source") and c["source"] != "unknown":
                    out.append(f"   Ev: {c['source']}:{c.get('line')}")
                out.append("")
            out.append("-" * 40)
        return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="nod: AI Spec Compliance")
    parser.add_argument("path", nargs="?", help="File/Dir to audit")
    parser.add_argument("--rules", action='append')
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--fix", action="store_true")
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--min-severity", default="HIGH", choices=["MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--output", choices=["text", "json", "sarif", "compliance"], default="text")
    parser.add_argument("--save-to")
    args = parser.parse_args()

    default_rules = ["defaults"] if os.path.isdir("defaults") else ["rules.yaml"]
    scanner = Nod(args.rules if args.rules else default_rules)

    if args.export:
        print(scanner.gen_context())
        sys.exit(0)
        
    if args.init:
        template = scanner.gen_template()
        if args.path:
            if os.path.exists(args.path):
                print("Error: File exists", file=sys.stderr)
                sys.exit(1)
            with open(args.path, "w", encoding="utf-8") as f:
                f.write(template)
            print(f"✅ Generated: {args.path}")
        else:
            print(template)
        sys.exit(0)

    if not args.path:
        parser.print_help()
        sys.exit(1)

    results, max_sev_label = scanner.scan_input(args.path, strict=args.strict)
    
    if args.freeze:
        scanner.freeze()
        sys.exit(0)
    
    if args.verify:
        if not scanner.verify():
            sys.exit(1)
        sys.exit(0)

    if args.fix:
        scanner.apply_fix(args.path, results)
        sys.exit(0)

    output_content = ""
    exit_code = 0
    
    if args.output == "sarif":
        output_content = json.dumps(scanner.gen_sarif(args.path), indent=2)
    elif args.output == "json":
        output_content = json.dumps(scanner.attestation, indent=2)
    elif args.output == "compliance":
        output_content = scanner.gen_report()
    else:
        # Determine usage of color
        use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        def colorize(text, code):
            return f"{code}{text}{Colors.RESET}" if use_color else text

        summary = [f"\n--- nod Summary ---\nTarget: {args.path}\nMax Sev: {max_sev_label}"]
        if scanner.attestation.get("signed"):
            summary.append(f"{colorize('🔒 Signed', Colors.GREEN)}")
            
        fail_check = False
        min_val = scanner.SEVERITY_MAP.get(args.min_severity, 0)
        
        for data in results.values():
            summary.append(f"\n[{colorize(data['label'], Colors.BOLD)}]")
            for check in data["checks"]:
                name = check.get("label") or check['id']
                if check["status"] == "FAIL":
                    sev_col = Colors.RED if check['severity'] in ["CRITICAL", "HIGH"] else Colors.YELLOW
                    summary.append(f"  {colorize('❌', Colors.RED)} [{colorize(check['severity'], sev_col)}] {name}")
                    if check.get("source"):
                        summary.append(f"     File: {check['source']}")
                    
                    if scanner.SEVERITY_MAP.get(check["severity"], 0) >= min_val:
                        fail_check = True
                elif check["status"] == "EXCEPTION":
                    summary.append(f"  {colorize('⚪', Colors.BLUE)} [EXCEPTION] {name}")
                elif check["status"] == "SKIPPED":
                    summary.append(f"  {colorize('⏭️', Colors.CYAN)}  [SKIPPED] {name}")
                else:
                    summary.append(f"  {colorize('✅', Colors.GREEN)} [PASS] {name}")
        
        status_msg = f"\nFAIL: Blocked by {args.min_severity}+" if fail_check else "\nPASS: Nod granted."
        summary.append(colorize(status_msg, Colors.RED if fail_check else Colors.GREEN))
        output_content = "\n".join(summary)
        if fail_check:
            exit_code = 1

    # Check exit code based on severity for non-text outputs too
    if scanner.SEVERITY_MAP.get(max_sev_label, 0) >= scanner.SEVERITY_MAP.get(args.min_severity, 0):
        exit_code = 1

    if args.save_to:
        try:
            with open(args.save_to, "w", encoding="utf-8") as f:
                f.write(output_content)
            print(f"Saved: {args.save_to}")
        except Exception as e:
            print(f"Error saving file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_content)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
