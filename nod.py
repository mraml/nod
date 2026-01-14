"""
nod: AI Spec Compliance Gatekeeper

A platform-agnostic, rule-based linter that ensures AI/LLM specifications
contain critical security and compliance elements before automated development.
"""

import argparse
import hashlib
import json
import os
import re
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

    def __init__(self, rules_source: str) -> None:
        """
        Initialize the scanner with rules from a local path or remote URL.

        Args:
            rules_source: Path to a local YAML file or a URL starting with http/https.
        """
        self.rules_source = rules_source
        self.config = self._load_rules(source=rules_source)
        self.attestation: Dict[str, Any] = {}

    def _load_rules(self, source: str) -> Dict[str, Any]:
        """
        Loads rules from a local file or remote URL.

        Args:
            source: The file path or URL string.

        Returns:
            A dictionary containing the parsed YAML configuration.
        """
        try:
            if source.startswith(("http://", "https://")):
                with urllib.request.urlopen(source) as response:
                    return yaml.safe_load(response.read())
            with open(source, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rules from {source}: {str(e)}")
            sys.exit(1)

    def scan_file(
        self, file_path: str, strict: bool = False
    ) -> Tuple[Dict[str, Any], str]:
        """
        Scans a file against the loaded compliance rules.

        Args:
            file_path: Path to the specification file (.md or .json).
            strict: If True, checks that required sections have content.

        Returns:
            A tuple containing:
            - results: Dictionary of audit results per profile.
            - max_sev_label: The highest severity gap found (e.g., "CRITICAL").
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}, "NONE"

        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                file_hash = hashlib.sha256(content.encode()).hexdigest()
        except Exception as e:
            return {"error": f"Could not read file: {str(e)}"}, "NONE"

        results = self._audit_logic(content, ext, strict)

        # Determine Maximum Severity for Gatekeeping
        max_sev_value = -1
        max_sev_label = "NONE"
        for p in results.values():
            if "checks" in p:
                for c in p["checks"]:
                    if not c["passed"]:
                        val = self.SEVERITY_MAP.get(c["severity"], 0)
                        if val > max_sev_value:
                            max_sev_value = val
                            max_sev_label = c["severity"]

        # Attestation Artifact: Structured for Downstream Agents
        self.attestation = {
            "tool": "nod",
            "version": "1.2.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "file_audited": file_path,
            "file_sha256": file_hash,
            "max_severity_gap": max_sev_label,
            "results": results,
            "remediation_summary": self._generate_agent_prompt(results),
        }

        return results, max_sev_label

    def _audit_logic(
        self, content: str, ext: str, strict: bool
    ) -> Dict[str, Any]:
        """Core logic for checking JSON keys or Markdown patterns."""
        report = {}
        profiles = self.config.get("profiles", {})

        for profile, profile_data in profiles.items():
            checks = []

            # 1. Requirements Scanning
            for req in profile_data.get("requirements", []):
                item_id = req["id"]
                sev = req.get("severity", "HIGH").upper()
                passed = False

                if ext == ".json":
                    try:
                        data = json.loads(content)
                        # Check existence and non-empty if strict
                        if item_id in data:
                            passed = True
                            if strict and not str(data[item_id]).strip():
                                passed = False
                    except json.JSONDecodeError:
                        pass
                else:
                    # Markdown/Text regex check
                    match = re.search(item_id, content, re.IGNORECASE | re.MULTILINE)
                    if match:
                        passed = True
                        if strict:
                            # Verify meaningful content exists after the header
                            # Grab text from end of match until next header or EOF
                            start_index = match.end()
                            following_text = content[start_index:].split("#")[0].strip()
                            passed = len(following_text) > 15  # Min char count threshold

                checks.append({
                    "id": item_id,
                    "passed": passed,
                    "severity": sev,
                    "remediation": req.get("remediation"),
                    "template_url": req.get("template_url"),
                })

            # 2. Red-Flag Scanning (Anti-patterns)
            for flag in profile_data.get("red_flags", []):
                item_id = flag["pattern"]
                sev = flag.get("severity", "CRITICAL").upper()
                found = re.search(item_id, content, re.IGNORECASE | re.MULTILINE)

                checks.append({
                    "id": item_id,
                    "passed": not bool(found),
                    "severity": sev,
                    "type": "red_flag",
                    "remediation": flag.get("remediation"),
                })

            # Determine profile pass/fail status
            # Only count severity >= HIGH (value 3) as blocking for the profile status
            blocking_failures = [
                c for c in checks
                if not c["passed"] and self.SEVERITY_MAP.get(c["severity"], 0) >= 3
            ]

            report[profile] = {
                "label": profile_data.get("badge_label", profile),
                "checks": checks,
                "passed": len(blocking_failures) == 0,
            }
        return report

    def _generate_agent_prompt(self, results: Dict[str, Any]) -> str:
        """Helper to create a concise summary for agentic resolution."""
        gaps = []
        for p in results.values():
            if "checks" in p:
                for c in p["checks"]:
                    if not c["passed"]:
                        gaps.append(
                            f"- [{c['severity']}] {c['id']}: {c.get('remediation', '')}"
                        )
        return "\n".join(gaps) if gaps else "No gaps detected."


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="nod: AI Spec Compliance Gatekeeper"
    )
    parser.add_argument("file", help="The spec file to audit")
    parser.add_argument(
        "--rules",
        default="rules.yaml",
        help="Local path or remote URL for rules",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Ensure fields are not empty",
    )
    parser.add_argument(
        "--min-severity",
        default="HIGH",
        choices=["MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity level to fail the build",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    args = parser.parse_args()

    scanner = Nod(args.rules)
    results, max_sev = scanner.scan_file(args.file, strict=args.strict)

    # JSON Output Handling
    if args.output == "json":
        print(json.dumps(scanner.attestation, indent=2))
        max_sev_val = scanner.SEVERITY_MAP.get(max_sev, 0)
        threshold_val = scanner.SEVERITY_MAP.get(args.min_severity)
        sys.exit(0 if max_sev_val < threshold_val else 1)

    # Text Output Handling
    print(f"\n--- nod Audit Summary ---")
    print(f"File: {args.file}")
    print(f"Max Severity Gap: {max_sev}")
    print(f"--------------------------")

    failed_gate = False
    min_val = scanner.SEVERITY_MAP.get(args.min_severity)

    if "error" in results:
        print(f"Error: {results['error']}")
        sys.exit(1)

    for profile, data in results.items():
        print(f"\n[{data['label']}]")
        for check in data["checks"]:
            if not check["passed"]:
                icon = "🚩" if check.get("type") == "red_flag" else "❌"
                print(f"  {icon} [{check['severity']}] {check['id']}")
                print(f"     Remediation: {check.get('remediation', 'None')}")
                if check.get("template_url"):
                    print(f"     Template: {check['template_url']}")

                if scanner.SEVERITY_MAP.get(check["severity"], 0) >= min_val:
                    failed_gate = True
            else:
                print(f"  ✅ [PASS] {check['id']}")

    # Save attestation regardless of pass/fail for the audit trail
    try:
        with open("nod-attestation.json", "w", encoding="utf-8") as f:
            json.dump(scanner.attestation, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save attestation artifact: {e}")

    if failed_gate:
        print(f"\nFAIL: Build blocked due to {args.min_severity}+ severity gaps.")
        sys.exit(1)
    else:
        print(f"\nPASS: Final nod of approval granted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
