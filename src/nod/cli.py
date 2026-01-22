import argparse
import sys
import os
import json
from .config import load_rules, load_ignore
from .scanner import Scanner, SEVERITY_MAP
from .generator import gen_template, gen_context, apply_fix
from .reporters import gen_sarif, gen_report
from .security import sign_attestation, freeze, verify
from .utils import Colors, colorize
from . import __version__

def main():
    parser = argparse.ArgumentParser(description="nod: AI Spec Compliance")
    parser.add_argument("path", nargs="?", help="File/Dir to audit")
    parser.add_argument("--rules", action='append')
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--fix", action="store_true")
    parser.add_argument("--export", nargs="?", const="context", choices=["context", "cursor", "windsurf"], help="Export context/rules")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--min-severity", default="HIGH", choices=["MEDIUM", "HIGH", "CRITICAL"])
    parser.add_argument("--output", choices=["text", "json", "sarif", "compliance"], default="text")
    parser.add_argument("--save-to")
    parser.add_argument("--version", action="version", version=f"nod v{__version__}")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    default_rules = ["defaults"] if os.path.isdir("defaults") else ["rules.yaml"]
    sources = args.rules if args.rules else default_rules
    
    # Init config (Quietly unless error)
    config = load_rules(sources)
    policy_version = config.get("version", "unknown")
    ignored = load_ignore(".nodignore")

    if args.export:
        print(gen_context(config, policy_version, ignored, args.export))
        sys.exit(0)
        
    if args.init:
        template = gen_template(config, policy_version)
        if args.path:
            if os.path.exists(args.path):
                print("Error: File exists", file=sys.stderr)
                sys.exit(1)
            with open(args.path, "w", encoding="utf-8") as f:
                f.write(template)
            if not args.quiet:
                print(f"✅ Generated: {args.path}")
        else:
            print(template)
        sys.exit(0)

    if not args.path:
        parser.print_help()
        sys.exit(1)

    scanner = Scanner(config, ignored)
    results, max_sev_label = scanner.scan_input(args.path, strict=args.strict, version=policy_version)
    
    # Sign attestation
    sign_attestation(scanner.attestation)

    if args.freeze:
        freeze(policy_version, scanner.attestation)
        if not args.quiet:
            print(f"✅ Baseline frozen to nod.lock")
        sys.exit(0)
    
    if args.verify:
        if not verify(scanner.attestation):
            sys.exit(1)
        if not args.quiet:
            print("✅ Verification Passed: No drift.")
        sys.exit(0)

    if args.fix:
        apply_fix(args.path, results)
        sys.exit(0)

    output_content = ""
    exit_code = 0
    
    if args.output == "sarif":
        output_content = json.dumps(gen_sarif(scanner.attestation, args.path), indent=2)
    elif args.output == "json":
        output_content = json.dumps(scanner.attestation, indent=2)
    elif args.output == "compliance":
        output_content = gen_report(scanner.attestation)
    else:
        # Text Output
        summary = []
        if not args.quiet:
            summary.append(f"\n--- nod Summary ---\nTarget: {args.path}\nMax Sev: {max_sev_label}")
            if scanner.attestation.get("signed"):
                summary.append(f"{colorize('🔒 Signed', Colors.GREEN)}")
            
        fail_check = False
        min_val = SEVERITY_MAP.get(args.min_severity, 0)
        
        for data in results.values():
            # In quiet mode, skip profile headers unless there's a failure inside? 
            # Or just print failures. Let's print failures only in quiet mode.
            profile_buffer = []
            if not args.quiet:
                profile_buffer.append(f"\n[{colorize(data['label'], Colors.BOLD)}]")
            
            has_failures = False
            for check in data["checks"]:
                name = check.get("label") or check['id']
                if check["status"] == "FAIL":
                    has_failures = True
                    sev_col = Colors.RED if check['severity'] in ["CRITICAL", "HIGH"] else Colors.YELLOW
                    profile_buffer.append(f"  {colorize('❌', Colors.RED)} [{colorize(check['severity'], sev_col)}] {name}")
                    if check.get("source"):
                        profile_buffer.append(f"     File: {check['source']}")
                    
                    if SEVERITY_MAP.get(check["severity"], 0) >= min_val:
                        fail_check = True
                elif not args.quiet:
                    if check["status"] == "EXCEPTION":
                        profile_buffer.append(f"  {colorize('⚪', Colors.BLUE)} [EXCEPTION] {name}")
                    elif check["status"] == "SKIPPED":
                        profile_buffer.append(f"  {colorize('⏭️', Colors.CYAN)}  [SKIPPED] {name}")
                    else:
                        profile_buffer.append(f"  {colorize('✅', Colors.GREEN)} [PASS] {name}")
            
            # In quiet mode, only append buffer if there were failures
            if not args.quiet or has_failures:
                summary.extend(profile_buffer)
        
        if fail_check:
            status_msg = f"\nFAIL: Blocked by {args.min_severity}+"
            summary.append(colorize(status_msg, Colors.RED))
            exit_code = 1
        elif not args.quiet:
            status_msg = "\nPASS: Nod granted."
            summary.append(colorize(status_msg, Colors.GREEN))
            
        output_content = "\n".join(summary)

    # Check exit code based on severity for non-text outputs too
    if SEVERITY_MAP.get(max_sev_label, 0) >= SEVERITY_MAP.get(args.min_severity, 0):
        exit_code = 1

    if args.save_to:
        try:
            with open(args.save_to, "w", encoding="utf-8") as f:
                f.write(output_content)
            if not args.quiet:
                print(f"Saved: {args.save_to}")
        except Exception as e:
            print(f"Error saving file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Only print if there is content (quiet mode with no errors might be empty)
        if output_content.strip():
            print(output_content)
    
    sys.exit(exit_code)
