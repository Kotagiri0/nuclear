import argparse
import sys
from pathlib import Path
from scanner import scan_directory, scan_file, scan_zip, generate_report


def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner — finds API keys, tokens and sensitive data"
    )
    parser.add_argument("path", help="File, directory or .zip archive to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
    )
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path '{args.path}' does not exist", file=sys.stderr)
        sys.exit(1)

    if target.suffix.lower() == ".zip":
        findings = scan_zip(str(target))
    elif target.is_dir():
        findings = scan_directory(str(target))
    else:
        findings = scan_file(str(target))

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_level = severity_order[args.min_severity]
    findings = [f for f in findings if severity_order[f.severity] >= min_level]

    print(generate_report(findings, output_format=args.format))

    has_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
