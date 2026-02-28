import argparse
import sys
from pathlib import Path

from .inputs import scan_remote_source
from .policy import filter_by_min_severity, should_fail
from .reporting import generate_report
from .scanning import scan_directory, scan_file, scan_git_history, scan_zip


def _scan_local_target(path: Path, scan_history: bool, history_commits: int) -> list:
    if path.suffix.lower() == ".zip":
        return scan_zip(str(path))
    if path.is_dir():
        findings = scan_directory(str(path))
        if scan_history and (path / ".git").exists():
            findings.extend(scan_git_history(str(path), max_commits=history_commits))
        return findings
    return scan_file(str(path))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secret Scanner — ищет API-ключи, токены и чувствительные данные",
    )
    parser.add_argument("target", nargs="?", help="Файл, директория или .zip архив для сканирования")
    parser.add_argument("--url", help="Удаленный Git/HTTP/ZIP URL для загрузки и сканирования")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH")
    parser.add_argument("--scan-history", action="store_true", help="Сканировать историю Git-коммитов")
    parser.add_argument("--history-commits", type=int, default=50, help="Максимальное число коммитов для сканирования")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.target and not args.url:
        parser.error("Укажите либо путь к цели, либо --url")

    findings = []
    if args.url:
        findings, _, _ = scan_remote_source(
            args.url,
            scan_history=args.scan_history,
            history_commits=args.history_commits,
        )
    else:
        target = Path(args.target)
        if not target.exists():
            print(f"Ошибка: путь '{args.target}' не существует", file=sys.stderr)
            sys.exit(1)
        findings = _scan_local_target(target, args.scan_history, args.history_commits)

    findings = filter_by_min_severity(findings, args.min_severity)
    print(generate_report(findings, output_format=args.format))
    sys.exit(1 if should_fail(findings, args.fail_on) else 0)


if __name__ == "__main__":
    main()
