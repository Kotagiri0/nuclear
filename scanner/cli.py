import argparse
import sys
from pathlib import Path

from scanner.config import load_config
from scanner.policy import should_fail
from scanner.reporting import generate_report
from scanner.runner import run_scan


def build_parser(cfg=None) -> argparse.ArgumentParser:
    if cfg is None:
        cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Secret Scanner — ищет API-ключи, токены и чувствительные данные",
    )
    parser.add_argument("target", nargs="?", help="Файл, директория или .zip архив для сканирования")
    parser.add_argument("--url", help="Удаленный Git/HTTP/ZIP URL для загрузки и сканирования")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default=cfg.format if cfg.format != "table" else "text")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.severity)
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.fail_on)
    parser.add_argument("--scan-history", action="store_true", default=cfg.history, help="Сканировать историю Git-коммитов")
    parser.add_argument("--history-commits", type=int, default=cfg.commits, help="Максимальное число коммитов для сканирования")
    parser.add_argument("--output", default=cfg.output_file or None, help="Путь к файлу отчёта (по умолчанию — stdout)")
    return parser


def main() -> None:
    # Ensure stdout supports Unicode on Windows (handles emoji in reports)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cfg = load_config()
    parser = build_parser(cfg)
    args = parser.parse_args()

    if not args.target and not args.url:
        parser.error("Укажите либо путь к цели, либо --url")

    try:
        findings = run_scan(
            target=args.target,
            url=args.url,
            min_severity=args.min_severity,
            scan_history=args.scan_history,
            history_commits=args.history_commits,
        )
    except FileNotFoundError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)

    report = generate_report(findings, output_format=args.format)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
    else:
        print(report)

    sys.exit(1 if should_fail(findings, args.fail_on) else 0)


if __name__ == "__main__":
    main()
