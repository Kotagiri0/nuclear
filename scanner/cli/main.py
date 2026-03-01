import argparse
import sys
import time
from pathlib import Path

from scanner.config import load_config
from scanner.output.policy import should_fail
from scanner.output.reporting import generate_report
from scanner.core.runner import run_scan


def build_parser(cfg=None) -> argparse.ArgumentParser:
    if cfg is None:
        cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Secret Scanner — ищет API-ключи, токены и чувствительные данные",
    )
    parser.add_argument("target", nargs="?", help="Файл, директория или .zip архив для сканирования")
    parser.add_argument("--url", help="Удаленный Git/HTTP/ZIP URL для загрузки и сканирования")
    parser.add_argument("--format", choices=["text", "json", "sarif", "html"], default=cfg.format if cfg.format != "table" else "text")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.severity)
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.fail_on)
    parser.add_argument("--scan-history", action="store_true", default=cfg.history, help="Сканировать историю Git-коммитов")
    parser.add_argument("--history-commits", type=int, default=cfg.commits, help="Максимальное число коммитов для сканирования")
    parser.add_argument("--output", default=cfg.output_file or None, help="Путь к файлу отчёта (по умолчанию — stdout)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Исключить файлы по glob-паттерну (можно указать несколько раз)")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB", help="Сканировать только файлы по glob-паттерну (можно указать несколько раз)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Тихий режим — только exit code, без вывода")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный режим — время сканирования, кол-во файлов")
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

    file_count = 0

    def _on_file(_path: str) -> None:
        nonlocal file_count
        file_count += 1

    start_time = time.monotonic()

    try:
        findings = run_scan(
            target=args.target,
            url=args.url,
            min_severity=args.min_severity,
            scan_history=args.scan_history,
            history_commits=args.history_commits,
            exclude=args.exclude or None,
            include=args.include or None,
            on_file=_on_file,
        )
    except FileNotFoundError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.monotonic() - start_time

    if not args.quiet:
        if args.format == "html":
            from scanner.output.html_report import save_html_report
            scan_target = args.target or args.url or "unknown"
            report_path = save_html_report(findings, target=scan_target)
            print(f"📄 HTML report saved: {report_path}")
        else:
            report = generate_report(findings, output_format=args.format)
            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report, encoding="utf-8")
            else:
                print(report)

        if args.verbose:
            print(f"\n⏱  Время: {elapsed:.2f}с | 📁 Файлов: {file_count} | 🔍 Секретов: {len(findings)}", file=sys.stderr)

    sys.exit(1 if should_fail(findings, args.fail_on) else 0)


if __name__ == "__main__":
    main()
