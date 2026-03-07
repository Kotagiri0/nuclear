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
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html", "pdf"],
        default=cfg.format if cfg.format != "table" else "text",
    )
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.severity)
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=cfg.fail_on)
    parser.add_argument("--scan-history", action="store_true", default=cfg.history, help="Сканировать историю Git-коммитов")
    parser.add_argument("--history-commits", type=int, default=cfg.commits, help="Максимальное число коммитов для сканирования")
    parser.add_argument("--output", default=cfg.output_file or None, help="Путь к файлу отчёта (по умолчанию — stdout)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Исключить файлы по glob-паттерну (можно указать несколько раз)")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB", help="Сканировать только файлы по glob-паттерну (можно указать несколько раз)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Тихий режим — только exit code, без вывода")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный режим — время сканирования, кол-во файлов")
    parser.add_argument("--recommendations", action="store_true", help="Добавить рекомендации по устранению найденных утечек")
    parser.add_argument(
        "--ai-security",
        action="store_true",
        help="Опционально: LLM-сканирование безопасности кода (внешний вызов; требует ключ и пакет openai)",
    )
    parser.add_argument(
        "--ai-provider",
        choices=["nvidia"],
        default="nvidia",
        help="AI-провайдер для --ai-security (по умолчанию: nvidia)",
    )
    parser.add_argument(
        "--ai-model",
        default=None,
        help="Имя модели (если не указано — выберется любая Qwen, приоритет 122B)",
    )
    parser.add_argument(
        "--ai-base-url",
        default="https://integrate.api.nvidia.com/v1",
        help="Base URL для AI-провайдера (по умолчанию: NVIDIA integrate api)",
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=30,
        help="Таймаут AI-запроса (сек)",
    )
    parser.add_argument(
        "--ai-max-bytes",
        type=int,
        default=50_000,
        help="Не отправлять в AI файлы больше этого размера (байт)",
    )
    parser.add_argument(
        "--ai-max-tokens",
        type=int,
        default=500,
        help="Максимум токенов в ответе AI",
    )
    parser.add_argument(
        "--ai-max-files",
        type=int,
        default=50,
        help="Лимит числа LLM-запросов за запуск (0 = без лимита)",
    )
    parser.add_argument(
        "--ai-scan-all",
        action="store_true",
        help="Сканировать LLM-ом все поддерживаемые файлы (медленно). По умолчанию LLM вызывается только для 'подозрительных' файлов.",
    )
    return parser


def main() -> None:
    # Ensure stdout supports Unicode on Windows (handles emoji in reports)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Load local .env (if present) before reading config/env overrides
    try:
        from scanner.config import load_dotenv

        load_dotenv()
    except Exception:
        pass
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

    ai_security_cfg = None
    if getattr(args, "ai_security", False):
        from scanner.ai.security import AISecurityConfig

        ai_security_cfg = AISecurityConfig(
            provider=args.ai_provider,
            base_url=args.ai_base_url,
            model=args.ai_model,
            max_tokens=args.ai_max_tokens,
            timeout_s=args.ai_timeout,
            max_bytes=args.ai_max_bytes,
            max_files=args.ai_max_files,
            scan_all_files=args.ai_scan_all,
        )

    try:
        findings = run_scan(
            target=args.target,
            url=args.url,
            min_severity=args.min_severity,
            scan_history=args.scan_history,
            history_commits=args.history_commits,
            exclude=args.exclude or None,
            include=args.include or None,
            ai_security_cfg=ai_security_cfg,
            on_file=_on_file,
        )
    except FileNotFoundError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        # AI mode (and some remote scan flows) can raise meaningful runtime errors.
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.monotonic() - start_time

    if not args.quiet:
        if args.format == "html":
            from scanner.output.html_report import save_html_report
            scan_target = args.target or args.url or "unknown"
            report_path = save_html_report(findings, target=scan_target)
            print(f"📄 HTML report saved: {report_path}")
        elif args.format == "pdf":
            from scanner.output.pdf_report import save_pdf_report

            scan_target = args.target or args.url or "unknown"
            report_path = save_pdf_report(
                findings,
                target=scan_target,
                output_path=args.output if args.output else None,
            )
            print(f"📄 PDF report saved: {report_path}")
        else:
            report = generate_report(findings, output_format=args.format)
            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report, encoding="utf-8")
            else:
                print(report)
            
            # Add recommendations if requested
            if args.recommendations and findings:
                from scanner.output.recommendations import generate_recommendations_report
                print("\n")
                rec_report = generate_recommendations_report(findings)
                if args.output:
                    rec_path = out_path.parent / "recommendations.txt"
                    rec_path.write_text(rec_report, encoding="utf-8")
                    print(f"\n📄 Recommendations saved: {rec_path}")
                else:
                    print(rec_report)

        if args.verbose:
            print(f"\n⏱  Время: {elapsed:.2f}с | 📁 Файлов: {file_count} | 🔍 Секретов: {len(findings)}", file=sys.stderr)

    sys.exit(1 if should_fail(findings, args.fail_on) else 0)


if __name__ == "__main__":
    main()
