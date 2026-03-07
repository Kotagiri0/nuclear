"""
Модуль рекомендаций по устранению утечек секретов.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Recommendation:
    title: str
    description: str
    code_example: Optional[str] = None
    priority: str = "high"  # high, medium, low


RECOMMENDATIONS = {
    "AWS Access Key": Recommendation(
        title="Перенесите AWS credentials в переменные окружения или IAM role",
        description=(
            "Никогда не храните AWS credentials в коде. Используйте:\n"
            "• Переменные окружения (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)\n"
            "• IAM roles для EC2/Lambda\n"
            "• AWS Secrets Manager или Parameter Store"
        ),
        code_example="""# ❌ Неправильно:
AWS_ACCESS_KEY_ID = "AKIA..."

# ✅ Правильно:
import os
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")

# ✅ Ещё лучше (IAM role):
import boto3
client = boto3.client('s3')  # Credentials автоматически берутся из IAM role""",
        priority="high",
    ),
    "AWS Secret Key": Recommendation(
        title="Перенесите AWS Secret Key в безопасное хранилище",
        description=(
            "AWS Secret Key предоставляет полный доступ к вашим ресурсам AWS.\n"
            "Используйте IAM roles или AWS Secrets Manager."
        ),
        priority="high",
    ),
    "GitHub Token": Recommendation(
        title="Удалите токен GitHub и используйте GitHub Secrets",
        description=(
            "GitHub токены предоставляют доступ к вашим репозиториям.\n"
            "• Для CI/CD используйте GitHub Secrets\n"
            "• Для локальной разработки — переменные окружения\n"
            "• Отозовите скомпрометированный токен в настройках GitHub"
        ),
        code_example="""# ❌ Неправильно:
GITHUB_TOKEN = "ghp_..."

# ✅ Правильно:
import os
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ✅ Для GitHub Actions:
# Используйте ${{ secrets.GITHUB_TOKEN }} в workflow""",
        priority="high",
    ),
    "Stripe Secret Key": Recommendation(
        title="Перенесите Stripe API ключи в переменные окружения",
        description=(
            "Stripe Secret Key позволяет проводить платежи от вашего имени.\n"
            "• Используйте переменные окружения\n"
            "• Настройте разные ключи для development/production\n"
            "• Отозовите скомпрометированный ключ в Stripe Dashboard"
        ),
        priority="high",
    ),
    "Private Key": Recommendation(
        title="Немедленно удалите приватный ключ из репозитория",
        description=(
            "⚠️ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!\n"
            "Приватные ключи дают полный доступ к серверам/сертификатам.\n"
            "• Немедленно отзовите ключ и сгенерируйте новый\n"
            "• Используйте менеджеры секретов (HashiCorp Vault, AWS Secrets Manager)\n"
            "• Настройте pre-commit хуки для предотвращения коммитов"
        ),
        priority="high",
    ),
    "JWT Token": Recommendation(
        title="Не храните JWT токены в коде",
        description=(
            "JWT токены могут предоставить доступ к пользовательским данным.\n"
            "• Генерируйте токены динамически\n"
            "• Храните секрет подписи в переменных окружениях\n"
            "• Установите короткое время жизни токенов"
        ),
        priority="medium",
    ),
    "Connection String": Recommendation(
        title="Перенесите строки подключения к БД в переменные окружения",
        description=(
            "Connection strings содержат учётные данные к базам данных.\n"
            "• Используйте переменные окружения\n"
            "• Применяйте системы управления секретами\n"
            "• Ограничьте права доступа БД по принципу минимальных привилегий"
        ),
        code_example="""# ❌ Неправильно:
DATABASE_URL = "postgres://admin:fake_password@localhost:5432/db"

# ✅ Правильно:
import os
DATABASE_URL = os.getenv("DATABASE_URL")

# ✅ С использованием Secrets Manager:
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/db/url')""",
        priority="high",
    ),
    "Generic Secret": Recommendation(
        title="Перенесите секретные значения в безопасное хранилище",
        description=(
            "Общие секреты (пароли, API ключи) не должны храниться в коде.\n"
            "• Используйте переменные окружения\n"
            "• Примените .env файлы (добавив их в .gitignore)\n"
            "• Используйте менеджеры секретов"
        ),
        priority="medium",
    ),
    "Generic API Key": Recommendation(
        title="Перенесите API ключи в переменные окружения",
        description=(
            "API ключи предоставляют доступ к внешним сервисам.\n"
            "• Храните в переменных окружения\n"
            "• Регулярно ротируйте ключи\n"
            "• Используйте разные ключи для разных окружений"
        ),
        priority="medium",
    ),
    "Bearer Token": Recommendation(
        title="Не храните bearer токены в коде",
        description=(
            "Bearer токены используются для аутентификации.\n"
            "• Получайте токены динамически через OAuth flow\n"
            "• Храните refresh tokens в безопасном хранилище\n"
            "• Установите короткое время жизни access токенов"
        ),
        priority="medium",
    ),
    "Basic Auth": Recommendation(
        title="Избегайте Basic Auth в коде",
        description=(
            "Basic Auth credentials легко декодируются.\n"
            "• Используйте OAuth 2.0 или JWT\n"
            "• Если необходим Basic Auth — храните credentials в secrets manager"
        ),
        priority="medium",
    ),
    "Telegram Bot Token": Recommendation(
        title="Перенесите токен Telegram бота в переменные окружения",
        description=(
            "Токен бота позволяет управлять ботом от вашего имени.\n"
            "• Храните токен в переменных окружения\n"
            "• Отозовите и перегенерируйте токен через @BotFather"
        ),
        priority="medium",
    ),
    "Yandex Cloud OAuth": Recommendation(
        title="Отозовите Yandex OAuth токен",
        description=(
            "OAuth токен Яндекса дает доступ к инфраструктуре Yandex Cloud.\n"
            "• Немедленно удалите и отзовите токен в Yandex Passport\n"
            "• Для сервисов используйте сервисные аккаунты (Service Accounts)\n"
            "• Храните ключи в Yandex Lockbox"
        ),
        priority="high",
    ),
    "Yandex IAM Token": Recommendation(
        title="Удалите IAM токен Yandex Cloud",
        description=(
            "IAM токены имеют короткое время жизни (до 12 часов), но компрометация опасна.\n"
            "• Не хардкодьте IAM токены\n"
            "• Используйте SDK/CLI для автоматической генерации IAM токенов из авторизованных ключей"
        ),
        priority="high",
    ),
    "VK API Token": Recommendation(
        title="Отозовите токен доступа ВКонтакте",
        description=(
            "Утечка VK API Token может привести к рассылке спама или сливу данных из сообществ.\n"
            "• Сбросьте ключи доступа в настройках API вашего приложения/сообщества VK\n"
            "• Используйте переменные окружения для хранения ключей"
        ),
        priority="medium",
    ),
    "Google API Key": Recommendation(
        title="Ограничьте и перенесите Google API ключ",
        description=(
            "Google API ключи могут быть использованы для доступа к сервисам.\n"
            "• Настройте ограничения по HTTP referrer/IP\n"
            "• Используйте разные ключи для разных проектов\n"
            "• Храните в переменных окружения или Secrets Manager"
        ),
        priority="medium",
    ),
    "Generic Token": Recommendation(
        title="Перенесите токен в безопасное хранилище",
        description=(
            "Токены аутентификации не должны храниться в коде.\n"
            "• Используйте OAuth flow для получения токенов\n"
            "• Храните refresh tokens в encrypted storage"
        ),
        priority="medium",
    ),
    "SendGrid API Key": Recommendation(
        title="Перенесите SendGrid API ключ",
        description=(
            "SendGrid API ключ позволяет отправлять письма от вашего имени.\n"
            "• Храните ключ в переменных окружения\n"
            "• Настройте ограничения по IP\n"
            "• Регулярно ротируйте ключи"
        ),
        priority="medium",
    ),
    "default": Recommendation(
        title="Перенесите секретные данные в безопасное хранилище",
        description=(
            "Чувствительные данные не должны храниться в исходном коде.\n"
            "• Используйте переменные окружения\n"
            "• Примените менеджеры секретов (HashiCorp Vault, AWS Secrets Manager)\n"
            "• Настройте pre-commit хуки для предотвращения утечек"
        ),
        priority="medium",
    ),
}


def get_recommendation(secret_type: str) -> Recommendation:
    """Получить рекомендацию по типу секрета."""
    return RECOMMENDATIONS.get(secret_type, RECOMMENDATIONS["default"])


def generate_recommendations_report(findings: list) -> str:
    """Сгенерировать отчёт с рекомендациями по всем найденным утечкам."""
    if not findings:
        return "✅ Утечек не найдено. Рекомендации не требуются."

    # Группируем по типам секретов
    by_type = {}
    for finding in findings:
        if finding.secret_type not in by_type:
            by_type[finding.secret_type] = []
        by_type[finding.secret_type].append(finding)

    output = []
    output.append("=" * 70)
    output.append("📋 РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ УТЕЧЕК")
    output.append("=" * 70)
    output.append("")

    # Сортируем по приоритету
    priority_order = {"high": 0, "medium": 1, "low": 2}
    sorted_types = sorted(
        by_type.keys(),
        key=lambda t: (priority_order.get(get_recommendation(t).priority, 2), t),
    )

    for secret_type in sorted_types:
        rec = get_recommendation(secret_type)
        count = len(by_type[secret_type])
        
        priority_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(rec.priority, "⚪")
        
        output.append(f"{priority_emoji} [{rec.priority.upper()}] {secret_type}")
        output.append(f"   Найдено: {count} утечек")
        output.append("")
        output.append(f"   📌 {rec.title}")
        output.append("")
        
        for line in rec.description.split("\n"):
            output.append(f"   {line}")
        
        if rec.code_example:
            output.append("")
            output.append("   Пример кода:")
            for code_line in rec.code_example.split("\n"):
                output.append(f"   {code_line}")
        
        output.append("")
        output.append("-" * 70)
        output.append("")

    # Общие рекомендации
    output.append("📚 ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ")
    output.append("")
    output.append("1. 🔐 Используйте системы управления секретами:")
    output.append("   • HashiCorp Vault")
    output.append("   • AWS Secrets Manager")
    output.append("   • Azure Key Vault")
    output.append("   • Google Secret Manager")
    output.append("")
    output.append("2. 🛡️ Настройте pre-commit хуки:")
    output.append("   • git-secrets")
    output.append("   • detect-secrets")
    output.append("   • pre-commit с hook для сканирования секретов")
    output.append("")
    output.append("3. 🔄 Регулярно ротируйте секреты:")
    output.append("   • Установите политику ротации (30-90 дней)")
    output.append("   • Автоматизируйте процесс ротации")
    output.append("")
    output.append("4. 📝 Включите сканирование в CI/CD:")
    output.append("   • Запускайте nuclear-scan в pipeline")
    output.append("   • Блокируйте merge при находках HIGH/CRITICAL")
    output.append("")
    output.append("5. 🗑️ Если секреты уже в Git:")
    output.append("   • Используйте BFG Repo-Cleaner или git filter-branch")
    output.append("   • Отозовите все скомпрометированные ключи")
    output.append("   • Сгенерируйте новые credentials")
    output.append("")
    output.append("=" * 70)

    return "\n".join(output)
