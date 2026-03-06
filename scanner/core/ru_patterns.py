# Паттерны для поиска секретов российских сервисов
# Поддерживаемые сервисы: Yandex Cloud, VK, Cloud.ru, Sber, Tinkoff, Ozon, Telegram

PATTERNS = {
    # ==================== YANDEX CLOUD ====================
    "Yandex Cloud OAuth Token": (r"\bt1\.[A-Za-z0-9_-]{128,}\b", 9, "oauth_token"),
    "Yandex Cloud IAM Token": (r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.t1\.[A-Za-z0-9_-]{64,}\b", 9, "iam_token"),
    "Yandex Cloud Service Account Key": (r"\bAQ[A-Za-z0-9_-]{38,}\b", 8, "service_account_key"),
    
    # ==================== VK (ВКонтакте) ====================
    "VK API Access Token": (r"\bvk[a-z0-9]{10,}[A-Za-z0-9_-]{10,}\b", 7, "api_token"),
    "VK API User Token": (r"(?i)vk_token\s*[=:]\s*['\"]?[a-f0-9]{40}['\"]?", 6, "user_token"),
    "VK API Service Token": (r"(?i)vk_api\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "service_token"),
    
    # ==================== CLOUD.RU ====================
    "Cloud.ru API Token": (r"\bcrp_[a-zA-Z0-9_-]{32,}\b", 8, "api_token"),
    "Cloud.ru Service Account": (r"\bcrsa_[a-zA-Z0-9_-]{32,}\b", 8, "service_account"),
    
    # ==================== SBER (Сбер) ====================
    "Sber ID Token": (r"\bsber_[a-zA-Z0-9_-]{24,}\b", 7, "oauth_token"),
    "Sber API Key": (r"(?i)sber[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "api_key"),
    
    # ==================== TINKOFF (Тинькофф) ====================
    "Tinkoff API Token": (r"\btinkoff_[a-zA-Z0-9_-]{28,}\b", 8, "api_token"),
    "Tinkoff Merchant Token": (r"\bmerchant_[a-zA-Z0-9_-]{32,}\b", 8, "merchant_token"),
    
    # ==================== OZON ====================
    "Ozon API Key": (r"(?i)api-key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{28,}['\"]?", 8, "api_key"),
    "Ozon Client ID": (r"(?i)client[_-]?id\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?", 6, "client_id"),
    
    # ==================== TELEGRAM ====================
    "Telegram Bot Token": (r"\b\d{8,10}:[A-Za-z0-9_-]{33,}\b", 8, "bot_token"),
    
    # ==================== ОБЩИЕ ПАТТЕРНЫ ====================
    "Generic API Key": (r"(?i)api[_\-\s]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", 5, "api_key"),
    "Generic Secret": (r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", 5, "credential"),
    "Generic Token": (r"(?i)token\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]", 4, "api_token"),
    "Connection String": (
        r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        8,
        "db_credential",
    ),
    "Private Key": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 10, "private_key"),
    "JWT Token": (r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b", 7, "jwt"),
}

CONTEXT_KEYWORDS = [
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "auth",
    "credential",
    "private_key",
    "access_key",
    "client_secret",
    "app_secret",
    "api_secret",
    "database_url",
    "connection_string",
    "yandex",
    "vk",
    "sber",
    "tinkoff",
    "ozon",
    "cloudru",
    "telegram",
]

IGNORE_PATTERNS = [
    r"example",
    r"test",
    r"fake",
    r"dummy",
    r"placeholder",
    r"xxxx",
    r"1234",
    r"your[_\-]?\w*key",
    r"<[^>]+>",
    r"\*{4,}",
    r"TODO",
    r"FIXME",
]

HASH_PATTERNS = [
    r"^[a-f0-9]{32}$",
    r"^[a-f0-9]{40}$",
    r"^[a-f0-9]{64}$",
]

SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".lock",
    ".sum",
    ".exe",
    ".dll",
    ".so",
    ".bin",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "vendor",
    "target",
    "out",
}

HIGH_ENTROPY_FILE_TYPES = {".env", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".toml"}

SINK_NAMES = {
    r"\brequests\.(get|post|put|patch|delete|head)\b": "HTTP request",
    r"\burllib\.request\.": "HTTP request",
    r"\bhttpx\.(get|post|put|patch|delete)\b": "HTTP request",
    r"\baiohttp\.": "HTTP request",
    r"\bsmtplib\.": "Email sending",
    r"\blogging\.(info|debug|warning|error|critical)\b": "Logging",
    r"\bprint\s*\(": "Console output",
    r"\bopen\s*\(": "File write",
    r"\bsubprocess\.(run|call|Popen|check_output)\b": "Shell execution",
    r"\bos\.system\s*\(": "Shell execution",
    r"\bsocket\.": "Raw socket",
    r"\bparamiko\.": "SSH connection",
    r"\bpysftp\.": "SFTP connection",
    r"\bboto3\.": "AWS SDK call",
    r"\bpymongo\.": "MongoDB query",
    r"\bpsycopg2\.": "PostgreSQL query",
    r"\bsqlalchemy\.": "Database query",
    r"\bsequelize\.": "Database query",
    r"\bexec\s*\(": "Dynamic code execution",
}
