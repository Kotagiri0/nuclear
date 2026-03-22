# Nuclear Secret Scanner — Полная логика проекта

> **Версия**: 0.2.0 | **Python**: ≥ 3.10  
> Дата актуализации: 2026-03-08

---

## Оглавление

1. [Что делает проект](#1-что-делает-проект)
2. [Структура файлов](#2-структура-файлов)
3. [Точки входа](#3-точки-входа)
4. [Конфигурация](#4-конфигурация-scannerconfigconfigpy)
5. [Ядро — паттерны](#5-ядро--паттерны)
6. [Ядро — анализ содержимого](#6-ядро--анализ-содержимого-scannercoreanalysispy)
7. [Ядро — физическое сканирование](#7-ядро--физическое-сканирование-scannercorescanning-py)
8. [Ядро — удалённые источники](#8-ядро--удалённые-источники-scannercoeinputspy)
9. [Ядро — единый runner](#9-ядро--единый-runner-scannercorerunnerpy)
10. [AI-модуль](#10-ai-модуль-scanneraisecuritypy)
11. [CLI](#11-cli-scannerclimapy)
12. [REPL](#12-repl-scannerrepl)
13. [Веб-сервер](#13-веб-сервер-scannerwebapppy)
14. [Форматирование отчётов](#14-форматирование-отчётов-scanneroutput)
15. [Тесты](#15-тесты)
16. [Схема потока данных](#16-схема-потока-данных)

---

## 1. Что делает проект

**Nuclear Secret Scanner** ищет утечки секретов — API-ключей, токенов, паролей, приватных ключей — в исходном коде. Поддерживает:

- Локальные файлы, директории, `.zip`-архивы
- Удалённые Git-репозитории и HTTP-URL
- Историю git-коммитов
- Опциональный LLM-анализ кода (NVIDIA API / Qwen)
- Три интерфейса: CLI, интерактивный REPL, REST HTTP API

---

## 2. Структура файлов

```
nuclear/
├── pyproject.toml                  # Метаданные пакета, entry_points
├── requirements.txt
│
├── scanner/                        # Главный пакет
│   ├── __init__.py
│   ├── __main__.py                 # python -m scanner → запуск REPL
│   │
│   ├── ai/
│   │   ├── __init__.py
│   │   └── security.py             # LLM-сканирование (NVIDIA Qwen)
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── __main__.py             # python -m scanner.cli
│   │   └── main.py                 # CLI argparse + main()
│   │
│   ├── config/
│   │   ├── __init__.py             # Re-export публичного API
│   │   ├── config.py               # NuclearConfig, load_config(), save_default_config()
│   │   └── dotenv.py               # Парсер .env файла
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── analysis.py             # Finding, TaintTrace, scan_content(), скоринг
│   │   ├── inputs.py               # scan_remote_source(), git clone, download
│   │   ├── patterns.py             # 500+ regex-паттернов (глобальные + RU) + вспомогательные наборы
│   │   ├── ru_patterns.py          # Устаревший файл с малым подмножеством RU-паттернов
│   │   ├── runner.py               # run_scan() — единый шлюз
│   │   └── scanning.py             # scan_file(), scan_directory(), scan_zip(), scan_git_history()
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   ├── html_report.py          # Самодостаточный HTML-отчёт
│   │   ├── pdf_report.py           # PDF через reportlab
│   │   ├── policy.py               # filter_by_min_severity(), should_fail()
│   │   ├── recommendations.py      # Рекомендации по устранению
│   │   └── reporting.py            # generate_report() → text / json / sarif
│   │
│   ├── repl/
│   │   ├── __init__.py             # run() — главный цикл REPL
│   │   ├── commands.py             # Обработчики команд: scan, set, config, help, history
│   │   ├── completer.py            # Контекстное автодополнение (prompt_toolkit)
│   │   └── ui.py                   # ASCII-баннер, таблицы, стили (rich)
│   │
│   └── web/
│       ├── __init__.py
│       ├── __main__.py             # python -m scanner.web
│       └── app.py                  # ThreadingHTTPServer + REST API + встроенный веб-UI
│
└── tests/
    ├── fix_entropy.py              # Утилита корректировки тестовых данных
    ├── update_test_secrets.py      # Обновление тестовых секретов
    ├── resources/
    │   ├── dir/corpus/             # Корпус тестовых проектов (clean + vuln, 10+ языков)
    │   └── fixtures/               # Фикстуры для unit-тестов
    ├── test_data/                  # Вспомогательные данные для отладки паттернов
    └── tests/                      # Pytest-тесты (17 файлов)
```

---

## 3. Точки входа

Определены в `pyproject.toml`:

| Команда | Модуль → функция | Описание |
|---------|-----------------|----------|
| `nuclear-scan <path>` | `scanner.cli.main:main` | Одноразовое CLI-сканирование |
| `nuclear` | `scanner.repl:run` | Интерактивный REPL |
| `nuclear-web` | `scanner.web.app:main` | HTTP/REST сервер |
| `python -m scanner` | `scanner.__main__` → `scanner.repl:run` | REPL через python -m |
| `python -m scanner.cli` | `scanner.cli.__main__` | CLI через python -m |
| `python -m scanner.web` | `scanner.web.__main__` | Веб через python -m |

---

## 4. Конфигурация (`scanner/config/config.py`)

### Файл конфигурации

Расположение: `~/.nuclear/config.toml` — создаётся автоматически при первом запуске через `save_default_config()`.

```toml
[defaults]
format   = "text"      # text | json | sarif | table
severity = "LOW"       # минимальный уровень вывода
fail_on  = "HIGH"      # CI-режим: exit 1 при нахождении >= этого уровня
history  = false       # сканировать историю git по умолчанию
commits  = 50          # лимит коммитов

[thresholds]
critical = 12          # порог score для CRITICAL
high     = 8           # порог score для HIGH
medium   = 5           # порог score для MEDIUM

[output]
file      = ""         # путь к файлу (пусто = stdout)
timestamp = false      # добавлять timestamp к имени файла

[ignore]
extra_ignore          = []  # дополнительные false-positive шаблоны
extra_skip_extensions = []  # дополнительные расширения для пропуска
extra_skip_dirs       = []  # дополнительные директории для пропуска

# [[patterns.custom]]       # пользовательские regex-паттерны
# name     = "Corp Token"
# regex    = "CORP_[A-Z0-9]{32}"
# score    = 8
# category = "api_key"
```

### Приоритет настроек (убывающий)

```
CLI-флаги  >  ENV-переменные  >  ~/.nuclear/config.toml  >  встроенные defaults
```

### ENV-переменные

| Переменная | Применение |
|-----------|-----------|
| `NUCLEAR_FORMAT` | Формат вывода |
| `NUCLEAR_SEVERITY` | Минимальный уровень |
| `NUCLEAR_FAIL_ON` | CI-порог |
| `NUCLEAR_HISTORY` | `1/true/yes` — включить историю |
| `NUCLEAR_COMMITS` | Число коммитов |
| `NUCLEAR_OUTPUT` | Путь к файлу отчёта |
| `NUCLEAR_NVIDIA_API_KEY` | API-ключ для LLM |

### `NuclearConfig` (dataclass)

```python
@dataclass
class NuclearConfig:
    format: str = "text"
    severity: str = "LOW"
    fail_on: str = "HIGH"
    history: bool = False
    commits: int = 50
    threshold_critical: int = 12
    threshold_high: int = 8
    threshold_medium: int = 5
    output_file: str = ""
    output_timestamp: bool = False
    extra_ignore: list[str] = []
    extra_skip_extensions: list[str] = []
    extra_skip_dirs: list[str] = []
    custom_patterns: list[CustomPattern] = []
```

### `dotenv.py` — `load_dotenv(path=".env")`

Перед загрузкой конфигурации читает `.env` из текущей директории. Поддерживает:
- Префикс `export KEY=VALUE`
- Одинарные и двойные кавычки
- Комментарии `#`
- Режим `override=False` — не перезаписывает уже установленные переменные

### TOML-загрузчик

Использует `tomllib` (встроен в Python 3.11+) с fallback на `tomli`. Пользовательские паттерны из `[[patterns.custom]]` валидируются regex-компиляцией перед добавлением.

### `set_config_value(key, value)`

Персистентное изменение одного ключа в TOML-файле с сохранением всех комментариев (строки читаются и модифицируются in-place).

---

## 5. Ядро — паттерны

### `scanner/core/patterns.py` — Главная база (500+ паттернов)

Основной словарь `PATTERNS`:
```python
PATTERNS = {
    "Secret Name": (r"regex_pattern", base_score, "category"),
    ...
}
```

**Покрываемые сервисы:**

| Группа | Сервисы |
|--------|---------|
| **Облако (глобальные)** | AWS (13 паттернов), Google Cloud/Firebase (10), Azure (9), Cloudflare (4), DigitalOcean (3), Heroku, Vercel, Netlify, Terraform, Pulumi |
| **VCS / CI** | GitHub (8), GitLab (3), npm, PyPI, Docker Hub, CircleCI, Travis CI, SonarQube, Codecov |
| **Коммуникации** | Slack (5), Discord (3), Zoom, WhatsApp, Telegram (4), Line, Teams |
| **Платежи** | Stripe (5), Twilio (4), PayPal, Square, Plaid, Razorpay |
| **Сервисы RU (в patterns.py)** | Yandex (14), VK (9), Cloud.ru (4), Sber (9), Tinkoff (7), Ozon (6), Wildberries (5), YooMoney/YooKassa (5), Avito (4), Mail.ru (7), Telegram (4) + ещё 80+ RU-сервисов |
| **AI/ML** | OpenAI, Anthropic, Hugging Face, Replicate, Stability AI, Cohere, AI21, AssemblyAI |
| **Аналитика** | Datadog, Sentry, New Relic, Splunk, LaunchDarkly |
| **Email / SMS** | Mailchimp, Brevo, SendGrid, Mailgun |
| **Инфраструктура** | Airtable, Postman, Notion, Asana, Mapbox, Algolia, Elastic, Auth0, Okta, Keycloak |
| **Базы данных** | PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ, Elasticsearch, Cassandra, MSSQL, Oracle |
| **Ключи и сертификаты** | RSA/EC/DSA/OpenSSH/PGP private keys, SSL/X509 certificates |
| **Токены** | JWT, Bearer, Basic Auth, OAuth Access/Refresh, Session, Auth |
| **Криптовалюта** | Bitcoin (key + address), Ethereum (key + address), Solana, BSC |
| **Общие** | Generic API Key, Secret, Token, Private Key, SSH Key, Connection String, env vars |

**Вспомогательные наборы в `patterns.py`:**

```python
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".idea", ".vscode", "vendor", "target", "out"}

SKIP_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
                   ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
                   ".zip", ".tar", ".gz", ".pdf", ".lock", ".sum",
                   ".exe", ".dll", ".so", ".bin"}

HIGH_ENTROPY_FILE_TYPES = {".env", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".toml"}

CONTEXT_KEYWORDS = ["api_key", "apikey", "secret", "password", "passwd",
                    "pwd", "token", "auth", "credential", "private_key",
                    "access_key", "client_secret", "app_secret", "api_secret",
                    "database_url", "connection_string"]

IGNORE_PATTERNS = ["example", "test", "fake", "dummy", "placeholder",
                   "xxxx", "1234", r"your[_\-]?\w*key", r"<[^>]+>",
                   r"\*{4,}", "TODO", "FIXME"]

HASH_PATTERNS = [r"^[a-f0-9]{32}$", r"^[a-f0-9]{40}$", r"^[a-f0-9]{64}$"]

SINK_NAMES = {
    r"\brequests\.(get|post|put|patch|delete|head)\b": "HTTP request",
    r"\bsubprocess\.(run|call|Popen|check_output)\b":  "Shell execution",
    r"\bos\.system\s*\(":                               "Shell execution",
    r"\beval\s*\(":                                     "Dynamic code execution",
    r"\bexec\s*\(":                                     "Dynamic code execution",
    r"\blogging\.(info|debug|warning|error|critical)\b": "Logging",
    r"\bprint\s*\(":                                    "Console output",
    r"\bopen\s*\(":                                     "File write",
    r"\bsocket\.":                                      "Raw socket",
    r"\bparamiko\.":                                    "SSH connection",
    r"\bboto3\.":                                       "AWS SDK call",
    r"\bpymongo\.":                                     "MongoDB query",
    r"\bpsycopg2\.":                                    "PostgreSQL query",
    r"\bsqlalchemy\.":                                  "Database query",
    # ... и др.
}

RU_SERVICES_PATTERNS = {...}  # set с именами всех RU-специфичных паттернов
```

### `scanner/core/ru_patterns.py` — Устаревший файл

Содержит малое подмножество RU-паттернов (Yandex Cloud, VK, Cloud.ru, Sber, Tinkoff, Ozon, Telegram + generic). Импортируется в `analysis.py` для обратной совместимости. Актуальные RU-паттерны полностью включены в `patterns.py`.

---

## 6. Ядро — анализ содержимого (`scanner/core/analysis.py`)

Главный файл алгоритмической логики. Импортирует паттерны из **обоих** файлов (`patterns.py` и `ru_patterns.py`).

### Структуры данных

```python
@dataclass
class Finding:
    file: str            # путь к файлу
    line_number: int     # номер строки (1-based)
    line_content: str    # полная строка
    secret_type: str     # название типа ("AWS Access Key", "GitHub Token"...)
    matched_value: str   # найденное значение (обрезается до 80 символов + "...")
    score: int           # итоговый балл (влияет на severity)
    severity: str        # LOW / MEDIUM / HIGH / CRITICAL
    category: str        # категория из паттерна (api_key, credential, jwt...)
    source: str          # "current" или "git:<sha>" для истории
    entropy: float       # энтропия Шеннона значения
    context_match: bool  # рядом есть контекстное ключевое слово
    structural_valid: bool  # прошла структурная валидация
    confidence: float    # итоговая уверенность [0.0..0.99]
    taint_traces: list   # список TaintTrace

@dataclass
class TaintTrace:
    source_variable: str  # переменная-источник
    source_file: str
    source_line: int
    sink_type: str         # тип опасного места (HTTP request, Shell execution...)
    sink_file: str
    sink_line: int
    sink_content: str      # строка с "вытеканием"
    steps: list[TaintStep] # промежуточные шаги распространения

@dataclass
class TaintStep:
    file: str
    line_number: int
    line_content: str
    variable: str
    action: str            # "propagated from <var>"
```

### Главная функция: `scan_content(content, filepath, source="current")`

Полный конвейер анализа одного файла:

#### Шаг 1 — Пропуск комментариев и пустых строк
```python
if not stripped or stripped.startswith("#") or stripped.startswith("//"):
    continue
```

#### Шаг 2 — Regex-матчинг по всем паттернам

Для каждой строки — итерация по всем паттернам из обоих словарей (`re.finditer`). Извлечение значения: если паттерн имеет capture-группу — берётся `match.group(1)`, иначе `match.group(0)`.

#### Шаг 3 — Фильтрация ложных срабатываний (`is_false_positive`)

```python
def is_false_positive(value: str) -> bool:
    # 1. Проверка на hash (MD5/SHA1/SHA256 — статичные шестнадцатеричные строки)
    for p in HASH_PATTERNS:
        if re.match(p, value, re.IGNORECASE):
            return True
    # 2. Слишком мало уникальных символов
    if len(set(value)) < 4:
        return True
    # 3. Совпадение с IGNORE_PATTERNS (example, test, fake, xxxx...)
    for p in IGNORE_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False
```

#### Шаг 4 — Скоринг (`_score_match`)

| Условие | Изменение score |
|---------|----------------|
| Базовый score паттерна | `base_score` |
| Значение похоже на хеш | `−3` |
| Энтропия Шеннона > 4.5 | `+3` |
| Энтропия Шеннона > 3.5 | `+1` |
| Контекстное ключевое слово рядом (±2 строки) | `+2` |
| Файл из `HIGH_ENTROPY_FILE_TYPES` (`.env`, `.yaml`...) | `+2` |
| Расширение `.env` | `+1` |
| Прошла структурная валидация | `+3` |
| Прошёл taint-анализ (добавляется позже) | `+2` |

**Пороги severity:**

| Score | Severity |
|-------|----------|
| ≥ 12 | `CRITICAL` |
| ≥ 8 | `HIGH` |
| ≥ 5 | `MEDIUM` |
| < 5 | `LOW` |

#### Шаг 5 — Структурная валидация (`validate_structure`)

Дополнительная проверка формата для конкретных типов:
- `JWT Token`: ровно 3 части, разделённые `.`
- `AWS Access Key`: строгий regex `^AKIA[0-9A-Z]{16}$`
- `Yandex Cloud Service Account Key`: `^AQ[A-Za-z0-9_-]{38,}$`
- `Private Key`: содержит `BEGIN` и `PRIVATE KEY`/`RSA`
- UUID-подобные типы (HubSpot, Ozon Client ID и др.): формат UUID
- `Connection String`: содержит `://` и `@`

#### Шаг 6 — Taint-анализ (`taint_analysis`)

Применяется для файлов с расширением `.py`, `.js`, `.ts`, `.rb`, `.go`, `.java`, `.php`.

**Алгоритм:**
1. Фиксируем переменные, содержащие секрет (`secret_vars` — список `(var_name, line_number)`)
2. Для каждой такой переменной создаём множество `tainted = {var_name}`
3. Линейный проход по всем строкам:
   - Если строка — присвоение (`lhs = rhs`) и в `rhs` есть `tainted`-переменная → добавляем `lhs` в `tainted`, записываем `TaintStep`
   - Если строка содержит паттерн из `SINK_NAMES` и в ней есть `tainted`-переменная → создаём `TaintTrace` (утечка найдена)
4. Если taint-след найден: `score += 2`, пересчёт severity

#### Шаг 7 — Расчёт confidence (`_confidence`)

```python
confidence = min(0.99, 0.15 + score / 16.0)
if entropy > 4.5:    confidence += 0.1
if struct_valid:     confidence += 0.15
if tainted:          confidence += 0.15
return round(min(confidence, 0.99), 2)
```

#### Шаг 8 — Применение taint и confidence ко всем findings

`_apply_taint_and_confidence()` — выполняется после сбора всех findings файла, связывает `TaintTrace` с соответствующими `Finding`.

---

## 7. Ядро — физическое сканирование (`scanner/core/scanning.py`)

### `scan_file(filepath, *, ai_security_cfg, ai_security_state)`

```
filepath
  │
  ├─ Проверка расширения в SKIP_EXTENSIONS → []
  ├─ Чтение UTF-8 (errors="ignore")
  ├─ scan_content() → findings
  │
  └─ Если ai_security_cfg:
       ├─ Пропустить dotfiles и расширения вне whitelist
       ├─ Если не scan_all_files → looks_risky_code_for_llm() → пропустить безопасные
       ├─ Если max_files > 0 → проверить счётчик ai_security_state["scanned"]
       └─ scan_code_security() → findings.extend(ai_findings)
```

**Whitelist расширений для AI:** `.py`, `.js`, `.ts`, `.tsx`, `.jsx`, `.java`, `.go`, `.rb`, `.php`, `.cs`, `.rs`, `.sh`, `.bash`, `.ps1`, `.sql`

### `scan_directory(root, on_file, *, ai_security_cfg, file_filter)`

```
os.walk(root)
  │
  ├─ dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]  ← прерывает рекурсию
  │
  └─ для каждого файла:
       ├─ file_filter(filepath) → пропустить если не совпадает
       ├─ on_file(filepath)     → callback для прогресса (подсчёт файлов в CLI)
       └─ scan_file(filepath, ai_security_cfg=..., ai_security_state=...)
```

Общий `ai_security_state = {"scanned": 0}` разделяется между всеми файлами директории — гарантирует соблюдение лимита `max_files` для всего прогона.

### `scan_zip(zip_path, *, ai_security_cfg, file_filter)`

```
ZipFile.namelist()
  │
  ├─ Фильтр: пропустить директории, SKIP_DIRS, SKIP_EXTENSIONS
  ├─ extractall() во временную директорию tempfile.mkdtemp()
  ├─ scan_directory() на распакованной директории
  └─ shutil.rmtree() в finally
```

### `scan_git_history(repo_path, max_commits)`

```
git log --format=%H -n max_commits
  │
  └─ для каждого SHA:
       git show <sha>
         │
         └─ Парсинг diff: строки начинающиеся с "+"
              └─ scan_content(added_lines, "git_history/<sha>", source="git:<sha>")
```

Найденные секреты имеют `source="git:<sha>"` — они отличаются от текущих файлов в отчётах.

---

## 8. Ядро — удалённые источники (`scanner/core/inputs.py`)

### `scan_remote_source(url, scan_history, history_commits, *, ai_security_cfg, file_filter)`

Определяет тип URL через `_looks_like_git_url()`:

```
URL
 │
 ├─ Git URL (git@..., *.git, github.com, локальный .git)?
 │    ├─ scan_history=False: git clone --depth 1 (shallow)
 │    ├─ scan_history=True:  git clone (полный)
 │    ├─ scan_directory() на клоне
 │    └─ scan_history → scan_git_history()
 │
 ├─ Заканчивается на .zip?
 │    ├─ urllib.request.urlopen() + запись во tmp
 │    └─ scan_zip()
 │
 └─ Иначе — одиночный файл:
      ├─ urllib.request.urlopen() + запись во tmp
      └─ scan_file()
```

Временные директории создаются через `tempfile.mkdtemp(prefix="secret_scanner_remote_")` и очищаются в `finally`.

---

## 9. Ядро — единый runner (`scanner/core/runner.py`)

### `run_scan(target, url, min_severity, scan_history, history_commits, exclude, include, ai_security_cfg, on_file)`

Единственная публичная точка запуска сканирования, используется CLI, REPL и Web API:

```python
def run_scan(...) -> list[Finding]:
    # 1. Валидация: ровно один из target/url
    if not target and not url:
        raise ValueError(...)
    if target and url:
        raise ValueError(...)

    # 2. Построение file_filter из glob-паттернов
    def _file_filter(filepath: str) -> bool:
        name = Path(filepath).name
        if include:
            if not any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(filepath, p) for p in include):
                return False
        if exclude:
            if any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(filepath, p) for p in exclude):
                return False
        return True

    # 3. Маршрутизация
    if url:
        findings, _, _ = scan_remote_source(url, ...)

    else:
        path = Path(target)
        if not path.exists():
            raise FileNotFoundError(...)

        if path.suffix.lower() == ".zip":
            findings = scan_zip(str(path), ...)
        elif path.is_dir():
            findings = scan_directory(str(path), ...)
            if scan_history and (path / ".git").exists():
                findings.extend(scan_git_history(str(path), ...))
        else:
            findings = scan_file(str(path), ...) if _file_filter(str(path)) else []

    # 4. Финальная фильтрация по glob (для findings из remote sources)
    if exclude or include:
        findings = [f for f in findings if _file_filter(f.file)]

    # 5. Фильтр по min_severity
    return filter_by_min_severity(findings, min_severity)
```

---

## 10. AI-модуль (`scanner/ai/security.py`)

Опциональный LLM-анализ кода. Требует `pip install nuclear-secret-scanner[ai]` (зависимость `openai`).

### `AISecurityConfig` (dataclass)

```python
@dataclass(frozen=True)
class AISecurityConfig:
    provider: str = "nvidia"
    base_url: str = "https://integrate.api.nvidia.com/v1"
    api_key_env: str = "NUCLEAR_NVIDIA_API_KEY"
    model: str | None = None        # None = автовыбор
    temperature: float = 0.1
    max_tokens: int = 500
    timeout_s: int = 30
    max_bytes: int = 50_000         # лимит файла для отправки
    scan_all_files: bool = False    # False = только "подозрительные" файлы
    max_files: int = 50             # 0 = без лимита
```

### Предфильтр `looks_risky_code_for_llm(content)`

Перед отправкой файла в LLM — быстрая проверка regex'ами на «опасные» паттерны:
- Выполнение кода: `os.system(`, `subprocess.run`, `eval(`, `exec(`
- Десериализация: `pickle.loads(`, `yaml.load(`
- Шаблоны: `render_template_string`, `Jinja2`
- SQL-инъекции: `SELECT .* + var`, `INSERT INTO .* + var`
- `shell=True`

Если ни один не совпал и `scan_all_files=False` — файл пропускается (экономия LLM-вызовов).

### `_pick_model(client, explicit_model)`

Если модель не указана явно:
1. Запрашивает `client.models.list()`
2. Фильтрует модели, содержащие `"qwen"` в ID
3. Приоритет: модель с `"122b"` в ID, иначе первая из списка
4. Кешируется в `_CACHED_MODEL` для повторного использования

### Системный промпт (на русском)

```
"Ты — лаконичный сканер безопасности кода. Твой ответ должен содержать ТОЛЬКО строки 
в формате: [УРОВЕНЬ УГРОЗЫ] - L<номер>: <строчка кода>.
Уровни: КРИТИЧЕСКАЯ, ВЫСОКАЯ, СРЕДНЯЯ, НИЗКАЯ.
Если строка безопасна, не упоминай её. Если весь код чист, пиши [БЕЗОПАСНО].
Не добавляй пояснений, заголовков и списков."
```

### `scan_code_security(code_text, *, filepath, cfg)`

```
1. Проверка size > max_bytes → []
2. _make_client(cfg) → openai.OpenAI(base_url=..., api_key=..., timeout=...)
3. _pick_model(client, cfg.model) → имя модели
4. Добавляем номера строк: "L1: ...\nL2: ..."
5. client.chat.completions.create(model, [system_prompt, user_content])
6. _parse_model_output(response):
   - "[БЕЗОПАСНО]" → []
   - "[УРОВЕНЬ] - L<n>: <text>" → парсинг
   - Маппинг RU→EN: КРИТИЧЕСКАЯ→CRITICAL, ВЫСОКАЯ→HIGH, СРЕДНЯЯ→MEDIUM, НИЗКАЯ→LOW
7. Создание Finding с:
   - secret_type = "AI Security"
   - category = "ai_security"
   - source = "ai:nvidia"
   - confidence = 0.55 (LOW/MEDIUM) или 0.7 (HIGH/CRITICAL)
```

---

## 11. CLI (`scanner/cli/main.py`)

### Аргументы (`build_parser()`)

| Аргумент | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `target` | positional? | — | Файл / директория / .zip |
| `--url` | str | — | Удалённый Git/HTTP/ZIP URL |
| `--format` | choice | из config | `text`/`json`/`sarif`/`html`/`pdf` |
| `--min-severity` | choice | из config | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` |
| `--fail-on` | choice | из config | CI-порог (exit 1) |
| `--scan-history` | flag | False | Сканировать git-историю |
| `--history-commits` | int | 50 | Лимит коммитов |
| `--output` | path | stdout | Файл для отчёта |
| `--exclude` | append | [] | Glob-паттерны исключений |
| `--include` | append | [] | Glob-паттерны включений |
| `-q`/`--quiet` | flag | False | Тихий режим |
| `-v`/`--verbose` | flag | False | Время + количество файлов |
| `--recommendations` | flag | False | Добавить рекомендации |
| `--ai-security` | flag | False | Включить LLM-анализ |
| `--ai-provider` | choice | `nvidia` | Провайдер AI |
| `--ai-model` | str | None | Имя модели (авто если не указано) |
| `--ai-base-url` | str | NVIDIA URL | Base URL для API |
| `--ai-timeout` | int | 30 | Таймаут запроса (сек) |
| `--ai-max-bytes` | int | 50000 | Лимит размера файла для AI |
| `--ai-max-tokens` | int | 500 | Лимит токенов ответа |
| `--ai-max-files` | int | 50 | Лимит LLM-запросов (0=без лимита) |
| `--ai-scan-all` | flag | False | LLM для всех файлов |

### Поток выполнения `main()`

```
1. sys.stdout.reconfigure(encoding="utf-8")  ← Unicode на Windows
2. load_dotenv()
3. load_config()  →  NuclearConfig
4. build_parser(cfg)  →  args
5. Если не target и не url → parser.error()

6. Если --ai-security:
     ai_security_cfg = AISecurityConfig(...)

7. run_scan(target, url, min_severity, scan_history, ...) → findings
   ├─ FileNotFoundError → stderr + exit(1)
   └─ Exception → stderr + exit(1)

8. elapsed = time.monotonic() - start_time

9. Форматирование:
   ├─ html → save_html_report() → print(path)
   ├─ pdf  → save_pdf_report() → print(path)
   └─ иначе → generate_report(findings, format)
              ├─ --output → запись в файл
              └─ иначе → print()

10. --recommendations → generate_recommendations_report() → print()
11. --verbose → elapsed + file_count

12. should_fail(findings, args.fail_on) → sys.exit(1)
```

---

## 12. REPL (`scanner/repl/`)

### `__init__.py` — Главный цикл `run()`

```
1. load_dotenv()
2. _build_state() из load_config()
3. banner()  ← ASCII-арт NUCLEAR + подсказки
4. NuclearCompleter() + FileHistory(~/.nuclear/history)
5. PromptSession(history, auto_suggest, completer, style)

Цикл:
  session.prompt("☢ nuclear > ")
    ├─ KeyboardInterrupt (двойной Ctrl+C ≤2 сек) → session_summary() + break
    ├─ EOFError → break
    ├─ "" (пустой ввод) → continue
    └─ shlex.split(raw) → dispatch:

        "scan"    → cmd_scan(rest, state)
        "set"     → cmd_set(tokens, state)
        "config"  → cmd_config(tokens, state)
        "status"  → status_table(state)
        "history" → cmd_history(state)
        "clear"   → console.clear() + banner()
        "help"    → cmd_help(tokens)
        "exit/quit" → break
        иначе     → "Unknown command"
```

**Состояние сессии (`state`):**
```python
{
    "format":        "table",   # текущий формат вывода
    "severity":      "LOW",     # минимальный уровень
    "fail_on":       "HIGH",    # CI-порог
    "history":       False,     # сканировать историю
    "commits":       50,        # лимит коммитов
    "cmd_history":   [],        # список введённых команд
    "scan_count":    0,         # число сканирований за сессию
    "total_findings": 0,        # суммарные findings за сессию
}
```

### `commands.py` — Обработчики

#### `cmd_scan(rest, state)`
1. `parse_scan_args(tokens)` → `(target, url, extra_opts)`
2. `run_scan(...)` в `console.status("[cyan]Scanning…[/cyan]")`
3. Всегда сохраняет HTML-отчёт через `save_html_report()`
4. Вывод в зависимости от формата: `findings_table()`, JSON, SARIF, text
5. Обновление счётчиков `state["scan_count"]`, `state["total_findings"]`
6. CI-проверка: `should_fail()` → предупреждение

#### `cmd_set(tokens, state)`
Изменяет настройки текущей сессии (не персистентно):
`format`, `severity`, `fail-on`, `history`, `commits`

#### `cmd_config(tokens, state)`
| Подкоманда | Действие |
|-----------|---------|
| `show` | Rich-таблица всех настроек из `~/.nuclear/config.toml` |
| `path` | Путь к файлу конфига |
| `init` | Создать конфиг-файл с дефолтами |
| `set <key> <val>` | `set_config_value()` — персистентное изменение |

#### `cmd_history(state)`
Печатает все команды текущей сессии с нумерацией.

### `completer.py` — `NuclearCompleter`

Контекстное автодополнение через `prompt_toolkit.Completer`:
- Первое слово → команды из `COMMANDS`
- После `scan` → флаги из `SCAN_ARGS` + пути файловой системы (через `os.listdir`)
- После `--format`/`-f` → значения: `table`, `json`, `sarif`, `text`
- После `--severity`/`-s` → `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- После `set` → ключи из `SET_KEYS`
- После `set <key>` → значения для конкретного ключа
- После `config` → подкоманды из `CONFIG_SUBS`
- После `help` → список всех команд

### `ui.py` — UI-компоненты

```python
banner()           # ASCII-логотип NUCLEAR + подсказки (rich Panel)
findings_table()   # Rich Table с цветными severity-бейджами
session_summary()  # Итоги сессии: commands, scans, findings
status_table()     # Текущие настройки формата/severity/history
```

**Цветовая схема:**
- `CRITICAL`: `#ff4444` / badge `[bold white on #cc0000]`
- `HIGH`: `#ff8c00` / badge `[bold white on #cc5500]`
- `MEDIUM`: `#ffd700` / badge `[bold black on #e6b800]`
- `LOW`: `#6ec1e4` / badge `[bold white on #336699]`

---

## 13. Веб-сервер (`scanner/web/app.py`)

`ThreadingHTTPServer` (без внешних фреймворков) с встроенным одностраничным веб-UI.

### Конфигурация сервера

```python
MAX_HISTORY_COMMITS = 5_000   # абсолютный лимит коммитов через API
MAX_BODY_BYTES      = 1_000_000  # лимит тела POST-запроса
```

### Endpoints

#### `GET /` — Веб-интерфейс

Возвращает полноценный одностраничный HTML (встроен прямо в `app.py`). UI включает:
- Форму с полями: target/URL, min_severity, scan_history, history_commits, exclude, include, ai_security, recommendations
- Отображение результатов: сводка по severity + таблица findings
- Фильтрация по severity на клиенте (JavaScript)
- Кнопки скачивания HTML/PDF отчётов
- Дизайн: светлая тема с teal-акцентом, radial-gradient фон

#### `POST /scan` — API сканирования

```json
// Request body
{
  "target": "/path/or/.",
  "url": "https://github.com/...",
  "min_severity": "LOW",
  "scan_history": false,
  "history_commits": 50,
  "exclude": ["*.test.js"],
  "include": ["*.py"],
  "ai_security": false,
  "recommendations": false
}

// Response
{
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "type": "AWS Access Key",
      "severity": "HIGH",
      "score": 11,
      "confidence": 0.83,
      "category": "api_key",
      "value": "AKIA...",
      "line_content": "AWS_KEY = 'AKIA...'",
      "ai_detection": false,
      "detector": "patterns",
      "recommendation": {  // только если recommendations=true
        "title": "...",
        "description": "...",
        "priority": "high"
      }
    }
  ],
  "summary": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 5},
  "total": 9,
  "elapsed_ms": 342
}
```

#### `GET /scan?target=...&min_severity=...` — GET-версия

Параметры query string аналогичны JSON-телу POST. Используется из веб-UI.

#### `GET /report/html` — HTML-отчёт

Принимает те же параметры что `/scan`, возвращает `Content-Type: text/html` — полный самодостаточный HTML-файл.

#### `GET /report/pdf` — PDF-отчёт

Аналогично, возвращает `Content-Type: application/pdf`.

#### `GET /health` — Health check

```json
{"status": "ok"}
```

### Валидация запросов (`_parse_scan_request`)

- `min_severity` — должен быть в `ALLOWED_SEVERITIES`
- `history_commits` — целое число в `[1..MAX_HISTORY_COMMITS]`
- `scan_history`, `ai_security`, `recommendations` — булевы (строки `"1"/"true"/"yes"` тоже принимаются)
- `exclude`/`include` — строка или список непустых строк
- Конфликт `target + url` — разрешается: если target == `"."` или совпадает с default_target, то `target = None`

### `main(args)` — запуск сервера

```python
def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--target", default=".")
    ...
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()
```

---

## 14. Форматирование отчётов (`scanner/output/`)

### `policy.py`

```python
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def filter_by_min_severity(findings, min_severity) -> list:
    min_level = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]

def should_fail(findings, fail_on) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)
```

### `reporting.py` — `generate_report(findings, output_format)`

1. `deduplicate(findings)` — по ключу `(file, line, type, value, source)`
2. Сортировка: `(-score, file, line_number)`
3. Маршрутизация:
   - `"json"` → `_json_report()`
   - `"sarif"` → `_sarif_report()`
   - иначе → `_text_report()`

#### Формат `json`
Полная сериализация: все поля Finding + taint_traces (включая шаги), `ai_detection: bool`, `detector: "patterns"/"llm"`.

#### Формат `sarif`
SARIF 2.1.0 с:
- `tool.driver.rules[]` — уникальные правила (одно на тип секрета)
- `results[]` — каждый finding с `level: "error"` (HIGH/CRITICAL) или `"warning"`
- `physicalLocation` → `artifactLocation.uri` + `region.startLine`
- Тег `[LLM]` в сообщении для AI-findings

#### Формат `text` (ANSI)
Цветной вывод с:
- Заголовком `[SEVERITY] type (category)`
- File, Value (обрезается до 60 символов), Score, Entropy, Confidence
- Source, флаги (`context✓`, `structure✓`, `taint:N✓`)
- Taint-трейсы: `source → sink` с цепочкой шагов
- Итоговый summary по уровням
- Предупреждение о tainted findings
- Счётчик AI/LLM findings

### `html_report.py`

`generate_html_report(findings, target)` → самодостаточный HTML-файл (встроенный CSS + JS):
- Сводная статистика по severity (цветные плитки)
- Таблица с кликабельными строками (раскрытие деталей)
- Детали: entropy, category, source, taint traces
- AI/LLM findings отмечаются иконкой `🤖 ML`
- Фильтрация по severity на клиенте (JavaScript)

`save_html_report(findings, target)` → сохраняет в `.nuclear-scan-result/scan_{timestamp}.html`

### `pdf_report.py`

Использует `reportlab`. Содержимое:
- Заголовок: "Nuclear Secret Scanner Report"
- Цель сканирования, дата, число findings
- Таблица severity-сводки
- Таблица findings: file, line, type, severity, score

`save_pdf_report(findings, target, output_path)` → сохраняет в указанный путь или `.nuclear-scan-result/`.

### `recommendations.py`

```python
@dataclass
class Recommendation:
    title: str
    description: str
    code_example: Optional[str] = None
    priority: str = "high"  # high | medium | low
```

Словарь `RECOMMENDATIONS` содержит рекомендации для всех основных типов секретов (AWS, GitHub, Stripe, Private Key и т.д.) с примерами кода `✅ правильно` / `❌ неправильно`.

`get_recommendation(secret_type)` → возвращает `Recommendation` или generic-рекомендацию если тип не найден.

`generate_recommendations_report(findings)` → форматированный текст для вывода в CLI с `--recommendations`.

---

## 15. Тесты (`tests/tests/`)

| Файл | Что проверяет |
|------|--------------|
| `test_scanner.py` | Базовое сканирование файлов, smoke-тесты |
| `test_scanning.py` | `scan_file()`, `scan_directory()`, `scan_zip()`, `scan_git_history()` |
| `test_analysis_branches.py` | Все ветви скоринга, taint-анализ, confidence, edge cases |
| `test_patterns_direct.py` | Regex-паттерны напрямую: must-match + must-not-match |
| `test_corpus.py` | Корпус проектов clean vs vuln (C#, Go, Java, JS, PHP, mixed) |
| `test_cli_integration.py` | CLI через `subprocess.run` — форматы, флаги, exit codes |
| `test_web_api.py` | Все REST-endpoints: `/scan`, `/report/html`, `/report/pdf`, `/health` |
| `test_web_extended.py` | Edge cases: параметры, ошибки, большие запросы |
| `test_ai_security.py` | LLM-модуль с mock OpenAI: парсинг, confidence, ошибки |
| `test_config.py` | NuclearConfig: приоритеты, ENV-переменные, TOML, custom patterns |
| `test_reporting_full.py` | Все форматы отчётов (text, json, sarif, html, pdf) |
| `test_recommendations.py` | Рекомендации для всех типов секретов |
| `test_inputs.py` | scan_remote_source(): mock git clone, download, zip |
| `test_runner.py` | run_scan(): маршрутизация, фильтры, ошибки |
| `test_url_and_history.py` | URL-сканирование + git-история |
| `test_pdf_report.py` | PDF-генератор, reportlab |
| `test_extended.py` | Расширенные edge-cases: unicode, большие файлы, пустые директории |

### Корпус (`tests/resources/dir/corpus/`)

Набор проектов для проверки precision/recall:

| Проект | Тип |
|--------|-----|
| `csharp_clean` / `csharp_vuln` | C# |
| `go_clean_small` / `go_vuln_small` | Go |
| `java_clean_small` / `java_vuln_small` | Java |
| `js_clean_small` / `js_vuln_small` | JavaScript |
| `php_clean_nested` / `php_vuln_nested` | PHP с вложенной структурой |
| `mixed_clean_large` / `mixed_vuln_large` | Смешанный большой проект |

---

## 16. Схема потока данных

```
┌──────────────────────────────────────────────────────────┐
│                    ИСТОЧНИК ДАННЫХ                        │
│  Файл / Директория / ZIP / Git URL / HTTP URL            │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│              inputs.py / scanning.py                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  scan_file  │  │ scan_directory│  │    scan_zip    │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                │                   │           │
│         └────────────────┴───────────────────┘           │
│                          │                               │
│                    scan_git_history                       │
│               (для URL/dir с .git + --history)           │
└─────────────────────────┬────────────────────────────────┘
                          │  content + filepath
                          ▼
┌──────────────────────────────────────────────────────────┐
│                   analysis.py                             │
│                                                          │
│  scan_content(content, filepath)                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │  1. Пропуск комментариев и пустых строк            │  │
│  │  2. Regex-матчинг (patterns.py + ru_patterns.py)  │  │
│  │  3. is_false_positive() — хеши, плейсхолдеры     │  │
│  │  4. _score_match() — entropy, context, structure  │  │
│  │  5. score → severity (LOW/MEDIUM/HIGH/CRITICAL)   │  │
│  │  6. taint_analysis() — цепочки утечки             │  │
│  │  7. _confidence() — итоговая уверенность          │  │
│  └────────────────────────────────────────────────────┘  │
│                          │                               │
│                   list[Finding]                           │
└─────────────────────────┬────────────────────────────────┘
                          │ (опционально)
                          ▼
┌──────────────────────────────────────────────────────────┐
│               ai/security.py                              │
│  looks_risky_code_for_llm() → предфильтр                 │
│  scan_code_security() → NVIDIA API (Qwen)                │
│  Парсинг: [УРОВЕНЬ] - L<n>: <код>                        │
│  → Finding(secret_type="AI Security", source="ai:nvidia")│
└─────────────────────────┬────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                  runner.py                                │
│  run_scan() — маршрутизация + filter_by_min_severity()   │
└────────┬────────────────┬──────────────────┬─────────────┘
         │                │                  │
         ▼                ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
│  CLI         │  │  REPL        │  │  Web API         │
│  cli/main.py │  │  repl/...    │  │  web/app.py      │
└──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
       │                 │                    │
       └─────────────────┴────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│                  output/                                  │
│  ┌──────────────┐  ┌────────┐  ┌──────┐  ┌───────────┐  │
│  │  reporting   │  │  html  │  │  pdf │  │   recs    │  │
│  │ text/json/   │  │ report │  │report│  │ recommends│  │
│  │ sarif        │  │        │  │      │  │           │  │
│  └──────────────┘  └────────┘  └──────┘  └───────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## Зависимости

| Пакет | Назначение | Обязательный |
|-------|-----------|-------------|
| `rich >= 13.7` | Цветной вывод, таблицы, панели (CLI + REPL) | ✅ |
| `prompt_toolkit >= 3.0.43` | Интерактивный ввод, автодополнение (REPL) | ✅ |
| `typer[all] >= 0.12` | Опциональный helper (объявлен в deps) | ✅ |
| `reportlab` | Генерация PDF | ✅ |
| `openai >= 1.40` | LLM AI-сканирование | ❌ (extra `[ai]`) |
| `tomllib` / `tomli` | Парсинг TOML (tomllib встроен в Python 3.11+) | auto |
