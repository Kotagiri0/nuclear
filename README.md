# 🔍 Secret Scanner

Инструмент статического анализа для поиска утечек секретов в исходном коде. Находит API-ключи, токены, пароли и другие чувствительные данные — и показывает, куда они утекают в коде.

---

## Возможности

### 🎯 Четыре слоя детекции

**Pattern-based** — 24 сигнатуры для популярных провайдеров:
AWS, GitHub, Stripe, Google, Telegram, SendGrid, Slack, Twilio, Mailgun, JWT, RSA-ключи и generic-паттерны для паролей, токенов и API-ключей.

**Entropy-based** — вычисление энтропии Шеннона для каждой строки. Случайные символы (как настоящие ключи) имеют высокую энтропию — это поднимает итоговый score.

**Context-based** — анализ окружения строки. Если рядом есть слова `api_key`, `secret`, `password`, `token` — вероятность утечки выше.

**Structural validation** — проверка структуры токена: у JWT ровно 3 части base64, AWS-ключ строго 20 символов с префиксом `AKIA`, RSA-ключ имеет заголовок `BEGIN/END`.

---

### 🔗 Taint-трекинг (semi-SAST)

Инструмент не просто находит секрет — он отслеживает его путь по коду рекурсивно через цепочку присваиваний до опасного вызова.

```
AWS_KEY = "AKIA..."                    ← источник
    ↓ propagated from AWS_KEY
headers = {"X-Api-Key": AWS_KEY}       ← промежуточный шаг
    ↓ propagated from headers
requests.get(url, headers=headers)     ← 💥 HTTP request (sink)
```

Поддерживаемые типы sink-ов: HTTP-запросы (`requests`, `httpx`, `aiohttp`, `urllib`), логирование (`logging`, `print`), файловый ввод-вывод (`open`), shell-команды (`subprocess`, `os.system`), сетевые соединения (`socket`, `paramiko`, `pysftp`), облачные SDK (`boto3`), базы данных (`psycopg2`, `pymongo`, `sqlalchemy`).

---

### 📦 Поддержка ZIP-архивов

Можно подать на вход `.zip`-архив — инструмент сам распакует его, просканирует все файлы и сообщит о находках с сохранением внутренней структуры путей.

```bash
python main.py project.zip
```

---

### 📊 Scoring и приоритизация

Каждая находка получает числовой score по совокупности факторов:

| Критерий | Бонус |
|---|---|
| Regex совпадение | базовый score паттерна |
| Энтропия > 4.5 | +3 |
| Энтропия > 3.5 | +1 |
| Контекстные слова рядом | +2 |
| Файл `.env` / конфигурационный | +2–3 |
| Валидная структура токена | +3 |
| Taint-трейс найден | +2 |
| Похоже на хэш (MD5/SHA) | −3 |

Итоговая классификация:

| Score | Severity |
|---|---|
| 12+ | 🔴 CRITICAL |
| 8–11 | 🟠 HIGH |
| 5–7 | 🟡 MEDIUM |
| < 5 | 🔵 LOW |

---

### 🚫 Фильтрация ложных срабатываний

Автоматически понижается приоритет строк, которые содержат `example`, `test`, `fake`, `dummy`, `placeholder`, `xxxx` или повторяющиеся символы, выглядят как хэш (MD5, SHA1, SHA256 по длине и алфавиту), или находятся в комментариях (`#`, `//`).

---

## Установка

```bash
git clone https://github.com/yourname/secret-scanner
cd secret-scanner
pip install -r requirements.txt
```

Требования: Python 3.10+. Зависимости только для тестов — сам сканер использует исключительно стандартную библиотеку.

---

## Использование

```bash
# Сканировать директорию
python main.py ./my_project

# Сканировать ZIP-архив
python main.py my_project.zip

# Сканировать один файл
python main.py config.env

# Только HIGH и CRITICAL
python main.py ./my_project --min-severity HIGH

# Вывод в JSON
python main.py ./my_project --format json > report.json
```

---

## Пример вывода

```
🔍 Secret Scanner Report
Found 3 potential secret(s)

======================================================================
[CRITICAL] AWS Access Key
  📁 File   : api_client.py:4
  🔑 Value  : AKIAJX7LKQHMBQWRFP2A
  📊 Score  : 17 | Entropy: 3.88
  🏷  Flags  : context✓, structure✓, taint:2✓
  📝 Line   : AWS_KEY = "AKIAJX7LKQHMBQWRFP2A"
  ──────────────────────────────────────────────────
  🔗 Taint trace: AWS_KEY → HTTP request
     📍 Source : api_client.py:4
     ↓  api_client.py:8  [propagated from AWS_KEY]
        headers = {"X-Api-Key": AWS_KEY}
     💥 Sink   : api_client.py:9  [HTTP request]
        requests.get("https://api.internal.com/users/", headers=headers)
----------------------------------------------------------------------

Summary:
  CRITICAL: 2
  HIGH: 1

  ⚠  Secrets actively used in dangerous sinks: 2
```

---

## Тесты

```bash
pytest test_scanner.py -v
```

73 теста покрывают все слои детекции, taint-трекинг, zip-сканирование и генерацию отчётов.

---

## Архитектура

```
Входной путь (файл / директория / .zip)
        ↓
    scan_content()
        ├── regex-паттерны       → базовый score
        ├── Shannon entropy      → +score если высокая
        ├── context keywords     → +score если есть
        ├── structural validate  → +score если структура верна
        └── taint_analysis()     → отслеживание до sink + +score
        ↓
    scoring engine
        ↓
    severity classification
        ↓
    generate_report() → text / JSON
```

---

## Поддерживаемые форматы

Сканируются все текстовые файлы. Автоматически пропускаются изображения, шрифты, медиа, архивы, бинарники, `.lock`-файлы, а также директории `node_modules`, `.git`, `__pycache__`, `venv`, `dist`, `build`.

---

## Exit codes

| Код | Значение |
|---|---|
| `0` | Секретов не найдено (или все ниже порога) |
| `1` | Найдены находки уровня HIGH или CRITICAL |

Удобно для CI/CD:

```yaml
# GitHub Actions
- name: Scan for secrets
  run: python main.py . --min-severity HIGH
```
