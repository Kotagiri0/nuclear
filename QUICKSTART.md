# ⚡ Быстрый старт — Nuclear Secret Scanner

## Установка

```bash
pip install -r requirements.txt
pip install -e .
```

## Демонстрация за 1 минуту

### 1️⃣ Запустить сканирование демо-проекта
```bash
nuclear-scan demo_project --verbose
```

### 2️⃣ Получить отчёт с рекомендациями
```bash
nuclear-scan demo_project --recommendations --min-severity HIGH
```

### 3️⃣ Сгенерировать HTML отчёт
```bash
nuclear-scan demo_project --format html
# Отчёт: .nuclear-scan-result/index.html
```

### 4️⃣ Проверить exit code для CI/CD
```bash
nuclear-scan demo_project --fail-on HIGH --quiet
echo Exit code: %ERRORLEVEL%  # Windows
echo Exit code: $?            # Linux/Mac
```

## Основные команды

| Команда | Описание |
|---------|----------|
| `nuclear-scan <path>` | Базовое сканирование |
| `nuclear-scan <path> --recommendations` | С рекомендациями |
| `nuclear-scan <path> --format json` | JSON отчёт |
| `nuclear-scan <path> --format html` | HTML отчёт |
| `nuclear-scan <path> --format sarif` | SARIF для GitHub |
| `nuclear-scan <path> --min-severity HIGH` | Только HIGH/CRITICAL |
| `nuclear-scan <path> --fail-on HIGH` | Exit code 1 если HIGH+ |
| `nuclear-scan --url <git-url>` | Сканировать Git репозиторий |
| `nuclear-scan --url <zip-url>` | Сканировать ZIP архив |
| `nuclear-scan . --scan-history` | Сканировать историю Git |

## Что находит сканер

### 🔴 CRITICAL (Score 12-18)
- Приватные ключи (RSA, EC, OPENSSH)
- AWS Access/Secret Keys
- GitHub токены
- Stripe Secret Keys
- JWT токены
- Connection strings к БД

### 🟠 HIGH (Score 8-11)
- Bearer токены
- Basic Auth credentials
- Generic secrets/passwords

### 🟡 MEDIUM (Score 5-7)
- Generic API keys
- Google API keys
- Telegram bot tokens

### 🟢 LOW (Score <5)
- Потенциальные ложные срабатывания

## Примеры использования

### Для разработчиков
```bash
# Проверить свой код перед коммитом
nuclear-scan src/ --recommendations

# Проверить .env файл
nuclear-scan .env
```

### Для CI/CD
```bash
# В pipeline (GitHub Actions, GitLab CI)
nuclear-scan . --fail-on HIGH --format sarif > results.sarif
```

### Для аудита
```bash
# Полный аудит проекта
nuclear-scan /path/to/project --format json --output audit.json --verbose

# С историей коммитов
nuclear-scan --url https://github.com/org/repo.git --scan-history --history-commits 100
```

## Интерпретация результатов

```
[CRITICAL] Private Key
  📁 File   : src/config.py:15      # Файл и строка
  🔑 Value  : -----BEGIN RSA...     # Найденное значение (обрезано)
  📊 Score  : 18                    # Оценка 0-18
  📈 Entropy: 3.38                  # Энтропия Шеннона
  🎯 Confidence: 0.99               # Уверенность 0-1
  🏷  Flags  : context✓, structure✓ # Флаги анализа
  📝 Line   : PRIVATE_KEY = "..."   # Строка кода
```

## Рекомендации

После обнаружения утечек:

1. **Немедленно** отзовите скомпрометированные ключи
2. **Перенесите** секреты в переменные окружения или secrets manager
3. **Настройте** pre-commit хуки для предотвращения будущих утечек
4. **Включите** сканер в CI/CD pipeline

## Тесты

```bash
# Запустить все тесты
pytest -q

# Запустить с покрытием
pytest --cov=scanner
```

## Документация

- `README.md` — полная документация
- `DEMO.md` — демонстрация возможностей
- `commands.md` — все команды CLI

## Поддержка

Инструмент работает полностью локально, не требует подключения к внешним сервисам.

## Web Interface (local)

```bash
nuclear-web --host 127.0.0.1 --port 8765 --target .
```

Open in browser:

```text
http://127.0.0.1:8765
```

API endpoint:

```text
POST /api/scan
```
