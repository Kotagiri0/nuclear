# 🚀 Демонстрация сканера секретов Nuclear

## Обзор решения

Разработан полнофункциональный инструмент для поиска утечек секретов в исходном коде, соответствующий требованиям кейса КРОК.

## ✅ Реализованный функционал

### Минимальные требования (выполнены)

| Требование | Статус | Описание |
|------------|--------|----------|
| Сканирование файлов проекта | ✅ | Поддержка всех типов файлов (py, js, ts, java, go, php, yaml, env и др.) |
| Поиск по типовым паттернам | ✅ | 25+ паттернов: API-ключи, токены, приватные ключи, connection strings, base64 |
| Определение критичности | ✅ | 4 уровня: LOW, MEDIUM, HIGH, CRITICAL + скоринг (0-18) |
| Формирование отчёта | ✅ | Файл, строка, тип секрета, уровень риска, confidence, entropy |

### Дополнительные возможности (выполнены)

| Возможность | Статус | Описание |
|-------------|--------|----------|
| Поддержка различных типов файлов | ✅ | Python, JavaScript, TypeScript, Java, Go, PHP, C#, Ruby, Rust, YAML, JSON, ENV |
| Настройка правил поиска | ✅ | Пользовательский конфиг ~/.nuclear/config.toml |
| Рекомендации по устранению | ✅ | Развёрнутые рекомендации для каждого типа утечки |
| Taint analysis | ✅ | Трассировка распространения секретов через код |
| Множественные форматы отчётов | ✅ | Text, JSON, SARIF, HTML |

## 📁 Структура проекта

```
nuclear/
├── scanner/
│   ├── core/
│   │   ├── patterns.py       # Сигнатуры секретов (25+ паттернов)
│   │   ├── analysis.py       # Анализ, скоринг, taint tracing
│   │   ├── scanning.py       # Сканирование файлов/директорий/zip/git
│   │   ├── inputs.py         # Загрузка из URL/Git
│   │   └── runner.py         # Единая точка входа
│   ├── output/
│   │   ├── reporting.py      # Генерация отчётов (text/json/sarif)
│   │   ├── html_report.py    # HTML отчёт
│   │   ├── recommendations.py # Рекомендации по устранению ⭐
│   │   └── policy.py         # CI/CD policy gate
│   ├── cli/
│   │   └── main.py           # CLI интерфейс
│   ├── config/
│   │   └── config.py         # Пользовательская конфигурация
│   └── repl/                 # Интерактивный режим
├── demo_project/             # Демонстрационный проект с утечками
├── tests/
│   └── tests/                # 384 unit/integration теста
└── README.md
```

## 🎯 Типы обнаруживаемых секретов

### Критичные (CRITICAL/HIGH)
- 🔑 AWS Access/Secret Keys
- 🔑 GitHub Tokens (ghp_, gho_, ghs_)
- 🔑 Stripe Secret Keys
- 🔑 Private Keys (RSA, EC, DSA, OPENSSH)
- 🔑 Database Connection Strings
- 🔑 JWT Tokens

### Средние (MEDIUM)
- 🔑 Google API Keys
- 🔑 Telegram Bot Tokens
- 🔑 SendGrid/Mailgun API Keys
- 🔑 Bearer/Basic Auth tokens
- 🔑 Generic secrets/passwords

## 📊 Форматы отчётов

### 1. Text (консольный)
```bash
nuclear-scan demo_project
```
- Цветной вывод с emoji
- Детальная информация о каждой находке
- Taint traces для опасных потоков данных

### 2. JSON
```bash
nuclear-scan demo_project --format json --output report.json
```
- Машиночитаемый формат
- Полная информация о находках
- Интеграция с другими системами

### 3. SARIF
```bash
nuclear-scan demo_project --format sarif --output report.sarif
```
- Стандарт для GitHub Security
- Интеграция с GitHub Code Scanning
- Поддержка Visual Studio

### 4. HTML
```bash
nuclear-scan demo_project --format html
```
- Интерактивный отчёт
- Фильтрация по severity
- Сохранение в .nuclear-scan-result/index.html

## 🛠️ Команды для демонстрации

### Базовое сканирование
```bash
nuclear-scan demo_project --verbose
```

### Сканирование с рекомендациями
```bash
nuclear-scan demo_project --recommendations --min-severity HIGH
```

### JSON отчёт
```bash
nuclear-scan demo_project --format json --output demo_project/report.json
```

### HTML отчёт
```bash
nuclear-scan demo_project --format html
```

### CI/CD режим (fail на HIGH)
```bash
nuclear-scan demo_project --fail-on HIGH --quiet
echo Exit code: %ERRORLEVEL%
```

## 📈 Метрики решения

| Метрика | Значение |
|---------|----------|
| Паттернов секретов | 25+ |
| Поддерживаемых языков | 10+ |
| Тестов | 384 |
| Форматов отчётов | 4 |
| Уровней severity | 4 (LOW/MEDIUM/HIGH/CRITICAL) |
| Метрик скоринга | Score, Entropy, Confidence |

## 🔧 Архитектура анализа

### 1. Detection (Обнаружение)
- Regex pattern matching (25+ паттернов)
- Context analysis (ключевые слова вокруг)
- Entropy calculation (Shannon entropy)
- Structure validation (валидация формата)

### 2. Scoring (Оценка)
```
Base Score (из паттерна)
+ Entropy bonus (>4.5 = +3, >3.5 = +1)
+ Context bonus (+2)
+ File type bonus (+2 для .env и конфига)
+ Structure validation (+3)
- Hash penalty (-3 для хешей)
= Final Score (0-18)
```

### 3. Severity Mapping
```
Score >= 12 → CRITICAL
Score >= 8  → HIGH
Score >= 5  → MEDIUM
Score < 5   → LOW
```

### 4. Taint Analysis (Трассировка)
- Отслеживание распространения секретов
- Обнаружение опасных sink'ов (HTTP, logging, exec)
- Формирование полного пути утечки

## 📋 Рекомендации по устранению

Для каждого типа секрета предоставляются:
1. **Краткое описание проблемы**
2. **Приоритет устранения** (high/medium/low)
3. **Примеры правильного кода**
4. **Ссылки на лучшие практики**

### Пример рекомендации для AWS Keys:
```python
# ❌ Неправильно:
AWS_ACCESS_KEY_ID = "AKIA..."

# ✅ Правильно:
import os
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")

# ✅ Ещё лучше (IAM role):
import boto3
client = boto3.client('s3')
```

## 🧪 Тестирование

```bash
# Запустить все тесты
pytest -q

# Запустить с покрытием
pytest --cov=scanner --cov-report=html

# Запустить конкретный тест
pytest tests/tests/test_scanner.py -v
```

## 📦 Установка и использование

```bash
# Установка зависимостей
pip install -r requirements.txt

# Установка в editable режиме
pip install -e .

# Запуск сканера
nuclear-scan <target> [options]
```

## 🎓 Соответствие требованиям кейса

| Требование кейса | Реализация |
|------------------|------------|
| Сканирование файлов | ✅ Все типы файлов в проекте |
| Поиск по паттернам | ✅ 25+ паттернов, включая API-ключи, токены, ключи, base64 |
| Определение критичности | ✅ 4 уровня + скоринг 0-18 |
| Отчёт (файл, строка, тип, риск) | ✅ Полная информация + confidence, entropy |
| Поддержка типов файлов | ✅ 10+ языков программирования |
| Настройка правил | ✅ config.toml для кастомизации |
| Рекомендации | ✅ Развёрнутые рекомендации для каждого типа |
| Локальная работа | ✅ Не требует внешних сервисов |
| CLI интерфейс | ✅ Полноценный CLI с опциями |

## 🔐 Безопасность

- **Не отправляет данные вовне** — весь анализ локально
- **Не сохраняет секреты** — в отчётах обрезаются до 60-80 символов
- **Exit code для CI/CD** — интеграция с pipeline
- **Игнорирование ложных срабатываний** — фильтрация test/fake/example

## 📞 Контакты

Инструмент разработан в рамках кейса КРОК для хакатона.
