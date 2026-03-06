# Nuclear Secret Scanner

Продвинутый статический сканер для поиска утечек секретов и критичных чувствительных фрагментов кода.

## Что реализовано

- Обнаружение API-ключей, токенов, учетных данных БД, приватных ключей и общих секретов.
- Ранжирование находок по score, severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) и confidence.
- Точная привязка к месту в формате `файл:строка` с типом уязвимости.
- Трассировка опасного использования секретов через taint-цепочки (источник → распространение → опасный sink).
- Поддерживаемые режимы сканирования:
  - локальный файл,
  - локальная директория,
  - локальный zip-архив,
  - удаленный URL (`git`, прямой `zip/http`),
  - история Git (`--scan-history`).
- Поддержка CI-политики (`--fail-on HIGH`) для блокировки merge в `prod/master`.
- Форматы отчетов: `text`, `json`, `sarif`.

## Архитектура проекта

```text
scanner/
  __init__.py
  cli.py                      # контракт CLI
  analysis.py                 # детекция, скоринг, taint, модели
  scanning.py                 # сканеры file/dir/zip/history
  inputs.py                   # загрузка из URL/Git
  policy.py                   # фильтрация severity и fail-gate
  reporting.py                # репортеры text/json/sarif
  patterns.py                 # сигнатуры, sink-правила, пропуски
  config.py                   # пользовательский конфиг ~/.nuclear/config.toml
  runner.py                   # единая точка запуска scan (cli + repl)
  repl.py                     # интерактивный REPL
tests/
  resources/                  # тестовые данные
    dir/
      corpus/
        manifest.json
        projects/             # 22 тестовых проекта (vulnerable + clean)
    zips/
      demo_vulnerable_project.zip
    fixtures/
    tools/
      generate_corpus.py
  tests/                      # тест-файлы
    test_scanner.py
    test_extended.py
    test_corpus.py
    test_url_and_history.py
    test_analysis_branches.py
    test_cli_integration.py
    test_config.py
    test_inputs.py
    test_patterns_direct.py
    test_reporting_full.py
    test_runner.py
    test_scanning.py
.github/workflows/
  security-scan.yml
```

## Установка

```bash
pip install -r requirements.txt
```

## Опционально: AI-сканирование безопасности кода (NVIDIA Qwen)

По умолчанию сканер работает полностью локально. Если вы хотите включить дополнительную проверку кода через LLM:

```bash
pip install -e ".[ai]"
# Можно либо экспортнуть ключ, либо положить его в .env (см. .env.example)
export NUCLEAR_NVIDIA_API_KEY="...ваш ключ..."
nuclear-scan . --ai-security
```

Можно явно указать модель/эндпоинт:

```bash
nuclear-scan . --ai-security --ai-model "qwen2.5-coder-32b-instruct" --ai-base-url "https://integrate.api.nvidia.com/v1"
```

## Локальный запуск

```bash
# Базовое сканирование (только российские сервисы)
nuclear-scan .

# Сканирование с рекомендациями по устранению
nuclear-scan . --recommendations

# Только HIGH и CRITICAL
nuclear-scan . --min-severity HIGH

# JSON отчёт
nuclear-scan . --format json

# SARIF отчёт (для GitHub Security)
nuclear-scan . --format sarif > scanner.sarif

# HTML отчёт
nuclear-scan . --format html

# Сканирование истории Git
nuclear-scan . --scan-history --history-commits 100

# Тихий режим (только exit code)
nuclear-scan . --quiet

# Подробный режим
nuclear-scan . --verbose
```

## Веб-сервер (локально)

```bash
nuclear-web --host 127.0.0.1 --port 8765 --target .
```

Откройте в браузере:

```text
http://127.0.0.1:8765
```

API для запуска сканирования:

```text
POST /api/scan
```

## Сканирование по URL

```bash
# Git-ссылка
nuclear-scan --url https://github.com/org/repo.git

# HTTP-ссылка на ZIP
nuclear-scan --url https://example.com/project.zip

# URL + история Git
nuclear-scan --url https://github.com/org/repo.git --scan-history --history-commits 100
```

## Режим пакета

Установка в editable-режиме и запуск через консольную команду:

```bash
pip install -e .
nuclear-scan . --fail-on HIGH
```

Сборка wheel/sdist:

```bash
python -m build
```

## CI и защита веток

Workflow-файл: `.github/workflows/security-scan.yml`

- Запускает unit/integration тесты.
- Запускает scanner gate по исходникам проекта.
- Падает, если найдены уязвимости уровня `HIGH` или `CRITICAL`.
- Формирует SARIF-артефакт.

Базовая policy-команда в CI:

```bash
nuclear-scan scanner --min-severity LOW --fail-on HIGH --exclude scanner/output/recommendations.py --format json
```

## Тестовый корпус (22 проекта)

В `tests/resources/dir/corpus/projects` находятся уязвимые и чистые проекты разных размеров, языков и уровней вложенности.

Покрываемые языки:

- Python
- JavaScript
- TypeScript
- Java
- Go
- PHP
- C#
- Ruby
- Rust
- смешанная многопапочная структура

Перегенерация корпуса:

```bash
python tools/generate_corpus.py
```

## Тесты

```bash
pytest -q
```

Включают:

- исходные unit-тесты сканера,
- тесты качества корпуса,
- тесты URL-сканирования и сканирования истории Git.

## Коды выхода

- `0` — нет находок на уровне `--fail-on` и выше.
- `1` — есть хотя бы одна находка на уровне `--fail-on` и выше.

Это позволяет включить жесткий CI/CD gate на защищенных ветках.
