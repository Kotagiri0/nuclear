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
src/
  main.py
  scanner.py                    # фасад совместимости
  secret_scanner/
    __init__.py
    cli.py                      # контракт CLI
    analysis.py                 # детекция, скоринг, taint, модели
    scanning.py                 # сканеры file/dir/zip/history
    inputs.py                   # загрузка из URL/Git
    policy.py                   # фильтрация severity и fail-gate
    reporting.py                # репортеры text/json/sarif
    patterns.py                 # сигнатуры, sink-правила, пропуски
  tools/
    generate_corpus.py
tests/
  test_scanner.py
  test_corpus.py
  test_url_and_history.py
  dir/
    corpus/
      manifest.json
      projects/                 # 22 тестовых проекта (vulnerable + clean)
  zips/
    demo_vulnerable_project.zip
.github/workflows/
  security-scan.yml
```

## Установка

```bash
pip install -r requirements.txt
```

## Локальный запуск

```bash
python src/main.py .
python src/main.py . --min-severity HIGH
python src/main.py . --format json
python src/main.py . --format sarif > scanner.sarif
python src/main.py . --scan-history --history-commits 100
```

## Сканирование по URL

```bash
# Git-ссылка
python src/main.py --url https://github.com/org/repo.git

# HTTP-ссылка на ZIP
python src/main.py --url https://example.com/project.zip

# URL + история Git
python src/main.py --url https://github.com/org/repo.git --scan-history --history-commits 100
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
python src/main.py src/secret_scanner --min-severity LOW --fail-on HIGH --format json
```

## Тестовый корпус (22 проекта)

В `tests/dir/corpus/projects` находятся уязвимые и чистые проекты разных размеров, языков и уровней вложенности.

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
python src/tools/generate_corpus.py
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
