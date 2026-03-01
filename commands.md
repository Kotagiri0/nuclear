# Nuclear — Command Reference

## Запуск

```bash
# REPL (интерактивный режим)
python -m scanner
# или
nuclear

# CLI (однократный скан)
python -m scanner.cli <path> [опции]
# или
nuclear-scan <path> [опции]
```

---

## REPL команды

### `scan <path|.zip>`

Сканирование файла, директории или ZIP-архива на наличие секретов.

| Аргумент | Описание |
|---|---|
| `<path>` | Путь к файлу или директории для сканирования |
| `--url`, `-u <url>` | Удалённый Git-репозиторий или URL файла |
| `--format`, `-f <fmt>` | Формат вывода: `table`, `json`, `sarif`, `text` |
| `--severity`, `-s <level>` | Минимальная severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--history`, `-H` | Включить сканирование Git-истории |
| `--commits`, `-c <n>` | Максимальное количество коммитов (по умолчанию 50) |

**Примеры:**
```
scan .
scan src/ --format json
scan --url https://github.com/user/repo.git --history
scan archive.zip --severity HIGH
scan myproject/ -f sarif -s MEDIUM
```

После каждого сканирования автоматически создаётся HTML-отчёт в `.nuclear-scan-result/index.html`.

---

### `set <key> <value>`

Изменение настроек текущей сессии.

| Ключ | Значения | Описание |
|---|---|---|
| `format` | `table`, `json`, `sarif`, `text` | Формат вывода результатов |
| `severity` / `min-severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Минимальный уровень severity |
| `fail-on` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Порог для статуса ошибки (CI) |
| `history` | `on`, `off` | Сканирование Git-истории |
| `commits` | число | Максимум коммитов для истории |

**Примеры:**
```
set format json
set severity HIGH
set history on
set commits 100
```

---

### `config <subcommand>`

Управление постоянной конфигурацией (TOML-файл).

| Подкоманда | Описание |
|---|---|
| `show` | Показать текущую конфигурацию |
| `path` | Показать путь к файлу конфигурации |
| `init` | Создать конфигурацию по умолчанию |
| `set <key> <value>` | Установить значение в конфигурации |

**Примеры:**
```
config show
config path
config init
config set format json
config set min_severity HIGH
```

---

### `status`

Показать текущие настройки сессии (формат, severity, history и т.д.).

---

### `history`

Показать историю введённых команд за текущую сессию.

---

### `clear`

Полная очистка экрана консоли с перерисовкой баннера.

---

### `help [command]`

Показать справку по всем командам или детальную справку по конкретной команде.

**Примеры:**
```
help
help scan
help set
help config
```

---

### `exit` / `quit`

Завершение сессии с выводом краткой статистики (количество команд, сканов, найденных секретов).

Также можно выйти двойным нажатием **Ctrl+C** в течение 2 секунд.

---

## CLI аргументы

```
nuclear-scan <target> [опции]
```

| Аргумент | Описание |
|---|---|
| `target` | Путь к файлу, директории или ZIP |
| `--url`, `-u` | Удалённый URL (Git repo или файл) |
| `--format`, `-f` | Формат: `text`, `json`, `sarif` |
| `--min-severity` | Минимальная severity |
| `--fail-on` | CI gate — severity для exit code ≠ 0 |
| `--history` | Сканировать Git-историю |
| `--commits` | Максимум коммитов |
| `--output`, `-o` | Файл для записи результата |

---

## HTML-отчёт

При каждом сканировании в REPL автоматически создаётся HTML-отчёт:

- **Путь:** `.nuclear-scan-result/index.html`
- **Формат:** Single-file HTML с встроенным CSS/JS
- **Содержит:** таблица находок, фильтрация по severity, статистика
- **Также:** `.nuclear-scan-result/data.json` — данные в JSON

Откройте `index.html` в браузере для интерактивного просмотра результатов.

---

## Автокомплит

REPL поддерживает контекстный автокомплит (Tab):

- На пустой строке — подсказки команд
- После `scan` — аргументы сканирования (`--url`, `--format`, и т.д.)
- После `set` — доступные ключи настроек
- После `config` — подкоманды конфигурации
- После `help` — имена команд
