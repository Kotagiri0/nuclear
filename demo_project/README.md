# Demo Vulnerable Project

Проект для демонстрации работы сканера секретов `nuclear-scan`.

## Содержимое

В этом проекте намеренно размещены примеры утечек секретов:

| Файл | Типы утечек |
|------|-------------|
| `config.py` | AWS credentials, GitHub токены, Stripe ключи, connection strings |
| `.env` | Пароли БД, API ключи, приватные ключи |
| `app.py` | Hardcoded credentials, taint flow (передача секретов в функции) |
| `config.js` | JavaScript/Node.js секреты, Firebase config |
| `k8s-manifest.yaml` | Kubernetes secrets в явном виде |

## Запуск сканера

```bash
# Текстовый отчёт
nuclear-scan demo_project

# JSON отчёт
nuclear-scan demo_project --format json

# SARIF отчёт (для интеграции с GitHub Security)
nuclear-scan demo_project --format sarif

# HTML отчёт
nuclear-scan demo_project --format html

# Только HIGH и CRITICAL
nuclear-scan demo_project --min-severity HIGH

# С рекомендациями (fail на HIGH)
nuclear-scan demo_project --fail-on HIGH
```

## Рекомендации по устранению

1. **Перенесите секреты в переменные окружения**
2. **Используйте системы управления секретами** (HashiCorp Vault, AWS Secrets Manager)
3. **Настройте pre-commit хуки** для предотвращения коммитов с секретами
4. **Включите сканирование в CI/CD pipeline**
