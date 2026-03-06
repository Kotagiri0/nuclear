"""Конфигурационный файл с примерами утечек секретов."""

# 🔴 AWS Credentials - утечка в коде
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 🔴 GitHub Token
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 🔴 Database connection string
DATABASE_URL = "postgresql://admin:supersecretpassword123@db.example.com:5432/production"

# 🔴 API Keys
STRIPE_SECRET_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 🟡 Менее критичные, но всё равно опасные
APP_SECRET = "my-super-secret-app-key-2024"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# ✅ Правильный подход (через переменные окружения)
# import os
# AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
# AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
