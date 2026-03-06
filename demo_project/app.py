"""Пример приложения с утечками секретов и опасным использованием."""

import requests
import logging
import os

# 🔴 Hardcoded credentials
API_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
SECRET_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def make_api_request(endpoint):
    """Делает запрос с использованием секретного токена."""
    headers = {
        "Authorization": f"Bearer {SECRET_TOKEN}",
        "X-API-Key": API_KEY
    }
    
    # 🔴 Токен передаётся в HTTP-запросе (taint flow)
    response = requests.get(endpoint, headers=headers)
    return response

def log_sensitive_data(user_id):
    """Логирование с чувствительными данными."""
    # 🔴 Секрет попадает в логи
    logging.info(f"Processing request for user {user_id} with API key: {API_KEY}")

def connect_to_database():
    """Подключение к БД с hardcoded credentials."""
    # 🔴 Connection string в коде
    conn_string = "mongodb://dbadmin:mongopass123@cluster0.example.com:27017/production"
    
    # 🔴 Передача секрета в функцию подключения
    return connect(conn_string)

def connect(conn_string):
    """Фиктивная функция подключения."""
    pass

# 🔴 Private key в коде
SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA...
-----END OPENSSH PRIVATE KEY-----"""

def deploy_to_server():
    """Деплой с использованием приватного ключа."""
    # 🔴 Использование приватного ключа для SSH
    import paramiko
    client = paramiko.SSHClient()
    # Ключ передаётся в метод подключения (taint flow)
    client.connect(hostname="prod.example.com", pkey=SSH_PRIVATE_KEY)

# 🟡 Bearer token в заголовке
AUTH_HEADER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
