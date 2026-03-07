FROM python:3.11-alpine

WORKDIR /app

# Установка зависимостей ОС для сборки и работы git
RUN apk add --no-cache git gcc musl-dev libffi-dev

# Копируем файлы зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir openai  # Устанавливаем опциональные зависимости для ИИ

# Копируем исходный код проекта
COPY . .

# Устанавливаем сам сканер как пакет
RUN pip install -e .

# Открываем порт для веб-интерфейса
EXPOSE 8765

# Устанавливаем точку входа. По умолчанию запускаем веб-сервер
CMD ["nuclear-web", "--host", "0.0.0.0", "--port", "8765", "--target", "/app"]
