FROM python:3.11-slim

WORKDIR /app

# Копируем код программы
COPY attacker.py /app/

# Устанавливаем права на выполнение
RUN chmod +x /app/attacker.py

# Создаём директорию для логов
RUN mkdir -p /logs

# Запускаем программу
CMD ["python3", "-u", "/app/attacker.py"]
