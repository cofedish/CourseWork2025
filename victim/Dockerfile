FROM python:3.11-slim

WORKDIR /app

# Копируем код программы
COPY victim.py /app/

# Устанавливаем права на выполнение
RUN chmod +x /app/victim.py

# Создаём директорию для логов
RUN mkdir -p /logs

# Запускаем программу
CMD ["python3", "-u", "/app/victim.py"]
