# Skyfall-CTI · Telegram Crawler (Telethon MTProto)
# Productor programático: monitoreo de canales de hacktivismo → Kafka
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
