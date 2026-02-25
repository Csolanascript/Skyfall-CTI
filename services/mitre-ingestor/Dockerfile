# Skyfall-CTI · MITRE ATT&CK Ingestor
# Descarga Enterprise/Mobile/ICS ATT&CK → valida STIX 2.1 → produce a Kafka
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
