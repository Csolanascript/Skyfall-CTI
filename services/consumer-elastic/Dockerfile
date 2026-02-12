# Skyfall-CTI · Consumer Elasticsearch
# Kafka consumer → Indexación de STIX bundles y contenido OSINT crudo
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
