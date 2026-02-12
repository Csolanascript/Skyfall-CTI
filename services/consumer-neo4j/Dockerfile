# Skyfall-CTI · Consumer Neo4j
# Kafka consumer → Inserción de nodos/relaciones STIX 2.1 en el grafo
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
