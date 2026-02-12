# Skyfall-CTI · Dumps Crawler
# Scraping de IP/hashes desde GitHub → enriquecimiento Intel-Owl → STIX 2.1 → Kafka
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
