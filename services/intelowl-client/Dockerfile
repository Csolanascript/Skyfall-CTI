# Skyfall-CTI · IntelOwl Client
# Cliente asíncrono de alto rendimiento para enriquecimiento de observables vía Intel-Owl
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop"]
