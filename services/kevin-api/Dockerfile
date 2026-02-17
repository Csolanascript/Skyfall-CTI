# ============================================================================
#  Skyfall-CTI · KEVin API  (https://github.com/synfinner/KEVin)
#  API para CISA KEV + NVD/MITRE — despliegue ligero con Flask dev server
# ============================================================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dependencias de sistema (gcc + headers para compilar Brotli, gevent, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clonar el repositorio de KEVin
RUN git clone --depth 1 https://github.com/synfinner/KEVin.git . && \
    rm -rf .git .github tests

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8444

# Un solo worker, sin concurrencia — ligero para desarrollo/TFG
CMD ["gunicorn", "--bind", "0.0.0.0:8444", "--workers", "1", "--worker-class", "gevent", "--timeout", "60", "kevin:app"]
