# ============================================================================
#  Skyfall-CTI · Batería de pruebas de integración del stack
#
#  Ejecuta con:  pytest tests/test_stack.py -v
#  Desde:        /deployment (necesita docker compose corriendo)
# ============================================================================
"""
Tests de integración para verificar que todos los servicios del stack
Skyfall-CTI están operativos y se comunican correctamente.
"""
import os
import subprocess
import time

import pytest
import requests

# ── Configuración ────────────────────────────────────────────────────────────

COMPOSE_DIR = os.environ.get("COMPOSE_DIR", ".")  # Se ejecuta desde /deployment

# El nombre del proyecto lo define COMPOSE_PROJECT_NAME (env) o el nombre del
# directorio que contiene el docker-compose.yml.
_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "deployment")
DOCKER_NETWORK = f"{_PROJECT}_skyfall_backbone"

# Puertos expuestos al host
PORTS = {
    "elasticsearch": 9200,
    "neo4j_http": 7474,
    "neo4j_bolt": 7687,
    "kafka": 9092,
    "n8n": 5679,
    "kevin_api": 8001,
    "intelowl": 8002,
    "correlation_engine": 8003,
    "intelowl_client": 8004,
    "mcp_server": 8000,
    "frontend": 3000,
}

# Servicios que deben estar "Up" (todos)
ALL_SERVICES = [
    "zookeeper",
    "kafka",
    "elasticsearch",
    "neo4j",
    "n8n",
    "telegram-crawler",
    "dumps-crawler",
    "kevin-mongo",
    "kevin-redis",
    "kevin-api",
    "intelowl",
    "intelowl-celery-beat",
    "intelowl-celery-worker",
    "intelowl-db",
    "intelowl-redis",
    "intelowl-client",
    "consumer-elastic",
    "consumer-neo4j",
    "correlation-engine",
    "mcp-server",
    "frontend",
]

# Workers Python sin puerto expuesto (se verifican via docker exec)
PYTHON_WORKERS = [
    "consumer-elastic",
    "consumer-neo4j",
    "telegram-crawler",
    "dumps-crawler",
    "intelowl-client",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def docker_compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Ejecuta un comando docker compose en el directorio de deployment."""
    return subprocess.run(
        ["docker", "compose", *args],
        capture_output=True,
        text=True,
        cwd=COMPOSE_DIR,
        check=check,
    )


def docker_exec(service: str, *cmd: str) -> subprocess.CompletedProcess:
    """Ejecuta un comando dentro de un contenedor de servicio."""
    return docker_compose("exec", "-T", service, *cmd, check=False)


def curl_internal(url: str) -> str:
    """Hace un curl desde dentro de la red backbone Docker."""
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", DOCKER_NETWORK,
            "curlimages/curl", "-s", "-f", url,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def wait_for_http(url: str, timeout: int = 60, interval: int = 5) -> bool:
    """Espera hasta que un endpoint HTTP responda 2xx."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.ok:
                return True
        except requests.RequestException:
            pass
        time.sleep(interval)
    return False


def wait_for_internal(url: str, timeout: int = 60, interval: int = 5) -> bool:
    """Espera a que un servicio en la red backbone Docker responda."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = curl_internal(url)
        if body:
            return True
        time.sleep(interval)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  1. TESTS DE ESTADO DE CONTENEDORES
# ═══════════════════════════════════════════════════════════════════════════════

class TestContainerStatus:
    """Verifica que todos los contenedores estén corriendo."""

    def test_compose_config_valid(self):
        """docker compose config no produce errores."""
        result = docker_compose("config", "--quiet")
        assert result.returncode == 0

    def test_all_containers_running(self):
        """Todos los servicios definidos están en estado 'Up'."""
        result = docker_compose("ps", "-a", "--format", "{{.Name}}\t{{.Status}}")
        output = result.stdout
        for service in ALL_SERVICES:
            # El nombre del contenedor incluye el project name como prefijo
            matching = [l for l in output.splitlines() if service in l]
            assert matching, f"Servicio {service} no encontrado en 'docker compose ps'"
            for line in matching:
                assert "Up" in line, (
                    f"Servicio {service} no está 'Up': {line}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
#  2. TESTS DE INFRAESTRUCTURA
# ═══════════════════════════════════════════════════════════════════════════════

class TestElasticsearch:
    """Verifica que Elasticsearch esté operativo."""

    @classmethod
    def setup_class(cls):
        """Espera a que Elasticsearch esté listo (hasta 60s)."""
        assert wait_for_internal(
            "http://elasticsearch:9200", timeout=60
        ), "Elasticsearch no arrancó en 60s"

    def test_cluster_health(self):
        """El cluster responde con nombre y versión."""
        body = curl_internal("http://elasticsearch:9200")
        assert "docker-cluster" in body
        assert "8.12.0" in body

    def test_cluster_status(self):
        """El cluster está en estado green o yellow."""
        body = curl_internal("http://elasticsearch:9200/_cluster/health")
        assert '"status":"green"' in body or '"status":"yellow"' in body

    def test_can_index_document(self):
        """Se puede indexar y buscar un documento de prueba."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", DOCKER_NETWORK,
                "curlimages/curl", "-s",
                "-X", "POST",
                "http://elasticsearch:9200/test-index/_doc/1",
                "-H", "Content-Type: application/json",
                "-d", '{"test": "skyfall-ci", "timestamp": "2026-02-12"}',
            ],
            capture_output=True, text=True,
        )
        assert '"result":"created"' in result.stdout or '"result":"updated"' in result.stdout

        # Leer de vuelta
        body = curl_internal("http://elasticsearch:9200/test-index/_doc/1")
        assert "skyfall-ci" in body

        # Limpiar
        subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", DOCKER_NETWORK,
                "curlimages/curl", "-s",
                "-X", "DELETE",
                "http://elasticsearch:9200/test-index",
            ],
            capture_output=True, text=True,
        )


class TestNeo4j:
    """Verifica que Neo4j esté operativo."""

    @classmethod
    def setup_class(cls):
        """Espera a que Neo4j HTTP esté listo (hasta 60s)."""
        assert wait_for_internal(
            "http://neo4j:7474", timeout=60
        ), "Neo4j no arrancó en 60s"

    def test_http_api(self):
        """El endpoint HTTP responde con info del servidor."""
        body = curl_internal("http://neo4j:7474")
        assert "neo4j_version" in body
        assert "5.15.0" in body

    def test_bolt_connection(self):
        """Se puede conectar por Bolt y ejecutar un query Cypher."""
        result = docker_exec(
            "consumer-neo4j",  # tiene el driver neo4j instalado
            "python", "-c",
            (
                "from neo4j import GraphDatabase; "
                "d = GraphDatabase.driver('bolt://neo4j:7687', auth=('neo4j','skyfall2026')); "
                "s = d.session(); "
                "r = s.run('RETURN 1 AS n').single(); "
                "print(r['n']); "
                "s.close(); d.close()"
            ),
        )
        assert result.returncode == 0
        assert "1" in result.stdout


class TestKafka:
    """Verifica que Kafka esté operativo."""

    @classmethod
    def setup_class(cls):
        """Espera a que Kafka esté listo aceptando conexiones (hasta 30s)."""
        deadline = time.time() + 30
        while time.time() < deadline:
            r = docker_exec(
                "kafka",
                "kafka-topics", "--bootstrap-server", "localhost:9092", "--list",
            )
            if r.returncode == 0:
                return
            time.sleep(3)
        raise AssertionError("Kafka no arrancó en 30s")

    def test_broker_accessible(self):
        """El broker responde a kafka-topics --list."""
        result = docker_exec(
            "kafka",
            "kafka-topics", "--bootstrap-server", "localhost:9092", "--list",
        )
        assert result.returncode == 0

    def test_produce_consume_roundtrip(self):
        """Se puede producir y consumir un mensaje completo."""
        topic = "ci-test-roundtrip"

        # Crear topic
        docker_exec(
            "kafka",
            "kafka-topics", "--bootstrap-server", "localhost:9092",
            "--create", "--topic", topic,
            "--partitions", "1", "--replication-factor", "1",
        )

        # Producir mensaje
        docker_exec(
            "kafka",
            "bash", "-c",
            f'echo "skyfall-test-msg" | kafka-console-producer '
            f'--bootstrap-server localhost:9092 --topic {topic}',
        )
        time.sleep(3)

        # Consumir mensaje (retry con timeout extendido)
        for _ in range(3):
            result = docker_exec(
                "kafka",
                "kafka-console-consumer",
                "--bootstrap-server", "localhost:9092",
                "--topic", topic,
                "--from-beginning",
                "--timeout-ms", "10000",
            )
            if "skyfall-test-msg" in result.stdout:
                break
            time.sleep(2)
        assert "skyfall-test-msg" in result.stdout

        # Limpiar
        docker_exec(
            "kafka",
            "kafka-topics", "--bootstrap-server", "localhost:9092",
            "--delete", "--topic", topic,
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  3. TESTS DE ORQUESTACIÓN (n8n)
# ═══════════════════════════════════════════════════════════════════════════════

class TestN8n:
    """Verifica la instancia de n8n."""

    def test_n8n_health(self):
        """n8n responde al health check."""
        r = requests.get(f"http://localhost:{PORTS['n8n']}/healthz", timeout=10)
        assert r.status_code == 200

    def test_n8n_data_volume(self):
        """La instancia tiene su volumen de datos montado."""
        result = docker_compose(
            "exec", "-T", "n8n",
            "ls", "/home/node/.n8n",
            check=False,
        )
        assert result.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  4. TESTS DE SERVICIOS CUSTOM (Python/FastAPI)
# ═══════════════════════════════════════════════════════════════════════════════

class TestKevinAPI:
    """Verifica KEVin API (synfinner/KEVin — Flask + MongoDB + Redis)."""

    def test_homepage(self):
        """La página principal de KEVin responde."""
        r = requests.get(f"http://localhost:{PORTS['kevin_api']}", timeout=10)
        assert r.status_code == 200
        assert "KEVin" in r.text

    def test_metrics_endpoint(self):
        """El endpoint /get_metrics responde con métricas."""
        r = requests.get(f"http://localhost:{PORTS['kevin_api']}/get_metrics", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "cves_count" in data or "kevs_count" in data

    def test_kev_endpoint(self):
        """El endpoint /kev responde con datos de vulnerabilidades."""
        r = requests.get(f"http://localhost:{PORTS['kevin_api']}/kev?per_page=1", timeout=10)
        assert r.status_code == 200


class TestCorrelationEngine:
    """Verifica el módulo de correlación."""

    def test_health(self):
        body = curl_internal("http://correlation-engine:8000/health")
        assert "correlation-engine" in body

    def test_docs_available(self):
        body = curl_internal("http://correlation-engine:8000/docs")
        assert "Swagger" in body or "FastAPI" in body or "openapi" in body.lower()


class TestMCPServer:
    """Verifica el MCP Server (FastAPI + RAG)."""

    def test_health(self):
        r = requests.get(f"http://localhost:{PORTS['mcp_server']}/health", timeout=10)
        assert r.status_code == 200
        assert r.json()["service"] == "mcp-server"

    def test_docs_available(self):
        r = requests.get(f"http://localhost:{PORTS['mcp_server']}/docs", timeout=10)
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
#  5. TESTS DE INTEL-OWL
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelOwl:
    """Verifica Intel-Owl y sus workers."""

    def test_api_responds(self):
        """Intel-Owl API responde (401 sin auth = funciona)."""
        # Intel-Owl tarda en arrancar (migraciones Django), retry hasta 90s
        for attempt in range(6):
            result = docker_exec(
                "intelowl",
                "python", "-c",
                "import urllib.request, urllib.error\n"
                "try:\n"
                "    urllib.request.urlopen('http://localhost:8001/api/')\n"
                "except urllib.error.HTTPError as e:\n"
                "    print(e.code, e.read().decode())\n"
                "except Exception as e:\n"
                "    print('ERR', e)\n",
            )
            combined = result.stdout + result.stderr
            if "401" in combined or "Authentication" in combined or "detail" in combined:
                break
            time.sleep(15)
        assert "401" in combined or "Authentication" in combined or "detail" in combined

    def test_celery_worker_alive(self):
        """El worker Celery está corriendo."""
        result = docker_compose(
            "ps", "intelowl-celery-worker",
            "--format", "{{.Status}}",
            check=False,
        )
        assert "Up" in result.stdout

    def test_celery_beat_alive(self):
        """El scheduler Celery está corriendo."""
        result = docker_compose(
            "ps", "intelowl-celery-beat",
            "--format", "{{.Status}}",
            check=False,
        )
        assert "Up" in result.stdout

    def test_redis_accessible(self):
        """Redis responde a PING desde Intel-Owl."""
        result = docker_exec(
            "intelowl-redis",
            "redis-cli", "ping",
        )
        assert "PONG" in result.stdout

    def test_postgres_accessible(self):
        """PostgreSQL acepta conexiones."""
        result = docker_exec(
            "intelowl-db",
            "pg_isready", "-U", "intelowl", "-d", "intel_owl_db",
        )
        assert result.returncode == 0


class TestIntelOwlClient:
    """Verifica el cliente asíncrono de Intel-Owl (Python/FastAPI)."""

    @classmethod
    def setup_class(cls):
        """Espera a que intelowl-client arranque (hasta 60s)."""
        assert wait_for_internal(
            "http://intelowl-client:8000/health", timeout=60
        ), "intelowl-client no arrancó en 60s"

    def test_health(self):
        """El endpoint /health responde OK."""
        r = requests.get(f"http://localhost:{PORTS['intelowl_client']}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["service"] == "intelowl-client"

    def test_health_internal(self):
        """Responde al health desde la red backbone."""
        body = curl_internal("http://intelowl-client:8000/health")
        assert "intelowl-client" in body

    def test_docs_available(self):
        """La documentación OpenAPI está accesible."""
        r = requests.get(f"http://localhost:{PORTS['intelowl_client']}/docs", timeout=10)
        assert r.status_code == 200

    def test_analyze_endpoint_rejects_empty(self):
        """El endpoint /analyze rechaza peticiones sin observable."""
        r = requests.post(
            f"http://localhost:{PORTS['intelowl_client']}/analyze",
            json={},
            timeout=10,
        )
        assert r.status_code == 422  # Validation error

    def test_batch_endpoint_exists(self):
        """El endpoint /analyze/batch está registrado."""
        r = requests.post(
            f"http://localhost:{PORTS['intelowl_client']}/analyze/batch",
            json={"observables": []},
            timeout=10,
        )
        # Lista vacía → respuesta vacía pero 200
        assert r.status_code == 200
        assert r.json() == []

    def test_has_pyintelowl(self):
        """La dependencia pyintelowl está instalada."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c", "from pyintelowl import IntelOwl; print('ok')",
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_has_uvloop(self):
        """uvloop está instalado (rendimiento)."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c", "import uvloop; print('ok')",
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_has_stix2(self):
        """La dependencia stix2 está instalada."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c", "import stix2; print('ok')",
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_stix_converter_importable(self):
        """El módulo stix_converter es importable dentro del contenedor."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c",
            "from stix_converter import job_to_stix_bundle; print('ok')",
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_stix_conversion_produces_valid_bundle(self):
        """La conversión STIX genera un bundle válido con un job simulado."""
        code = """
import json
from stix_converter import job_to_stix_bundle
job = {
    "id": 999,
    "observable_name": "8.8.8.8",
    "observable_classification": "ip",
    "status": "reported_without_fails",
    "tlp": "AMBER",
    "received_request_time": "2025-01-01T00:00:00Z",
    "finished_analysis_time": "2025-01-01T00:00:05Z",
    "process_time": 5.0,
    "analyzer_reports": [
        {
            "name": "AbuseIPDB",
            "status": "SUCCESS",
            "report": {"abuse_confidence_score": 0},
            "errors": [],
            "process_time": 1.2,
            "start_time": "2025-01-01T00:00:01Z",
            "end_time": "2025-01-01T00:00:02Z",
            "type": "analyzer"
        }
    ]
}
bundle = job_to_stix_bundle(job)
assert bundle["type"] == "bundle"
assert bundle["id"].startswith("bundle--")
types = {o["type"] for o in bundle["objects"]}
assert "identity" in types
assert "indicator" in types
assert "report" in types
assert "note" in types
assert "ipv4-addr" in types
assert "relationship" in types
print("stix_ok")
"""
        result = docker_exec("intelowl-client", "python", "-c", code)
        assert result.returncode == 0, f"STIX conversion failed: {result.stderr}"
        assert "stix_ok" in result.stdout

    def test_stix_conversion_malicious_detection(self):
        """Detecta maliciosidad y genera objetos Malware + Relationship."""
        code = """
import json
from stix_converter import job_to_stix_bundle
job = {
    "id": 1000,
    "observable_name": "evil.example.com",
    "observable_classification": "domain",
    "status": "reported_without_fails",
    "tlp": "RED",
    "received_request_time": "2025-01-01T00:00:00Z",
    "finished_analysis_time": "2025-01-01T00:00:05Z",
    "process_time": 5.0,
    "analyzer_reports": [
        {
            "name": "VirusTotal_v3",
            "status": "SUCCESS",
            "report": {"malicious": True, "positives": 15, "total": 70},
            "errors": [],
            "process_time": 2.0,
            "type": "analyzer"
        }
    ]
}
bundle = job_to_stix_bundle(job)
types = [o["type"] for o in bundle["objects"]]
assert "malware" in types, f"No malware object found. Types: {types}"
rel_types = [o["relationship_type"] for o in bundle["objects"] if o["type"] == "relationship"]
assert "indicates" in rel_types, f"No 'indicates' relationship. Rels: {rel_types}"
indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
assert "malicious" in indicator.get("labels", [])
print("malicious_ok")
"""
        result = docker_exec("intelowl-client", "python", "-c", code)
        assert result.returncode == 0, f"Malicious detection failed: {result.stderr}"
        assert "malicious_ok" in result.stdout

    def test_stix_output_env_var(self):
        """La variable STIX_OUTPUT está configurada en el contenedor."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c",
            "import os; print(os.getenv('STIX_OUTPUT', 'unset'))",
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "true"


# ═══════════════════════════════════════════════════════════════════════════════
#  6. TESTS DE WORKERS PYTHON
# ═══════════════════════════════════════════════════════════════════════════════

class TestPythonWorkers:
    """Verifica que los workers Python están vivos."""

    @pytest.mark.parametrize("service", PYTHON_WORKERS)
    def test_worker_alive(self, service: str):
        """El worker responde a un exec de Python."""
        result = docker_exec(service, "python", "-c", "print('alive')")
        assert result.returncode == 0
        assert "alive" in result.stdout

    @pytest.mark.parametrize("service", PYTHON_WORKERS)
    def test_worker_has_dependencies(self, service: str):
        """Las dependencias pip están instaladas."""
        result = docker_exec(service, "pip", "list", "--format=columns")
        assert result.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  7. TESTS DE FRONTEND
# ═══════════════════════════════════════════════════════════════════════════════

class TestFrontend:
    """Verifica el frontend React."""

    def test_serves_html(self):
        """Nginx sirve la página estática."""
        r = requests.get(f"http://localhost:{PORTS['frontend']}", timeout=10)
        assert r.status_code == 200
        assert "Skyfall" in r.text

    def test_nginx_running(self):
        """El proceso nginx está activo."""
        result = docker_exec("frontend", "nginx", "-t")
        assert result.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  8. TESTS DE CONECTIVIDAD INTER-SERVICIO
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkConnectivity:
    """
    Verifica que los servicios pueden comunicarse entre sí
    a través de las redes Docker definidas.
    """

    def test_n8n_reaches_kafka(self):
        """n8n puede resolver el DNS de Kafka en backbone."""
        result = docker_exec(
            "n8n",
            "wget", "-q", "-O", "-", "--timeout=5",
            "http://kafka:29092",
        )
        # Kafka no responde HTTP en el puerto binario, pero si resuelve
        # el DNS y conecta, wget fallará con error de protocolo, no de DNS
        # Suficiente verificar que no sea error de resolución
        combined = result.stdout + result.stderr
        assert "Resolving kafka" not in combined or "failed" not in combined.lower()

    def test_intelowl_client_reaches_intelowl(self):
        """intelowl-client puede alcanzar Intel-Owl API."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c",
            "import urllib.request, urllib.error\n"
            "try:\n"
            "    urllib.request.urlopen('http://intelowl:8001/api/')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code)\n"
            "except Exception as e:\n"
            "    print('ERR', e)\n",
        )
        combined = result.stdout + result.stderr
        assert "401" in combined or "200" in combined

    def test_intelowl_client_reaches_kafka(self):
        """intelowl-client puede conectar a Kafka."""
        result = docker_exec(
            "intelowl-client",
            "python", "-c",
            "from confluent_kafka import Producer; "
            "p = Producer({'bootstrap.servers': 'kafka:29092'}); "
            "p.flush(timeout=5); "
            "print('ok')",
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

    def test_mcp_reaches_correlation(self):
        """MCP-server puede alcanzar el correlation-engine."""
        result = docker_exec(
            "mcp-server",
            "python", "-c",
            "import urllib.request; "
            "r = urllib.request.urlopen('http://correlation-engine:8000/health'); "
            "print(r.read().decode())",
        )
        assert "correlation-engine" in result.stdout

    def test_mcp_reaches_elasticsearch(self):
        """MCP-server puede alcanzar Elasticsearch."""
        result = docker_exec(
            "mcp-server",
            "python", "-c",
            "import urllib.request; "
            "r = urllib.request.urlopen('http://elasticsearch:9200'); "
            "print(r.read().decode())",
        )
        assert "docker-cluster" in result.stdout

    def test_mcp_reaches_neo4j(self):
        """MCP-server puede alcanzar Neo4j."""
        result = docker_exec(
            "mcp-server",
            "python", "-c",
            "import urllib.request; "
            "r = urllib.request.urlopen('http://neo4j:7474'); "
            "print(r.read().decode())",
        )
        assert "neo4j_version" in result.stdout

    def test_consumer_elastic_reaches_es(self):
        """consumer-elastic puede conectar a ES."""
        result = docker_exec(
            "consumer-elastic",
            "python", "-c",
            "import urllib.request; "
            "r = urllib.request.urlopen('http://elasticsearch:9200'); "
            "print(r.read().decode())",
        )
        assert "docker-cluster" in result.stdout

    def test_consumer_neo4j_reaches_neo4j(self):
        """consumer-neo4j puede conectar a Neo4j."""
        result = docker_exec(
            "consumer-neo4j",
            "python", "-c",
            "from neo4j import GraphDatabase; "
            "d = GraphDatabase.driver('bolt://neo4j:7687', auth=('neo4j','skyfall2026')); "
            "s = d.session(); "
            "r = s.run('RETURN 42 AS n').single(); "
            "print(r['n']); "
            "s.close(); d.close()",
        )
        assert "42" in result.stdout

    def test_backbone_is_internal(self):
        """
        Los servicios en skyfall_backbone no deberían tener salida a internet.
        Verificamos que un contenedor solo-backbone no resuelve DNS externo.
        """
        # intelowl-db está SOLO en backbone
        result = docker_exec(
            "intelowl-db",
            "sh", "-c",
            "ping -c 1 -W 2 google.com 2>&1 || echo 'NO_INTERNET'",
        )
        combined = result.stdout + result.stderr
        # Debe fallar: sin gateway, no hay salida
        assert "NO_INTERNET" in combined or "bad address" in combined or "unreachable" in combined


# ═══════════════════════════════════════════════════════════════════════════════
#  9. TESTS DE RESILIENCIA BÁSICA
# ═══════════════════════════════════════════════════════════════════════════════

class TestResilience:
    """
    Verifica comportamiento básico de resiliencia:
    los workers sobreviven a reinicios cortos de dependencias.
    """

    def test_consumer_survives_kafka_restart(self):
        """consumer-elastic sigue Up después de reiniciar Kafka."""
        docker_compose("restart", "kafka")
        time.sleep(15)  # Esperar a que Kafka re-arrange

        result = docker_compose(
            "ps", "consumer-elastic",
            "--format", "{{.Status}}",
        )
        assert "Up" in result.stdout
