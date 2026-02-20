"""
Skyfall-CTI · IntelOwl Async Client
====================================
Microservicio asíncrono de alto rendimiento para enriquecimiento de
observables (IPs, dominios, hashes, URLs) mediante Intel-Owl.

Arquitectura:
  1. Consumidor Kafka asíncrono ─ lee mensajes de topics configurables.
  2. Pool de workers ─ envía análisis concurrentes a Intel-Owl vía pyintelowl.
  3. API HTTP (FastAPI) ─ permite solicitudes de análisis ad-hoc y consulta de
     estado / resultados.
  4. Productor Kafka ─ publica resultados enriquecidos en topic de salida.

Decisiones de rendimiento:
  • uvloop como event-loop (2-4× más rápido que asyncio por defecto).
  • asyncio.Semaphore para limitar la concurrencia hacia Intel-Owl y evitar
    saturar la instancia.
  • Pooling de conexiones HTTP subyacente (requests.Session en pyintelowl).
  • Procesamiento en lotes con asyncio.gather.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from pyintelowl import IntelOwl, IntelOwlClientException

from stix_converter import job_to_stix_bundle

# ──────────────────────────────────────────────────────────────────────
#  Configuración (env vars)
# ──────────────────────────────────────────────────────────────────────
INTELOWL_URL = os.getenv("INTELOWL_URL", "http://intelowl:8001")
INTELOWL_API_KEY = os.getenv("INTELOWL_API_KEY", "")
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:29092")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "cg-intelowl-client")
KAFKA_INPUT_TOPICS = os.getenv("KAFKA_INPUT_TOPICS", "enrichment.requests").split(",")
KAFKA_OUTPUT_TOPIC = os.getenv("KAFKA_OUTPUT_TOPIC", "enrichment.results")
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "10"))
POLL_INTERVAL_SEC = float(os.getenv("POLL_INTERVAL_SEC", "2.0"))
POLL_TIMEOUT_SEC = float(os.getenv("POLL_TIMEOUT_SEC", "300"))
ANALYZERS_DEFAULT = os.getenv("ANALYZERS_DEFAULT", "")  # csv, vacío = todos
STIX_OUTPUT = os.getenv("STIX_OUTPUT", "true").lower() in ("1", "true", "yes")

# ──────────────────────────────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
)
log = logging.getLogger("intelowl-client")

# ──────────────────────────────────────────────────────────────────────
#  Intel-Owl SDK (síncrono internamente, lo envolvemos con run_in_executor)
# ──────────────────────────────────────────────────────────────────────
_owl: Optional[IntelOwl] = None
_semaphore: Optional[asyncio.Semaphore] = None
_producer: Optional[Producer] = None
_consumer_task: Optional[asyncio.Task] = None
_shutdown_event = asyncio.Event()


def _build_owl_client() -> IntelOwl:
    """Construye la instancia de pyintelowl."""
    return IntelOwl(
        token=INTELOWL_API_KEY,
        instance_url=INTELOWL_URL,
    )


# ──────────────────────────────────────────────────────────────────────
#  Helpers asíncronos (run_in_executor para llamadas bloqueantes)
# ──────────────────────────────────────────────────────────────────────
async def _analyze_observable(
    observable: str,
    analyzers: List[str] | None = None,
    connectors: List[str] | None = None,
    tlp: str = "CLEAR",
) -> Dict[str, Any]:
    """Envía análisis de observable a Intel-Owl de forma asíncrona."""
    loop = asyncio.get_running_loop()
    async with _semaphore:  # type: ignore[union-attr]
        result = await loop.run_in_executor(
            None,
            lambda: _owl.send_observable_analysis_request(  # type: ignore[union-attr]
                observable_name=observable,
                analyzers_requested=analyzers,
                connectors_requested=connectors,
                tlp=tlp,
            ),
        )
    return result


async def _analyze_file(
    filename: str,
    binary: bytes,
    analyzers: List[str] | None = None,
    connectors: List[str] | None = None,
    tlp: str = "CLEAR",
) -> Dict[str, Any]:
    """Envía análisis de fichero a Intel-Owl de forma asíncrona."""
    loop = asyncio.get_running_loop()
    async with _semaphore:  # type: ignore[union-attr]
        result = await loop.run_in_executor(
            None,
            lambda: _owl.send_file_analysis_request(  # type: ignore[union-attr]
                filename=filename,
                binary=binary,
                analyzers_requested=analyzers,
                connectors_requested=connectors,
                tlp=tlp,
            ),
        )
    return result


async def _poll_job(job_id: int) -> Dict[str, Any]:
    """Hace polling del estado de un job hasta que finaliza o timeout."""
    loop = asyncio.get_running_loop()
    deadline = time.monotonic() + POLL_TIMEOUT_SEC
    while time.monotonic() < deadline:
        job = await loop.run_in_executor(
            None,
            lambda: _owl.get_job_by_id(job_id),  # type: ignore[union-attr]
        )
        status = job.get("status", "")
        if status in ("reported_without_fails", "reported_with_fails", "failed", "killed"):
            return job
        await asyncio.sleep(POLL_INTERVAL_SEC)
    return {"job_id": job_id, "status": "timeout"}


async def _analyze_and_wait(
    observable: str,
    analyzers: List[str] | None = None,
    tlp: str = "CLEAR",
) -> Dict[str, Any]:
    """Envía análisis + polling asíncrono del resultado completo."""
    resp = await _analyze_observable(observable, analyzers=analyzers, tlp=tlp)
    job_id = resp.get("job_id")
    if not job_id:
        return resp
    result = await _poll_job(job_id)
    return result


# ──────────────────────────────────────────────────────────────────────
#  Publicación de resultados en Kafka
# ──────────────────────────────────────────────────────────────────────
def _delivery_report(err, msg):
    if err:
        log.error("Kafka delivery failed: %s", err)
    else:
        log.debug("Kafka delivered → %s [%d]", msg.topic(), msg.partition())


def _publish_result(topic: str, key: str, payload: dict):
    """Publica un resultado en el topic Kafka de salida."""
    if _producer is None:
        return
    _producer.produce(
        topic,
        key=key.encode("utf-8"),
        value=json.dumps(payload, default=str).encode("utf-8"),
        callback=_delivery_report,
    )
    _producer.poll(0)


# ──────────────────────────────────────────────────────────────────────
#  Consumidor Kafka (background task)
# ──────────────────────────────────────────────────────────────────────
async def _kafka_consumer_loop():
    """Consume mensajes de los topics de entrada y dispara análisis."""
    conf = {
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": KAFKA_GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    }
    consumer = Consumer(conf)
    consumer.subscribe(KAFKA_INPUT_TOPICS)
    log.info(
        "Kafka consumer arrancado → topics=%s, group=%s",
        KAFKA_INPUT_TOPICS,
        KAFKA_GROUP_ID,
    )

    loop = asyncio.get_running_loop()
    default_analyzers = [a.strip() for a in ANALYZERS_DEFAULT.split(",") if a.strip()] or None

    try:
        while not _shutdown_event.is_set():
            # Poll bloqueante en executor para no bloquear el event-loop
            msg = await loop.run_in_executor(None, lambda: consumer.poll(1.0))
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.error("Kafka error: %s", msg.error())
                continue

            try:
                payload = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                log.warning("Mensaje descartado (decode): %s", exc)
                continue

            observable = payload.get("observable") or payload.get("value") or payload.get("name")
            if not observable:
                log.warning("Mensaje sin observable válido: %s", payload)
                continue

            analyzers = payload.get("analyzers") or default_analyzers
            tlp = payload.get("tlp", "CLEAR")

            # Fire-and-forget con gather limitado por semáforo
            asyncio.create_task(
                _process_single(observable, analyzers, tlp)
            )

    except asyncio.CancelledError:
        log.info("Kafka consumer cancelado")
    finally:
        consumer.close()
        log.info("Kafka consumer cerrado")


async def _process_single(observable: str, analyzers: list | None, tlp: str):
    """Analiza un observable, convierte a STIX 2.1 y publica."""
    try:
        result = await _analyze_and_wait(observable, analyzers=analyzers, tlp=tlp)

        # ── Conversión a STIX 2.1 antes de publicar ──────────────
        if STIX_OUTPUT:
            try:
                stix_bundle = job_to_stix_bundle(result)
                payload = {
                    "stix_bundle": stix_bundle,
                    "meta": {
                        "observable": observable,
                        "job_id": result.get("id") or result.get("job_id"),
                        "status": result.get("status"),
                        "analyzer_count": len(result.get("analyzer_reports", [])),
                    },
                }
            except Exception as exc:
                log.warning(
                    "STIX conversion falló para %s, publicando raw: %s",
                    observable, exc,
                )
                payload = result
        else:
            payload = result

        _publish_result(KAFKA_OUTPUT_TOPIC, observable, payload)
        log.info("✓ %s → job %s (stix=%s)", observable, result.get("job_id", "?"), STIX_OUTPUT)
    except IntelOwlClientException as exc:
        log.error("Intel-Owl error para %s: %s", observable, exc)
    except Exception as exc:
        log.exception("Error inesperado procesando %s: %s", observable, exc)


# ──────────────────────────────────────────────────────────────────────
#  Pydantic models (API HTTP)
# ──────────────────────────────────────────────────────────────────────
class AnalysisRequest(BaseModel):
    observable: str = Field(..., description="IP, dominio, hash, URL u observable genérico")
    analyzers: List[str] = Field(default_factory=list, description="Lista de analyzers (vacío=todos)")
    connectors: List[str] = Field(default_factory=list, description="Lista de connectors (vacío=todos)")
    tlp: str = Field(default="CLEAR", description="TLP: CLEAR, GREEN, AMBER, RED")
    wait: bool = Field(default=False, description="Esperar resultado completo (polling)")


class BatchRequest(BaseModel):
    observables: List[str]
    analyzers: List[str] = Field(default_factory=list)
    tlp: str = "CLEAR"
    wait: bool = False


class AnalysisResponse(BaseModel):
    job_id: int | None = None
    status: str
    result: Dict[str, Any] | None = None
    stix_bundle: Dict[str, Any] | None = None


# ──────────────────────────────────────────────────────────────────────
#  FastAPI app
# ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _owl, _semaphore, _producer, _consumer_task

    # Startup
    if not INTELOWL_API_KEY:
        log.critical("INTELOWL_API_KEY no configurada — todas las peticiones fallarán con 401")
    _owl = _build_owl_client()
    _semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    _producer = Producer({"bootstrap.servers": KAFKA_BROKER})
    _consumer_task = asyncio.create_task(_kafka_consumer_loop())
    log.info(
        "IntelOwl client arrancado — url=%s concurrency=%d",
        INTELOWL_URL,
        MAX_CONCURRENCY,
    )

    yield

    # Shutdown
    _shutdown_event.set()
    if _consumer_task:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass
    if _producer:
        _producer.flush(timeout=5)
    log.info("IntelOwl client detenido")


app = FastAPI(
    title="Skyfall IntelOwl Client",
    description="Cliente asíncrono de alto rendimiento para Intel-Owl",
    lifespan=lifespan,
)


# ── Endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "intelowl-client"}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(req: AnalysisRequest):
    """Solicita análisis de un observable a Intel-Owl."""
    try:
        if req.wait:
            result = await _analyze_and_wait(
                req.observable, analyzers=req.analyzers or None, tlp=req.tlp
            )
            stix = None
            if STIX_OUTPUT:
                try:
                    stix = job_to_stix_bundle(result)
                except Exception as exc:
                    log.warning("STIX conversion falló en /analyze: %s", exc)
            return AnalysisResponse(
                job_id=result.get("job_id") or result.get("id"),
                status=result.get("status", "unknown"),
                result=result,
                stix_bundle=stix,
            )
        else:
            resp = await _analyze_observable(
                req.observable,
                analyzers=req.analyzers or None,
                connectors=req.connectors or None,
                tlp=req.tlp,
            )
            return AnalysisResponse(
                job_id=resp.get("job_id"),
                status=resp.get("status", "accepted"),
            )
    except IntelOwlClientException as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/analyze/batch")
async def analyze_batch(req: BatchRequest):
    """Envía análisis concurrentes para múltiples observables."""
    analyzers = req.analyzers or None
    tasks = [
        _analyze_and_wait(obs, analyzers=analyzers, tlp=req.tlp) if req.wait
        else _analyze_observable(obs, analyzers=analyzers, tlp=req.tlp)
        for obs in req.observables
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    output = []
    for obs, res in zip(req.observables, results):
        if isinstance(res, Exception):
            output.append({"observable": obs, "error": str(res)})
        else:
            output.append({"observable": obs, **res})
    return output


@app.get("/job/{job_id}")
async def get_job(job_id: int):
    """Consulta el estado de un job existente."""
    try:
        loop = asyncio.get_running_loop()
        job = await loop.run_in_executor(
            None, lambda: _owl.get_job_by_id(job_id)  # type: ignore[union-attr]
        )
        return job
    except IntelOwlClientException as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/healthcheck/analyzer/{name}")
async def analyzer_healthcheck(name: str):
    """Healthcheck de un analyzer específico de Intel-Owl."""
    try:
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(
            None, lambda: _owl.analyzer_healthcheck(name)  # type: ignore[union-attr]
        )
        return {"analyzer": name, "healthy": ok}
    except IntelOwlClientException as exc:
        raise HTTPException(status_code=502, detail=str(exc))
