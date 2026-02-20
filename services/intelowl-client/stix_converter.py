"""
Skyfall-CTI · Intel-Owl → STIX 2.1 Converter
==============================================
Transforma las respuestas de la API de Intel-Owl (job result con
analyzer_reports) en STIX 2.1 Bundles válidos.

Estructura del STIX Bundle generado:
  ┌─ Identity           → Skyfall-CTI como fuente
  ├─ SCO observable     → ipv4-addr / ipv6-addr / domain-name / url / file
  ├─ Indicator          → patrón STIX del observable (siempre)
  ├─ Report             → agrupa todo el análisis Intel-Owl
  ├─ Note (×N)          → uno por cada analyzer_report con datos
  ├─ Malware            → si algún analyzer detecta malware
  ├─ Relationship (×N)  → vincula los objetos entre sí
  └─ MarkingDefinition  → TLP mapping
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import stix2

log = logging.getLogger("intelowl-client.stix")

# ──────────────────────────────────────────────────────────────────────
#  Constantes
# ──────────────────────────────────────────────────────────────────────

# Identidad Skyfall-CTI (determinística para que sea siempre la misma)
SKYFALL_IDENTITY_ID = "identity--" + str(
    uuid.uuid5(uuid.NAMESPACE_URL, "https://skyfall-cti.local")
)

# Mapeo TLP → STIX 2.1 marking-definition IDs (estándar OASIS)
TLP_MAP = {
    "CLEAR": stix2.TLP_WHITE.id,
    "WHITE": stix2.TLP_WHITE.id,
    "GREEN": stix2.TLP_GREEN.id,
    "AMBER": stix2.TLP_AMBER.id,
    "RED":   stix2.TLP_RED.id,
}

# Clasificaciones que indican "malicioso" en analyzer reports
_MALICIOUS_KEYWORDS = frozenset({
    "malicious", "malware", "trojan", "ransomware", "phishing",
    "botnet", "c2", "command and control", "exploit", "apt",
    "suspicious", "threat", "compromised",
})


# ──────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────

def _deterministic_id(type_: str, seed: str) -> str:
    """Genera un ID STIX determinístico a partir del tipo y una semilla."""
    return f"{type_}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _classify_observable(value: str) -> str:
    """Clasifica un observable en ip/domain/url/hash/generic."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^(?:https?|ftps?|tcp)://", value, re.IGNORECASE):
        return "url"
    if re.match(r"^[a-fA-F\d]{32}$", value) or \
       re.match(r"^[a-fA-F\d]{40}$", value) or \
       re.match(r"^[a-fA-F\d]{64}$", value):
        return "hash"
    if re.match(r"^(\.)?[a-z\d\-]{1,63}(\.[a-z\d\-]{1,63})+$", value):
        return "domain"
    return "generic"


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _hash_length_to_algo(value: str) -> Tuple[str, str]:
    """Retorna (stix_field, nombre_algoritmo) según longitud del hash."""
    clean = value.lower().strip()
    length = len(clean)
    if length == 32:
        return "MD5", clean
    elif length == 40:
        return "SHA-1", clean
    elif length == 64:
        return "SHA-256", clean
    return "MD5", hashlib.md5(clean.encode()).hexdigest()


def _scan_for_malicious(analyzer_reports: List[Dict]) -> Tuple[bool, List[str]]:
    """
    Recorre los analyzer_reports buscando indicios de maliciosidad.
    Retorna (is_malicious, list[razones]).
    """
    reasons = []
    for report in analyzer_reports:
        if report.get("status") != "SUCCESS":
            continue
        report_data = report.get("report", {})
        if not isinstance(report_data, dict):
            continue

        analyzer_name = report.get("name", "unknown")
        report_str = json.dumps(report_data).lower()

        # Búsqueda directa de campos "malicious"
        for key in ("malicious", "is_malicious", "verdict", "classification",
                     "threat_label", "threat_type", "category"):
            val = report_data.get(key)
            if val is None:
                continue
            val_str = str(val).lower()
            if val_str in ("true", "1") or any(kw in val_str for kw in _MALICIOUS_KEYWORDS):
                reasons.append(f"{analyzer_name}: {key}={val}")

        # VirusTotal: positives / total
        positives = report_data.get("positives") or report_data.get("positive_detections")
        total = report_data.get("total") or report_data.get("total_scans")
        if positives and total:
            try:
                ratio = int(positives) / max(int(total), 1)
                if ratio > 0.1:
                    reasons.append(f"{analyzer_name}: {positives}/{total} detections")
            except (ValueError, TypeError):
                pass

        # AbuseIPDB: abuse_confidence_score
        score = report_data.get("abuse_confidence_score") or report_data.get("abuseConfidenceScore")
        if score is not None:
            try:
                if int(score) >= 50:
                    reasons.append(f"{analyzer_name}: abuse_score={score}")
            except (ValueError, TypeError):
                pass

        # Campos de scores genéricos
        for score_key in ("risk_score", "score", "threat_score", "reputation"):
            s = report_data.get(score_key)
            if s is not None:
                try:
                    s_val = float(s)
                    # Heurística: scores >=50 (sobre 100) o >=5 (sobre 10)
                    if (s_val >= 50) or (0 < s_val <= 10 and s_val >= 5):
                        reasons.append(f"{analyzer_name}: {score_key}={s}")
                except (ValueError, TypeError):
                    pass

    return bool(reasons), reasons


# ──────────────────────────────────────────────────────────────────────
#  Constructores de SCOs (STIX Cyber Observables)
# ──────────────────────────────────────────────────────────────────────

def _build_sco(observable_name: str, classification: str) -> stix2.base._STIXBase:
    """Construye el SCO apropiado según la clasificación."""
    if classification == "ip":
        if _is_ipv6(observable_name):
            return stix2.IPv6Address(value=observable_name)
        return stix2.IPv4Address(value=observable_name)

    if classification == "domain":
        return stix2.DomainName(value=observable_name)

    if classification == "url":
        return stix2.URL(value=observable_name)

    if classification == "hash":
        algo, digest = _hash_length_to_algo(observable_name)
        hashes = {algo: digest}
        return stix2.File(hashes=hashes)

    # generic → artifact con payload_bin del valor (base64-encoded, requerido por STIX 2.1)
    return stix2.Artifact(
        payload_bin=base64.b64encode(observable_name.encode("utf-8")).decode("ascii"),
        allow_custom=True,
    )


def _build_indicator_pattern(observable_name: str, classification: str) -> str:
    """Genera el patrón STIX para el indicator."""
    if classification == "ip":
        if _is_ipv6(observable_name):
            return f"[ipv6-addr:value = '{observable_name}']"
        return f"[ipv4-addr:value = '{observable_name}']"

    if classification == "domain":
        return f"[domain-name:value = '{observable_name}']"

    if classification == "url":
        # Escapar comillas simples en URL
        safe_url = observable_name.replace("'", "\\'")
        return f"[url:value = '{safe_url}']"

    if classification == "hash":
        algo, digest = _hash_length_to_algo(observable_name)
        algo_field = algo.replace("-", "").lower()
        # map to STIX pattern field: MD5, 'SHA-1', 'SHA-256'
        return f"[file:hashes.'{algo}' = '{digest}']"

    return f"[artifact:payload_bin = '{observable_name}']"


# ──────────────────────────────────────────────────────────────────────
#  Conversión principal
# ──────────────────────────────────────────────────────────────────────

def job_to_stix_bundle(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convierte un resultado de `get_job_by_id()` de Intel-Owl en un
    STIX 2.1 Bundle serializable a JSON.

    Estructura del job de Intel-Owl (campos relevantes):
    {
        "id": 174,
        "observable_name": "dns.google.com",
        "observable_classification": "domain",  # ip/domain/url/hash/generic
        "md5": "f9bc35...",
        "status": "reported_without_fails",
        "tlp": "AMBER",
        "received_request_time": "2023-05-31T08:19:03.256003",
        "finished_analysis_time": "2023-05-31T08:19:04.484684",
        "process_time": 0.23,
        "analyzers_requested": ["Classic_DNS", "AbuseIPDB"],
        "analyzer_reports": [
            {
                "name": "Classic_DNS",
                "process_time": 0.07,
                "report": { ... },       # ← contenido varía por analyzer
                "status": "SUCCESS",
                "errors": [],
                "start_time": "...",
                "end_time": "...",
                "type": "analyzer"
            },
            ...
        ],
        "connector_reports": [...],
        ...
    }

    Returns:
        Dict serializable del STIX 2.1 Bundle.
    """
    objects: List[stix2.base._STIXBase] = []
    now = _now_iso()

    # ── 0. Metadatos del job ─────────────────────────────────────────
    job_id = job.get("id") or job.get("job_id") or 0
    observable_name = (
        job.get("observable_name") or job.get("name") or
        job.get("file_name") or str(job_id)
    )
    observable_classification = job.get("observable_classification") or ""
    if not observable_classification:
        observable_classification = _classify_observable(observable_name)

    tlp = (job.get("tlp") or "CLEAR").upper()
    marking_refs = [TLP_MAP.get(tlp, stix2.TLP_WHITE.id)]

    analyzer_reports = job.get("analyzer_reports", [])
    received_time = job.get("received_request_time") or now
    finished_time = job.get("finished_analysis_time") or now

    # ── 1. Identity de Skyfall-CTI ───────────────────────────────────
    identity = stix2.Identity(
        id=SKYFALL_IDENTITY_ID,
        name="Skyfall-CTI",
        identity_class="system",
        description="Plataforma CTI proactiva y multidimensional",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 1, 1, tzinfo=timezone.utc),
        object_marking_refs=marking_refs,
    )
    objects.append(identity)

    # ── 2. SCO del observable ────────────────────────────────────────
    sco = _build_sco(observable_name, observable_classification)
    objects.append(sco)

    # ── 3. Indicator ─────────────────────────────────────────────────
    is_malicious, malicious_reasons = _scan_for_malicious(analyzer_reports)

    indicator_labels = ["intelowl-enrichment"]
    if is_malicious:
        indicator_labels.append("malicious")

    pattern = _build_indicator_pattern(observable_name, observable_classification)
    indicator = stix2.Indicator(
        id=_deterministic_id("indicator", f"intelowl-job-{job_id}-{observable_name}"),
        name=f"IntelOwl [{observable_classification}] {observable_name}",
        description=(
            f"Análisis Intel-Owl job #{job_id}. "
            f"Analyzers ejecutados: {len(analyzer_reports)}. "
            + (f"Indicios maliciosos: {'; '.join(malicious_reasons)}" if is_malicious
               else "Sin indicios claros de maliciosidad.")
        ),
        pattern=pattern,
        pattern_type="stix",
        valid_from=received_time,
        labels=indicator_labels,
        created_by_ref=identity.id,
        object_marking_refs=marking_refs,
        confidence=85 if is_malicious else 40,
        allow_custom=True,
    )
    objects.append(indicator)

    # Relación: indicator → based-on → SCO
    objects.append(stix2.Relationship(
        source_ref=indicator.id,
        target_ref=sco.id,
        relationship_type="based-on",
        created_by_ref=identity.id,
        object_marking_refs=marking_refs,
    ))

    # ── 4. Notes por cada analyzer_report ────────────────────────────
    for ar in analyzer_reports:
        ar_name = ar.get("name", "unknown-analyzer")
        ar_status = ar.get("status", "UNKNOWN")
        ar_report = ar.get("report", {})
        ar_errors = ar.get("errors", [])
        ar_start = ar.get("start_time")
        ar_end = ar.get("end_time")

        # Construir contenido legible
        content_parts = [
            f"**Analyzer:** {ar_name}",
            f"**Status:** {ar_status}",
        ]
        if ar_start and ar_end:
            content_parts.append(f"**Periodo:** {ar_start} → {ar_end}")
        if ar.get("process_time") is not None:
            content_parts.append(f"**Tiempo de proceso:** {ar['process_time']}s")
        if ar_errors:
            content_parts.append(f"**Errores:** {json.dumps(ar_errors, default=str)}")

        # Truncar el report si es muy grande (>32KB) para no explotar el bundle
        report_json = json.dumps(ar_report, indent=2, default=str)
        if len(report_json) > 32768:
            report_json = report_json[:32768] + "\n... [truncado]"

        content_parts.append(f"\n**Resultado:**\n```json\n{report_json}\n```")

        note = stix2.Note(
            id=_deterministic_id("note", f"intelowl-{job_id}-{ar_name}"),
            abstract=f"Intel-Owl: {ar_name} ({ar_status})",
            content="\n".join(content_parts),
            object_refs=[indicator.id, sco.id],
            created_by_ref=identity.id,
            object_marking_refs=marking_refs,
            allow_custom=True,
        )
        objects.append(note)

    # ── 5. Malware (si se detecta) ───────────────────────────────────
    if is_malicious:
        malware = stix2.Malware(
            id=_deterministic_id("malware", f"intelowl-malware-{job_id}-{observable_name}"),
            name=f"Posible amenaza: {observable_name}",
            description=(
                f"Identificado como potencialmente malicioso por Intel-Owl "
                f"(job #{job_id}). Razones: {'; '.join(malicious_reasons)}"
            ),
            is_family=False,
            malware_types=["unknown"],
            created_by_ref=identity.id,
            object_marking_refs=marking_refs,
        )
        objects.append(malware)

        # Relación: indicator → indicates → malware
        objects.append(stix2.Relationship(
            source_ref=indicator.id,
            target_ref=malware.id,
            relationship_type="indicates",
            created_by_ref=identity.id,
            object_marking_refs=marking_refs,
        ))

    # ── 6. Report STIX (agrupa todo el análisis) ─────────────────────
    all_object_refs = [obj.id for obj in objects if obj.id != identity.id]
    report = stix2.Report(
        id=_deterministic_id("report", f"intelowl-report-{job_id}"),
        name=f"Intel-Owl Analysis #{job_id}: {observable_name}",
        description=(
            f"Resultado completo del análisis Intel-Owl para "
            f"{observable_classification} '{observable_name}'. "
            f"Estado: {job.get('status', 'unknown')}. "
            f"Analyzers: {len(analyzer_reports)}."
        ),
        published=finished_time,
        report_types=["threat-report"],
        object_refs=all_object_refs,
        created_by_ref=identity.id,
        object_marking_refs=marking_refs,
        allow_custom=True,
        # Propiedades custom de Skyfall
        x_skyfall_job_id=job_id,
        x_skyfall_process_time=job.get("process_time"),
        x_skyfall_status=job.get("status"),
        x_skyfall_tlp=tlp,
        x_skyfall_analyzers_requested=job.get("analyzers_requested", []),
    )
    objects.append(report)

    # ── 7. Bundle ────────────────────────────────────────────────────
    bundle = stix2.Bundle(
        objects=objects,
        allow_custom=True,
    )

    return json.loads(bundle.serialize())
