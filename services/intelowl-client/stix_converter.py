"""
Skyfall-CTI · STIX Converter (bridge)
======================================
Punto de entrada para la conversión de resultados IntelOwl a STIX 2.1.
Detecta el tipo de observable y delega al converter específico.

Actualmente soportado:
  - IP (IPv4/IPv6) → stix_converter_ip.job_to_stix_bundle
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict

from stix_converter_ip import job_to_stix_bundle as _ip_bundle

log = logging.getLogger("stix_converter")


def job_to_stix_bundle(job_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convierte un job IntelOwl completo a un STIX 2.1 Bundle (dict).

    Determina el tipo de observable y enruta al converter adecuado.
    Extensible: añadir más converters para dominios, hashes, URLs, etc.
    """
    observable = (
        job_result.get("observable_name")
        or job_result.get("observable", {}).get("value", "")
        or job_result.get("name", "unknown")
    )

    # Detectar tipo de observable
    obs_type = _detect_observable_type(observable)

    if obs_type == "ip":
        return _ip_bundle(job_result)
    else:
        log.warning(
            "No STIX converter for observable type '%s' (%s), "
            "returning empty bundle",
            obs_type, observable,
        )
        return {
            "type": "bundle",
            "id": f"bundle--empty-{observable}",
            "objects": [],
        }


def _detect_observable_type(value: str) -> str:
    """Detecta si el observable es IP, dominio, hash, URL, etc."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if value.startswith(("http://", "https://")):
        return "url"

    # Hash: md5 (32), sha1 (40), sha256 (64)
    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return "hash"

    # Por defecto asumimos dominio
    if "." in value:
        return "domain"

    return "unknown"
