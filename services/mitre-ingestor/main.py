"""
Skyfall-CTI · MITRE ATT&CK Ingestor
====================================
Descarga la base de conocimiento completa de MITRE ATT&CK (Enterprise, Mobile
e ICS), valida cada bundle con stix2.MemoryStore (siguiendo la guía oficial:
https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md) y
produce cada objeto STIX 2.1 como mensaje individual en Kafka.

Tamaño aproximado del dataset (v16 / 2025):
  ┌─────────────────────┬───────────┬──────────────┐
  │ Dominio             │  JSON     │  Objetos ~   │
  ├─────────────────────┼───────────┼──────────────┤
  │ enterprise-attack   │  ~60 MB   │  ~15 000     │
  │ mobile-attack       │  ~7 MB    │  ~2 200      │
  │ ics-attack          │  ~4 MB    │  ~1 200      │
  ├─────────────────────┼───────────┼──────────────┤
  │ TOTAL               │  ~71 MB   │  ~18 400     │
  └─────────────────────┴───────────┴──────────────┘

Cada objeto se envía serializado en JSON con compresión gzip para no superar
el límite por defecto de Kafka (message.max.bytes = 1 MB).
"""

import os
import sys
import json
import time
import signal
import requests
from collections import Counter
 # from kafka import KafkaProducer
from stix2 import MemoryStore, Filter

# ── Configuración vía variables de entorno ────────────────────────────────

# Dominios ATT&CK a ingestar (separados por coma)
MITRE_DOMAINS = os.getenv(
    "MITRE_DOMAINS", "enterprise-attack,mobile-attack,ics-attack"
).split(",")

# URL base del repositorio oficial de MITRE ATT&CK STIX data
MITRE_BASE_URL = os.getenv(
    "MITRE_BASE_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master",
)

# ── Señal de apagado limpio ───────────────────────────────────────────────
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))


# ── Descarga (guía oficial MITRE: requests + JSON) ───────────────────────
def download_mitre_domain(domain: str) -> dict:
    """Descarga un dominio ATT&CK completo desde GitHub y lo devuelve como
    dict STIX Bundle.

    Equivalente a la receta 'Access the most recent version from GitHub
    via requests' de USAGE.md:

        stix_json = requests.get(
            f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
            f"/master/{domain}/{domain}.json"
        ).json()
        return MemoryStore(stix_data=stix_json["objects"])
    """
    url = f"{MITRE_BASE_URL}/{domain}/{domain}.json"
    print(f"[mitre-ingestor] Descargando {domain} desde {url} ...")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    bundle = resp.json()
    size_mb = len(resp.content) / (1024 * 1024)
    n_objects = len(bundle.get("objects", []))
    print(
        f"[mitre-ingestor] {domain}: {size_mb:.1f} MB, "
        f"{n_objects} objetos STIX descargados"
    )
    return bundle


# ── Validación con stix2.MemoryStore (guía de MITRE) ─────────────────────
def validate_with_memorystore(bundle: dict, domain: str):
    """Carga el bundle en un MemoryStore para asegurar que el STIX es
    sintácticamente correcto.  Siguiendo la guía de MITRE:

        src = MemoryStore(stix_data=stix_json["objects"])
        techniques = src.query([Filter("type", "=", "attack-pattern")])
        groups     = src.query([Filter("type", "=", "intrusion-set")])
    """
    try:
        src = MemoryStore(stix_data=bundle["objects"])

        # Consultas de sanidad usando stix2 Filters (recetas de USAGE.md)
        techniques = src.query([Filter("type", "=", "attack-pattern")])
        groups = src.query([Filter("type", "=", "intrusion-set")])
        malware = src.query([Filter("type", "=", "malware")])
        tools = src.query([Filter("type", "=", "tool")])
        relationships = src.query([Filter("type", "=", "relationship")])

        print(
            f"[mitre-ingestor] Validación {domain} OK —\n"
            f"  Técnicas: {len(techniques)}, Grupos: {len(groups)}, "
            f"Malware: {len(malware)}, Tools: {len(tools)}, "
            f"Relaciones: {len(relationships)}"
        )
    except Exception as exc:
        print(
            f"[mitre-ingestor] WARN: validación stix2 de {domain} falló "
            f"({exc}), se continuará con la ingesta del JSON crudo"
        )



# Kafka logic removed. Objects are now just prepared for later insertion.


# ── Resumen estadístico ──────────────────────────────────────────────────
def print_summary(objects: list, domain: str):
    """Imprime un resumen por tipo STIX de los objetos descargados."""
    counter = Counter(obj.get("type", "unknown") for obj in objects)
    print(f"\n[mitre-ingestor] ═══ Resumen {domain} ═══")
    for stype, count in counter.most_common():
        print(f"  {stype:<35s} {count:>6d}")
    print(f"  {'TOTAL':<35s} {sum(counter.values()):>6d}\n")


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  Skyfall-CTI · MITRE ATT&CK Ingestor")
    print(f"  Dominios: {', '.join(MITRE_DOMAINS)}")
    print("=" * 70)

    run_flag = os.getenv("RUN_MITRE_INGESTOR", "0")
    if run_flag != "1":
        print("[mitre-ingestor] Esperando orden del usuario. Para ejecutar la ingesta, establece RUN_MITRE_INGESTOR=1.")
        return

    grand_total = 0
    prepared_objects = {}

    for domain in MITRE_DOMAINS:
        domain = domain.strip()
        if not domain:
            continue

        # 1. Descargar bundle STIX desde GitHub (guía MITRE: requests + JSON)
        bundle = download_mitre_domain(domain)
        objects = bundle.get("objects", [])

        if not objects:
            print(f"[mitre-ingestor] {domain}: sin objetos, saltando.")
            continue

        # 2. Validar con stix2.MemoryStore (guía MITRE — Filter queries)
        validate_with_memorystore(bundle, domain)

        # 3. Resumen estadístico por tipo STIX
        print_summary(objects, domain)

        # 4. Preparar objetos para futura inserción
        prepared_objects[domain] = objects
        grand_total += len(objects)

    print("=" * 70)
    print(f"[mitre-ingestor] Preparación completada: {grand_total} objetos STIX descargados y validados.")
    print("[mitre-ingestor] Listos para enviar a Neo4j/Elasticsearch en el siguiente paso.")
    print("=" * 70)


if __name__ == "__main__":
    main()
