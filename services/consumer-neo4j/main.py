"""
Skyfall-CTI · Consumer Neo4j  —  Universal Correlation Engine
================================================================
Kafka consumer → STIX 2.1 ingestion + deep correlation in Neo4j.

Responsabilidades:
  1. Consume STIX bundles/objetos de los topics de Kafka configurados.
  2. MERGE (upsert) todos los objetos STIX como nodos Neo4j.
  3. Crea las relaciones STIX explícitas del bundle.
  4. Genera relaciones implícitas (created_by_ref, object_refs, …).
  5. **Motor de correlación universal** — NO solo MITRE:

  ─── MITRE ATT&CK ────────────────────────────────────────────
  C01  Malware → MITRE Software name/alias matching.
  C02  Technique IDs (Txxxx.xxx) extraídos de texto libre.
  C03  Vulnerability → técnicas MITRE que la explotan.
  C04  Propagación: Indicator → Malware → MITRE → Actor.

  ─── IOC / Observable ────────────────────────────────────────
  C05  Deduplicación de observables con mismo valor + tipo.
  C06  Indicator pattern parsing → link a SCOs existentes.
  C07  Extracción de IOCs de texto libre (IPs, dominios, hashes,
       emails, URLs, CVEs, BTC wallets) → link a SCOs.

  ─── Infraestructura ─────────────────────────────────────────
  C08  Infrastructure compartida entre actores/campañas.
  C09  Malware → misma infraestructura C2 (resolves-to, hosts).

  ─── Threat Actor / Campaign ─────────────────────────────────
  C10  TTP overlap: actores que comparten ≥N técnicas.
  C11  Campañas con IOCs/malware superpuestos → RELATED_CAMPAIGN.
  C12  Indicator → Vulnerability → Actor attribution chain.

  ─── CVE / Vulnerability ─────────────────────────────────────
  C13  CVE cross-ref: malware/indicators que mencionan CVEs.
  C14  CVE severity propagation: CVE crítico → IOCs asociados.
  C15  Course-of-action → vulnerabilities/techniques linkage.

  ─── Report / Intelligence ───────────────────────────────────
  C16  Co-occurrence: objetos que aparecen en el mismo bundle/report.
  C17  Temporal proximity: objetos creados en ventana temporal.

  ─── Identity / Targeting ────────────────────────────────────
  C18  Sector/victim targeting: actores atacando mismo sector.

  ─── Geo-Intelligence ────────────────────────────────────────
  C19  Geo-Clustering: actores/campañas que atacan la misma región.

Confidence Scoring:
  Cada relación auto_correlated lleva un campo `confidence` (0-100)
  que indica la fiabilidad de la correlación:
    100  Coincidencia exacta de hash/observable (C05, C06)
     90  Referencia explícita a CVE/Técnica (C02, C03, C13)
     85  Matching de nombre/alias de malware (C01)
     80  Propagación por cadena corta (C04, C12)
     75  Infraestructura compartida (C08, C09)
     70  IOC mencionado en texto libre (C07)
     65  Overlap de TTPs/IOCs (C10, C11)
     60  Co-ocurrencia en mismo bundle/report (C16)
     55  Mitigación implícita (C14, C15)
     50  Sector targeting compartido (C18)
     45  Geo-clustering regional (C19)
     30  Proximidad temporal (C17)

Esquema Neo4j (compatible con mitre-ingestor):
  - Label primario: :StixObject   (todos los nodos)
  - Label dinámico: :Attack_pattern, :Malware, :Ipv4_addr, etc.
  - Propiedades: id, type, name, description, external_id, ...
  - Relaciones: tipos dinámicos en UPPER_SNAKE (BASED_ON, INDICATES, USES…)
  - Relaciones auto-generadas: siempre llevan {auto_correlated: true,
        correlation_type: '<strategy_id>', matched_at: datetime()}
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from confluent_kafka import Consumer, KafkaError, KafkaException
from neo4j import GraphDatabase

# ══════════════════════════════════════════════════════════════════════
#  Configuración (env vars — definidas en docker-compose.yml)
# ══════════════════════════════════════════════════════════════════════

KAFKA_BROKER   = os.getenv("KAFKA_BROKER", "kafka:29092")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "cg-neo4j")
KAFKA_TOPICS   = os.getenv(
    "KAFKA_TOPICS",
    "stix.cve,stix.osint,stix.telegram,stix.social,stix.dumps,stix.mitre,enrichment.results",
).split(",")
NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "skyfall2026")
BATCH_SIZE     = int(os.getenv("BATCH_SIZE", "100"))
POLL_TIMEOUT   = float(os.getenv("POLL_TIMEOUT", "1.0"))
CORRELATE      = os.getenv("CORRELATE", "true").lower() in ("1", "true", "yes")
# Umbral mínimo de TTP overlap para vincular actores (C10)
TTP_OVERLAP_THRESHOLD = int(os.getenv("TTP_OVERLAP_MIN", "3"))
# Ventana temporal para correlación de proximidad (C17), en días
TEMPORAL_WINDOW_DAYS  = int(os.getenv("TEMPORAL_WINDOW_DAYS", "7"))

# ══════════════════════════════════════════════════════════════════════
#  Logging
# ══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
)
log = logging.getLogger("consumer-neo4j")

# ══════════════════════════════════════════════════════════════════════
#  Shutdown controlado
# ══════════════════════════════════════════════════════════════════════

_running = True


def _shutdown(signum, frame):
    global _running
    log.info("Señal de parada recibida, terminando batch actual…")
    _running = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

# ══════════════════════════════════════════════════════════════════════
#  Regex patterns — IOC extraction from free text
# ══════════════════════════════════════════════════════════════════════

# MITRE Technique IDs: T1059, T1059.001
TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# CVE IDs: CVE-2024-1234
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)

# IPv4 (excluye rangos privados obvios como 0.0.0.0, 127.x, 10.x)
IPV4_RE = re.compile(
    r"\b(?!(?:0|127|10|255)\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# IPv6 (simplificado — al menos 2 grupos hex con :)
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")

# Dominios (excluye extensiones de archivo comunes)
DOMAIN_RE = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|"
    r"onion|bit|dev|me|co|uk|de|fr|jp|kr|in|br|za|ir))\b",
    re.IGNORECASE,
)

# URLs completas
URL_RE = re.compile(
    r"(https?://[^\s\"'<>\]\)}{,]+)", re.IGNORECASE
)

# Hashes: MD5, SHA1, SHA256
MD5_RE    = re.compile(r"\b([a-fA-F0-9]{32})\b")
SHA1_RE   = re.compile(r"\b([a-fA-F0-9]{40})\b")
SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")

# Emails
EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)

# Bitcoin wallets  (P2PKH / P2SH / Bech32)
BTC_RE = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b")

# STIX indicator pattern value extraction:  [ipv4-addr:value = '1.2.3.4']
STIX_PATTERN_VALUE_RE = re.compile(
    r"\[([a-z0-9\-]+):(?:value|hashes\.(?:MD5|SHA-1|SHA-256))\s*=\s*'([^']+)'\]",
    re.IGNORECASE,
)

# ══════════════════════════════════════════════════════════════════════
#  Confidence Scoring — pesos por estrategia de correlación
# ══════════════════════════════════════════════════════════════════════

CONFIDENCE_SCORES: Dict[str, int] = {
    # Coincidencia exacta de observable / hash
    "C05_dedup":              100,
    "C06_pattern_sco":        100,
    # Referencia explícita a ID de técnica / CVE
    "C02_technique_extraction": 90,
    "C03_vuln_mitre":           90,
    "C13_cve_crossref":         90,
    # Matching nombre/alias
    "C01_malware_mitre":        85,
    # Propagación por cadena
    "C04_malware_propagation":  80,
    "C12_ind_vuln_actor":       80,
    # Infraestructura compartida
    "C08_shared_infra":         75,
    "C09_malware_c2":           75,
    # IOC en texto libre
    "C07_text_ioc":             70,
    # Overlap de TTPs / IOCs
    "C10_ttp_overlap":          65,
    "C11_campaign_overlap":     65,
    # Co-ocurrencia en bundle
    "C16_co_occurrence":        60,
    # Mitigación implícita
    "C14_cve_severity":         55,
    "C15_coa_vuln":             55,
    "C15_coa_technique":        55,
    # Sector targeting
    "C18_sector_targeting":     50,
    # Geo-clustering
    "C19_geo_cluster":          45,
    # Proximidad temporal (hipótesis)
    "C17_temporal":             30,
}

# ══════════════════════════════════════════════════════════════════════
#  Domain Blacklist — filtrar dominios legítimos de C07
# ══════════════════════════════════════════════════════════════════════

DOMAIN_BLACKLIST: Set[str] = {
    # Buscadores y redes sociales
    "google.com", "www.google.com", "google.co.uk", "google.de",
    "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "reddit.com", "youtube.com", "tiktok.com",
    "pinterest.com", "snapchat.com", "whatsapp.com", "telegram.org",
    # Big Tech infra
    "microsoft.com", "apple.com", "amazon.com", "amazonaws.com",
    "azure.com", "cloudflare.com", "akamai.com", "fastly.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "windows.net", "office.com", "office365.com", "live.com",
    "outlook.com", "hotmail.com", "msn.com",
    # CDNs y servicios comunes
    "cloudfront.net", "cdn.jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "jquery.com", "googleapis.com",
    # Seguridad / CTI (fuentes, no IOCs)
    "virustotal.com", "shodan.io", "censys.io", "urlscan.io",
    "abuseipdb.com", "otx.alienvault.com", "intelowl.com",
    "mitre.org", "attack.mitre.org", "cve.org", "nvd.nist.gov",
    "nist.gov", "cisa.gov", "cert.org",
    # Otros legítimos
    "wikipedia.org", "en.wikipedia.org", "archive.org",
    "w3.org", "iana.org", "icann.org",
    "example.com", "example.org", "example.net",
    "localhost", "localhost.localdomain",
}


# ══════════════════════════════════════════════════════════════════════
#  Helpers — IOC extraction from free text  (used by C02, C07, C13)
# ══════════════════════════════════════════════════════════════════════


def _collect_text(obj: Dict) -> str:
    """Concatena todos los campos de texto libre de un objeto STIX."""
    parts: List[str] = []
    for field in (
        "name", "description", "abstract", "content", "pattern",
        "x_skyfall_summary", "goal",
    ):
        val = obj.get(field)
        if val and isinstance(val, str):
            parts.append(val)
    return " ".join(parts)


def _extract_iocs_from_text(text: str) -> Dict[str, Set[str]]:
    """
    Extrae IOCs de texto libre y los devuelve clasificados.
    Retorna dict: tipo_sco → set de valores.
    """
    iocs: Dict[str, Set[str]] = {
        "ipv4-addr": set(),
        "ipv6-addr": set(),
        "domain-name": set(),
        "url": set(),
        "email-addr": set(),
        "file:md5": set(),
        "file:sha1": set(),
        "file:sha256": set(),
        "vulnerability": set(),   # CVE-XXXX-XXXXX
        "technique": set(),       # Txxxx(.xxx)
        "btc-wallet": set(),
    }

    # Orden importa: SHA256 antes que SHA1 antes que MD5
    for h in SHA256_RE.findall(text):
        iocs["file:sha256"].add(h.lower())
    # Excluir SHA256 matches de SHA1 check
    text_no_sha256 = SHA256_RE.sub("", text)
    for h in SHA1_RE.findall(text_no_sha256):
        iocs["file:sha1"].add(h.lower())
    text_no_sha = SHA1_RE.sub("", text_no_sha256)
    for h in MD5_RE.findall(text_no_sha):
        iocs["file:md5"].add(h.lower())

    for ip in IPV4_RE.findall(text):
        iocs["ipv4-addr"].add(ip)
    for ip in IPV6_RE.findall(text):
        iocs["ipv6-addr"].add(ip)
    for d in DOMAIN_RE.findall(text):
        d_lower = d.lower()
        if d_lower not in DOMAIN_BLACKLIST:
            iocs["domain-name"].add(d_lower)
    for u in URL_RE.findall(text):
        iocs["url"].add(u)
    for e in EMAIL_RE.findall(text):
        iocs["email-addr"].add(e.lower())
    for cve in CVE_RE.findall(text):
        iocs["vulnerability"].add(cve.upper())
    for tid in TECHNIQUE_RE.findall(text):
        iocs["technique"].add(tid.upper())
    for btc in BTC_RE.findall(text):
        iocs["btc-wallet"].add(btc)

    return {k: v for k, v in iocs.items() if v}


def _extract_pattern_values(pattern: str) -> List[Tuple[str, str]]:
    """
    Extrae pares (sco_type, value) de un STIX indicator pattern.
    Ej: "[ipv4-addr:value = '1.2.3.4']" → [("ipv4-addr", "1.2.3.4")]
    """
    return STIX_PATTERN_VALUE_RE.findall(pattern or "")


# ══════════════════════════════════════════════════════════════════════
#  Neo4jIngestor — Motor de ingesta + correlación universal
# ══════════════════════════════════════════════════════════════════════


class Neo4jIngestor:
    """
    Ingesta de objetos STIX 2.1 y correlación universal.
    Correlaciona entre TODOS los objetos del grafo: MITRE, IOCs,
    CVEs, APTs, campañas, infraestructura, reports, etc.
    """

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        log.info(f"Driver Neo4j creado → {uri}")

    def close(self):
        self.driver.close()

    # ── Conectividad ──────────────────────────────────────────────

    def verify_connectivity(self) -> bool:
        try:
            with self.driver.session() as s:
                s.run("RETURN 1").consume()
            return True
        except Exception as e:
            log.warning(f"Neo4j no listo: {e}")
            return False

    # ── Índices ───────────────────────────────────────────────────

    def setup_indexes(self):
        """Crea índices para acelerar MERGE y las 18 estrategias de correlación."""
        indexes = [
            # ─ Identidad de nodo ─
            "CREATE INDEX stix_id IF NOT EXISTS FOR (n:StixObject) ON (n.id)",
            "CREATE INDEX stix_type IF NOT EXISTS FOR (n:StixObject) ON (n.type)",
            # ─ Búsqueda por nombre / valor ─
            "CREATE INDEX stix_name IF NOT EXISTS FOR (n:StixObject) ON (n.name)",
            "CREATE INDEX stix_value IF NOT EXISTS FOR (n:StixObject) ON (n.value)",
            # ─ MITRE & CVE lookup ─
            "CREATE INDEX stix_ext_id IF NOT EXISTS FOR (n:StixObject) ON (n.external_id)",
            # ─ Pattern matching (indicadores) ─
            "CREATE INDEX stix_pattern IF NOT EXISTS FOR (n:StixObject) ON (n.pattern)",
            # ─ Hash lookups (file SCOs) ─
            "CREATE INDEX stix_hash_md5 IF NOT EXISTS FOR (n:StixObject) ON (n.hash_md5)",
            "CREATE INDEX stix_hash_sha1 IF NOT EXISTS FOR (n:StixObject) ON (n.hash_sha1)",
            "CREATE INDEX stix_hash_sha256 IF NOT EXISTS FOR (n:StixObject) ON (n.hash_sha256)",
            # ─ Temporal (created, modified) ─
            "CREATE INDEX stix_created IF NOT EXISTS FOR (n:StixObject) ON (n.created)",
            # ─ Sector / targeting (identities) ─
            "CREATE INDEX stix_sectors IF NOT EXISTS FOR (n:StixObject) ON (n.sectors)",
            # ─ Composite para correlación rápida ─
            "CREATE INDEX stix_type_name IF NOT EXISTS FOR (n:StixObject) ON (n.type, n.name)",
            "CREATE INDEX stix_type_value IF NOT EXISTS FOR (n:StixObject) ON (n.type, n.value)",
        ]
        with self.driver.session() as session:
            for idx_query in indexes:
                try:
                    session.run(idx_query)
                except Exception:
                    pass  # Ya existe
        log.info("Índices Neo4j verificados / creados (13 índices)")

    # ── Estadísticas del grafo ────────────────────────────────────

    def log_graph_stats(self):
        """Muestra composición actual del grafo (diagnóstico al arrancar)."""
        with self.driver.session() as session:
            result = session.run(
                "MATCH (n:StixObject) "
                "RETURN n.type AS type, count(*) AS cnt "
                "ORDER BY cnt DESC LIMIT 25"
            )
            records = list(result)
            rel_result = session.run(
                "MATCH ()-[r]->() "
                "RETURN type(r) AS rel_type, count(*) AS cnt "
                "ORDER BY cnt DESC LIMIT 15"
            )
            rel_records = list(rel_result)
        if records:
            log.info("═══ Composición actual del grafo STIX ═══")
            for rec in records:
                log.info(f"  {rec['type']:30s} → {rec['cnt']:>6d} nodos")
            if rel_records:
                log.info("═══ Relaciones ═══")
                for rec in rel_records:
                    log.info(f"  {rec['rel_type']:30s} → {rec['cnt']:>6d} rels")
        else:
            log.info("Grafo vacío — la primera ingesta creará los nodos iniciales")

    # ══════════════════════════════════════════════════════════════
    #  INGESTA DE NODOS
    # ══════════════════════════════════════════════════════════════

    def ingest_nodes(self, nodes: List[Dict]) -> int:
        """MERGE de objetos STIX como nodos Neo4j (batch)."""
        if not nodes:
            return 0

        batch = []
        for obj in nodes:
            stix_type = obj.get("type", "unknown")
            batch.append({
                "id": obj["id"],
                "label": _type_to_label(stix_type),
                "stix_type": stix_type,
                "props": _flatten_properties(obj),
            })

        with self.driver.session() as session:
            session.execute_write(self._merge_nodes_tx, batch)
        return len(batch)

    @staticmethod
    def _merge_nodes_tx(tx, batch: List[Dict]):
        tx.run(
            """
            UNWIND $batch AS item
            MERGE (n:StixObject {id: item.id})
            SET n += item.props,
                n.type = item.stix_type,
                n.last_seen = datetime()
            WITH n, item
            CALL apoc.create.addLabels(n, [item.label]) YIELD node
            RETURN count(node)
            """,
            batch=batch,
        )

    # ══════════════════════════════════════════════════════════════
    #  INGESTA DE RELACIONES EXPLÍCITAS (STIX relationship objects)
    # ══════════════════════════════════════════════════════════════

    def ingest_relationships(self, rels: List[Dict]) -> int:
        """MERGE de relaciones STIX explícitas (batch)."""
        if not rels:
            return 0

        batch = []
        for rel in rels:
            rel_type = rel.get("relationship_type", "related-to")
            neo4j_type = rel_type.upper().replace("-", "_")
            props: Dict[str, Any] = {"id": rel.get("id", "")}
            if rel.get("description"):
                props["description"] = rel["description"]
            if rel.get("created"):
                props["created"] = rel["created"]

            batch.append({
                "source_ref": rel["source_ref"],
                "target_ref": rel["target_ref"],
                "rel_type": neo4j_type,
                "props": props,
            })

        with self.driver.session() as session:
            session.execute_write(self._merge_rels_tx, batch)
        return len(batch)

    @staticmethod
    def _merge_rels_tx(tx, batch: List[Dict]):
        tx.run(
            """
            UNWIND $batch AS item
            MATCH (src:StixObject {id: item.source_ref})
            MATCH (tgt:StixObject {id: item.target_ref})
            CALL apoc.merge.relationship(
                src, item.rel_type, {id: item.props.id}, item.props, tgt, {}
            ) YIELD rel
            RETURN count(rel)
            """,
            batch=batch,
        )

    # ══════════════════════════════════════════════════════════════
    #  RELACIONES IMPLÍCITAS (created_by_ref, object_refs, …)
    # ══════════════════════════════════════════════════════════════

    def create_implicit_relationships(self, objects: List[Dict]) -> int:
        """
        Genera relaciones Neo4j a partir de propiedades de referencia
        STIX que no son objetos 'relationship' explícitos.
        Cubre: created_by_ref, object_refs, sample_refs,
        observed_data_refs, where_sighted_refs, sighting_of_ref.
        """
        batch: List[Dict] = []

        for obj in objects:
            oid = obj.get("id", "")
            otype = obj.get("type", "")

            # created_by_ref → CREATED_BY
            created_by = obj.get("created_by_ref")
            if created_by:
                batch.append({
                    "source_ref": oid,
                    "target_ref": created_by,
                    "rel_type": "CREATED_BY",
                    "props": {
                        "id": f"implicit--created-by--{oid}",
                        "auto_generated": True,
                    },
                })

            # object_refs → REFERS_TO (notes, reports, opinions, groupings)
            if otype in ("note", "report", "opinion", "grouping",
                         "observed-data"):
                for ref in obj.get("object_refs", []):
                    if isinstance(ref, str):
                        batch.append({
                            "source_ref": oid,
                            "target_ref": ref,
                            "rel_type": "REFERS_TO",
                            "props": {
                                "id": f"implicit--refers--{oid}--{ref}",
                                "auto_generated": True,
                            },
                        })

            # sample_refs → HAS_SAMPLE (malware → file SCOs)
            for ref in obj.get("sample_refs", []):
                if isinstance(ref, str):
                    batch.append({
                        "source_ref": oid,
                        "target_ref": ref,
                        "rel_type": "HAS_SAMPLE",
                        "props": {
                            "id": f"implicit--sample--{oid}--{ref}",
                            "auto_generated": True,
                        },
                    })

            # sighting_of_ref → SIGHTING_OF
            sighting_of = obj.get("sighting_of_ref")
            if sighting_of and otype == "sighting":
                batch.append({
                    "source_ref": oid,
                    "target_ref": sighting_of,
                    "rel_type": "SIGHTING_OF",
                    "props": {
                        "id": f"implicit--sighting-of--{oid}",
                        "auto_generated": True,
                    },
                })
                # observed_data_refs from sighting
                for ref in obj.get("observed_data_refs", []):
                    if isinstance(ref, str):
                        batch.append({
                            "source_ref": oid,
                            "target_ref": ref,
                            "rel_type": "OBSERVED_DATA",
                            "props": {
                                "id": f"implicit--obs-data--{oid}--{ref}",
                                "auto_generated": True,
                            },
                        })
                # where_sighted_refs → SIGHTED_AT
                for ref in obj.get("where_sighted_refs", []):
                    if isinstance(ref, str):
                        batch.append({
                            "source_ref": oid,
                            "target_ref": ref,
                            "rel_type": "SIGHTED_AT",
                            "props": {
                                "id": f"implicit--sighted-at--{oid}--{ref}",
                                "auto_generated": True,
                            },
                        })

        if not batch:
            return 0
        with self.driver.session() as session:
            session.execute_write(self._merge_rels_tx, batch)
        return len(batch)

    # ══════════════════════════════════════════════════════════════
    #  MOTOR DE CORRELACIÓN UNIVERSAL  (18 estrategias)
    # ══════════════════════════════════════════════════════════════

    def correlate_bundle(self, objects: List[Dict]):
        """
        Motor de correlación universal.
        Ejecuta 19 estrategias de correlación sobre los objetos recién
        ingestados contra TODO el grafo (MITRE, IOCs, CVEs, APTs, …).
        Todas las relaciones auto-generadas llevan:
          {auto_correlated: true, correlation_type: '...', matched_at: datetime()}
        """
        # ── Clasificar objetos ingestados ─────────────────────────
        by_type: Dict[str, List[str]] = {}    # type → [id, …]
        texts: Dict[str, str] = {}            # id → full text
        iocs_per_obj: Dict[str, Dict] = {}    # id → iocs dict
        patterns: Dict[str, str] = {}         # id → stix pattern
        bundle_ids: List[str] = []            # todos los IDs del bundle

        for obj in objects:
            otype = obj.get("type", "")
            oid = obj.get("id", "")
            bundle_ids.append(oid)

            by_type.setdefault(otype, []).append(oid)

            # Texto para extracción
            text = _collect_text(obj)
            if text:
                texts[oid] = text
                iocs_per_obj[oid] = _extract_iocs_from_text(text)

            # Pattern de indicadores
            if otype == "indicator" and obj.get("pattern"):
                patterns[oid] = obj["pattern"]

        stats: Dict[str, int] = {}   # strategy → total correlations

        def _log_stat(strategy: str, count: int):
            if count:
                stats[strategy] = stats.get(strategy, 0) + count

        with self.driver.session() as session:

            # ╔══════════════════════════════════════════════════════╗
            # ║  MITRE ATT&CK  (C01–C04)                           ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C01  Malware → MITRE Software name matching ───────
            for mid in by_type.get("malware", []):
                cnt = session.execute_write(self._C01_malware_mitre_tx, mid)
                _log_stat("C01_malware_mitre", cnt)

            # ── C02  Technique IDs extraídos de texto → attack-pattern
            for oid, iocs in iocs_per_obj.items():
                for tid in iocs.get("technique", []):
                    cnt = session.execute_write(self._C02_technique_tx, oid, tid)
                    _log_stat("C02_technique_id", cnt)

            # ── C03  Vulnerability → MITRE attack-patterns ────────
            for vid in by_type.get("vulnerability", []):
                cnt = session.execute_write(self._C03_vuln_mitre_tx, vid)
                _log_stat("C03_vuln_mitre", cnt)

            # ── C04  Indicator → Malware → MITRE → Actor propagation
            for iid in by_type.get("indicator", []):
                cnt = session.execute_write(self._C04_propagate_tx, iid)
                _log_stat("C04_indicator_propagate", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  IOC / OBSERVABLE  (C05–C07)                        ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C05  Observable dedup (mismo value + type) ────────
            obs_ids = [
                oid for oid in bundle_ids
                for obj in objects if obj.get("id") == oid and obj.get("value")
            ]
            if not obs_ids:
                # Fast path: collect from objects directly
                obs_ids = [o["id"] for o in objects if o.get("value")]
            if obs_ids:
                session.execute_write(self._C05_dedup_observables_tx, obs_ids)
                _log_stat("C05_observable_dedup", len(obs_ids))

            # ── C06  Indicator pattern → SCO linking ──────────────
            for iid, pat in patterns.items():
                extracted = _extract_pattern_values(pat)
                for sco_type, value in extracted:
                    cnt = session.execute_write(
                        self._C06_pattern_to_sco_tx, iid, sco_type, value
                    )
                    _log_stat("C06_pattern_sco", cnt)

            # ── C07  IOCs extraídos de texto → SCOs existentes ────
            for oid, iocs in iocs_per_obj.items():
                for ioc_type, values in iocs.items():
                    if ioc_type in ("technique", "vulnerability"):
                        continue  # Handling by C02 / C13
                    for val in values:
                        cnt = session.execute_write(
                            self._C07_text_ioc_to_sco_tx, oid, ioc_type, val
                        )
                        _log_stat("C07_text_ioc_sco", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  INFRAESTRUCTURA  (C08–C09)                         ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C08  Shared infrastructure between actors/campaigns
            for aid in (by_type.get("intrusion-set", [])
                        + by_type.get("campaign", [])):
                cnt = session.execute_write(self._C08_shared_infra_tx, aid)
                _log_stat("C08_shared_infra", cnt)

            # ── C09  Malware → shared C2 infrastructure ───────────
            for mid in by_type.get("malware", []):
                cnt = session.execute_write(self._C09_malware_c2_tx, mid)
                _log_stat("C09_malware_c2", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  THREAT ACTOR / CAMPAIGN  (C10–C12)                 ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C10  TTP overlap entre actores ────────────────────
            for aid in by_type.get("intrusion-set", []):
                cnt = session.execute_write(
                    self._C10_ttp_overlap_tx, aid, TTP_OVERLAP_THRESHOLD
                )
                _log_stat("C10_ttp_overlap", cnt)

            # ── C11  Campaign IOC/malware overlap → RELATED_CAMPAIGN
            for cid in by_type.get("campaign", []):
                cnt = session.execute_write(self._C11_campaign_overlap_tx, cid)
                _log_stat("C11_campaign_overlap", cnt)

            # ── C12  Indicator → Vulnerability → Actor chain ──────
            for iid in by_type.get("indicator", []):
                cnt = session.execute_write(self._C12_indicator_vuln_actor_tx, iid)
                _log_stat("C12_ind_vuln_actor", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  CVE / VULNERABILITY  (C13–C15)                     ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C13  CVE mentions in malware/indicator descriptions
            for oid, iocs in iocs_per_obj.items():
                for cve_id in iocs.get("vulnerability", []):
                    cnt = session.execute_write(
                        self._C13_cve_crossref_tx, oid, cve_id
                    )
                    _log_stat("C13_cve_crossref", cnt)

            # ── C14  CVE severity propagation ─────────────────────
            for vid in by_type.get("vulnerability", []):
                cnt = session.execute_write(self._C14_cve_severity_tx, vid)
                _log_stat("C14_cve_severity", cnt)

            # ── C15  Course-of-action → vuln/techniques ───────────
            for coa_id in by_type.get("course-of-action", []):
                cnt = session.execute_write(self._C15_coa_link_tx, coa_id)
                _log_stat("C15_coa_link", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  REPORT / INTELLIGENCE  (C16–C17)                   ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C16  Co-occurrence: objetos mismo bundle → CO_OCCURS
            if len(bundle_ids) >= 2:
                cnt = session.execute_write(
                    self._C16_co_occurrence_tx, bundle_ids
                )
                _log_stat("C16_co_occurrence", cnt)

            # ── C17  Temporal proximity ───────────────────────────
            actionable_ids = []
            for obj in objects:
                if obj.get("type") in (
                    "indicator", "malware", "vulnerability",
                    "campaign", "intrusion-set", "tool",
                ):
                    actionable_ids.append(obj["id"])
            if actionable_ids:
                cnt = session.execute_write(
                    self._C17_temporal_proximity_tx,
                    actionable_ids, TEMPORAL_WINDOW_DAYS,
                )
                _log_stat("C17_temporal", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  IDENTITY / TARGETING  (C18)                        ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C18  Sector targeting overlap ─────────────────────
            for aid in by_type.get("intrusion-set", []):
                cnt = session.execute_write(self._C18_sector_targeting_tx, aid)
                _log_stat("C18_sector_targeting", cnt)

            # ╔══════════════════════════════════════════════════════╗
            # ║  GEOLOCALIZACIÓN  (C19)                             ║
            # ╚══════════════════════════════════════════════════════╝

            # ── C19  Geo-clustering by country/region ─────────────
            for aid in (by_type.get("intrusion-set", [])
                        + by_type.get("campaign", [])):
                cnt = session.execute_write(self._C19_geo_cluster_tx, aid)
                _log_stat("C19_geo_cluster", cnt)

        # ── Resumen de correlaciones ──────────────────────────────
        if stats:
            total = sum(stats.values())
            log.info(f"  ═══ Correlación: {total} relaciones generadas ═══")
            for strategy, cnt in sorted(stats.items()):
                log.info(f"    {strategy}: {cnt}")

    # ══════════════════════════════════════════════════════════════
    #  ESTRATEGIAS DE CORRELACIÓN — CYPHER TRANSACTIONS
    # ══════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────
    #  C01 — Malware → MITRE Software name matching
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C01_malware_mitre_tx(tx, malware_id: str) -> int:
        """
        Vincula malware nuevo con software MITRE ATT&CK existente
        por nombre (case-insensitive). Limpia prefijos genéricos
        del converter STIX ("Posible amenaza:", "Possible threat:").
        También busca en aliases de MITRE software.
        """
        result = tx.run(
            """
            MATCH (new:StixObject {id: $mid})
            WHERE new.type = 'malware' AND new.name IS NOT NULL
            WITH new, toLower(new.name) AS raw_name

            // Limpiar prefijos genéricos del converter
            WITH new,
                 replace(
                   replace(raw_name, 'posible amenaza: ', ''),
                   'possible threat: ', ''
                 ) AS clean_name

            MATCH (mitre:StixObject)
            WHERE mitre.type IN ['malware', 'tool']
              AND mitre.id <> new.id
              AND mitre.name IS NOT NULL
              AND (
                  toLower(mitre.name) = clean_name
                  OR toLower(mitre.name) CONTAINS clean_name
                  OR clean_name CONTAINS toLower(mitre.name)
                  // Buscar también en aliases (almacenados como lista)
                  OR any(alias IN coalesce(mitre.aliases, [])
                         WHERE toLower(alias) = clean_name)
              )
            MERGE (new)-[r:VARIANT_OF]->(mitre)
            SET r.auto_correlated = true,
                r.correlation_type = 'C01_malware_mitre',
                r.confidence = $confidence,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            mid=malware_id,
            confidence=CONFIDENCE_SCORES.get('C01_malware_mitre', 85),
        )
        record = result.single()
        return record["cnt"] if record else 0

    # ─────────────────────────────────────────────────────────────
    #  C02 — Technique ID extraction → Attack-Pattern
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C02_technique_tx(tx, obj_id: str, technique_id: str) -> int:
        result = tx.run(
            """
            MATCH (obj:StixObject {id: $oid})
            MATCH (tech:StixObject {external_id: $tid})
            WHERE tech.type = 'attack-pattern'
            MERGE (obj)-[r:RELATED_TO_TECHNIQUE]->(tech)
            SET r.auto_correlated = true,
                r.technique_id = $tid,
                r.correlation_type = 'C02_technique_extraction',
                r.confidence = $confidence,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            oid=obj_id, tid=technique_id,
            confidence=CONFIDENCE_SCORES.get('C02_technique_extraction', 90),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C03 — Vulnerability → MITRE Attack-Patterns
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C03_vuln_mitre_tx(tx, vuln_id: str) -> int:
        result = tx.run(
            """
            MATCH (vuln:StixObject {id: $vid})
            WHERE vuln.type = 'vulnerability' AND vuln.name IS NOT NULL
            WITH vuln, vuln.name AS cve_id
            MATCH (ap:StixObject {type: 'attack-pattern'})
            WHERE ap.description IS NOT NULL
              AND ap.description CONTAINS cve_id
            MERGE (ap)-[r:EXPLOITS]->(vuln)
            SET r.auto_correlated = true,
                r.correlation_type = 'C03_vuln_mitre',
                r.confidence = $confidence,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            vid=vuln_id,
            confidence=CONFIDENCE_SCORES.get('C03_vuln_mitre', 90),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C04 — Indicator → Malware → MITRE → Actor propagation
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C04_propagate_tx(tx, indicator_id: str) -> int:
        result = tx.run(
            """
            MATCH (ind:StixObject {id: $iid})
                  -[:INDICATES]->(m:StixObject {type: 'malware'})
            MATCH (m)-[:VARIANT_OF]->(mitre_m:StixObject)
            MATCH (actor:StixObject)-[:USES]->(mitre_m)
            WHERE actor.type IN ['intrusion-set', 'campaign']
            MERGE (ind)-[r:ATTRIBUTED_TO]->(actor)
            SET r.auto_correlated = true,
                r.correlation_type = 'C04_malware_propagation',
                r.via_malware = mitre_m.name,
                r.confidence = $confidence,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            iid=indicator_id,
            confidence=CONFIDENCE_SCORES.get('C04_malware_propagation', 80),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C05 — Observable deduplication (same value + type)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C05_dedup_observables_tx(tx, obj_ids: List[str]):
        tx.run(
            """
            UNWIND $ids AS oid
            MATCH (new:StixObject {id: oid})
            WHERE new.value IS NOT NULL
            WITH new
            MATCH (existing:StixObject)
            WHERE existing.value = new.value
              AND existing.id <> new.id
              AND existing.type = new.type
            MERGE (new)-[r:SAME_OBSERVABLE]->(existing)
            SET r.auto_correlated = true,
                r.correlation_type = 'C05_dedup',
                r.confidence = $confidence,
                r.matched_at = datetime()
            """,
            ids=obj_ids,
            confidence=CONFIDENCE_SCORES.get('C05_dedup', 100),
        )

    # ─────────────────────────────────────────────────────────────
    #  C06 — Indicator STIX pattern → existing SCO nodes
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C06_pattern_to_sco_tx(
        tx, indicator_id: str, sco_type: str, value: str
    ) -> int:
        """
        Vincula un indicador a SCOs existentes en el grafo cuyo
        tipo y valor coinciden con lo extraído de su pattern STIX.
        """
        result = tx.run(
            """
            MATCH (ind:StixObject {id: $iid})
            MATCH (sco:StixObject)
            WHERE sco.type = $sco_type
              AND (sco.value = $val
                   OR sco.hash_md5 = $val
                   OR sco.hash_sha1 = $val
                   OR sco.hash_sha256 = $val)
              AND sco.id <> ind.id
            MERGE (ind)-[r:PATTERN_MATCHES]->(sco)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C06_pattern_sco',
                r.matched_value = $val,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            iid=indicator_id, sco_type=sco_type, val=value,
            confidence=CONFIDENCE_SCORES.get('C06_pattern_sco', 100),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C07 — IOCs extracted from free text → existing SCOs
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C07_text_ioc_to_sco_tx(
        tx, obj_id: str, ioc_type: str, value: str
    ) -> int:
        """
        Vincula un objeto cualquiera a SCOs del grafo cuando su
        texto libre contiene un IOC (IP, dominio, hash, email, URL)
        que coincide con un SCO existente.
        """
        # Map ioc_type to possible SCO type & field
        type_map = {
            "ipv4-addr":    ("ipv4-addr", "value"),
            "ipv6-addr":    ("ipv6-addr", "value"),
            "domain-name":  ("domain-name", "value"),
            "url":          ("url", "value"),
            "email-addr":   ("email-addr", "value"),
            "file:md5":     ("file", "hash_md5"),
            "file:sha1":    ("file", "hash_sha1"),
            "file:sha256":  ("file", "hash_sha256"),
            "btc-wallet":   ("artifact", "value"),
        }
        sco_type, field = type_map.get(ioc_type, (ioc_type, "value"))

        result = tx.run(
            f"""
            MATCH (obj:StixObject {{id: $oid}})
            MATCH (sco:StixObject)
            WHERE sco.type = $sco_type
              AND sco.{field} = $val
              AND sco.id <> obj.id
            MERGE (obj)-[r:MENTIONS_IOC]->(sco)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C07_text_ioc',
                r.ioc_type = $ioc_type,
                r.ioc_value = $val,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            oid=obj_id, sco_type=sco_type, val=value, ioc_type=ioc_type,
            confidence=CONFIDENCE_SCORES.get('C07_text_ioc', 70),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C08 — Shared infrastructure between actors/campaigns
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C08_shared_infra_tx(tx, actor_id: str) -> int:
        """
        Detecta cuando dos actores/campañas distintos comparten
        infraestructura (IPs, dominios, URLs conectados via USES/HOSTS).
        Crea :SHARES_INFRASTRUCTURE.
        """
        result = tx.run(
            """
            MATCH (a:StixObject {id: $aid})
            WHERE a.type IN ['intrusion-set', 'campaign']
            MATCH (a)-[:USES|HOSTS|COMMUNICATES_WITH|CONTROLS*1..2]->
                  (infra:StixObject)
            WHERE infra.type IN ['infrastructure', 'ipv4-addr', 'ipv6-addr',
                                 'domain-name', 'url']
            WITH a, infra
            MATCH (other:StixObject)-[:USES|HOSTS|COMMUNICATES_WITH|CONTROLS*1..2]->
                  (infra)
            WHERE other.type IN ['intrusion-set', 'campaign']
              AND other.id <> a.id
            MERGE (a)-[r:SHARES_INFRASTRUCTURE]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C08_shared_infra',
                r.shared_node = infra.id,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            aid=actor_id,
            confidence=CONFIDENCE_SCORES.get('C08_shared_infra', 75),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C09 — Malware → shared C2 infrastructure
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C09_malware_c2_tx(tx, malware_id: str) -> int:
        """
        Detecta malware distinto que comparte la misma infraestructura
        de C2 (command-and-control). Crea :SHARES_C2.
        """
        result = tx.run(
            """
            MATCH (m:StixObject {id: $mid})
            WHERE m.type = 'malware'
            MATCH (m)-[:COMMUNICATES_WITH|USES|CONTROLS*1..2]->
                  (infra:StixObject)
            WHERE infra.type IN ['infrastructure', 'ipv4-addr', 'ipv6-addr',
                                 'domain-name', 'url']
            WITH m, infra
            MATCH (other:StixObject)-[:COMMUNICATES_WITH|USES|CONTROLS*1..2]->
                  (infra)
            WHERE other.type IN ['malware', 'tool']
              AND other.id <> m.id
            MERGE (m)-[r:SHARES_C2]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C09_malware_c2',
                r.shared_infra = infra.id,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            mid=malware_id,
            confidence=CONFIDENCE_SCORES.get('C09_malware_c2', 75),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C10 — TTP overlap between threat actors
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C10_ttp_overlap_tx(tx, actor_id: str, threshold: int) -> int:
        """
        Vincula actores (intrusion-set) que comparten ≥N técnicas
        MITRE ATT&CK con :SHARES_TTP.
        """
        result = tx.run(
            """
            MATCH (a:StixObject {id: $aid})
            WHERE a.type = 'intrusion-set'
            MATCH (a)-[:USES]->(:StixObject)-[:SUBTECHNIQUE_OF|RELATED_TO*0..1]->
                  (tech:StixObject {type: 'attack-pattern'})
            WITH a, collect(DISTINCT tech.id) AS a_techniques
            WHERE size(a_techniques) > 0

            MATCH (other:StixObject {type: 'intrusion-set'})
            WHERE other.id <> a.id
            MATCH (other)-[:USES]->(:StixObject)-[:SUBTECHNIQUE_OF|RELATED_TO*0..1]->
                  (tech2:StixObject {type: 'attack-pattern'})
            WITH a, a_techniques, other,
                 collect(DISTINCT tech2.id) AS other_techniques
            WITH a, other,
                 [t IN a_techniques WHERE t IN other_techniques] AS shared
            WHERE size(shared) >= $threshold

            MERGE (a)-[r:SHARES_TTP]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C10_ttp_overlap',
                r.shared_techniques_count = size(shared),
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            aid=actor_id, threshold=threshold,
            confidence=CONFIDENCE_SCORES.get('C10_ttp_overlap', 65),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C11 — Campaign overlap (shared IOCs / malware)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C11_campaign_overlap_tx(tx, campaign_id: str) -> int:
        """
        Vincula campañas que comparten malware o indicadores
        con :RELATED_CAMPAIGN.
        """
        result = tx.run(
            """
            MATCH (c:StixObject {id: $cid})
            WHERE c.type = 'campaign'
            MATCH (c)-[:USES|INDICATES|ATTRIBUTED_TO*1..2]->
                  (shared:StixObject)
            WHERE shared.type IN ['malware', 'tool', 'indicator',
                                  'infrastructure']
            WITH c, collect(DISTINCT shared.id) AS c_assets

            MATCH (other:StixObject {type: 'campaign'})
            WHERE other.id <> c.id
            MATCH (other)-[:USES|INDICATES|ATTRIBUTED_TO*1..2]->
                  (shared2:StixObject)
            WHERE shared2.id IN c_assets
            WITH c, other, count(DISTINCT shared2.id) AS overlap_count
            WHERE overlap_count >= 1

            MERGE (c)-[r:RELATED_CAMPAIGN]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C11_campaign_overlap',
                r.shared_assets = overlap_count,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            cid=campaign_id,
            confidence=CONFIDENCE_SCORES.get('C11_campaign_overlap', 65),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C12 — Indicator → Vulnerability → Actor attribution
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C12_indicator_vuln_actor_tx(tx, indicator_id: str) -> int:
        """
        Cadena: Indicator →[INDICATES]→ Vuln ←[EXPLOITS|TARGETS]←
                Actor/Campaign.  Crea atajo :ATTRIBUTED_VIA_VULN.
        """
        result = tx.run(
            """
            MATCH (ind:StixObject {id: $iid})
            MATCH (ind)-[:INDICATES|PATTERN_MATCHES|MENTIONS_IOC*1..2]->
                  (vuln:StixObject {type: 'vulnerability'})
            MATCH (actor:StixObject)-[:EXPLOITS|TARGETS]->(vuln)
            WHERE actor.type IN ['intrusion-set', 'campaign', 'malware']
            MERGE (ind)-[r:ATTRIBUTED_VIA_VULN]->(actor)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C12_ind_vuln_actor',
                r.via_vulnerability = vuln.name,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            iid=indicator_id,
            confidence=CONFIDENCE_SCORES.get('C12_ind_vuln_actor', 80),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C13 — CVE cross-reference from any object
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C13_cve_crossref_tx(tx, obj_id: str, cve_id: str) -> int:
        """
        Vincula cualquier objeto que menciona un CVE en su texto
        a la vulnerabilidad existente en el grafo.
        """
        result = tx.run(
            """
            MATCH (obj:StixObject {id: $oid})
            MATCH (vuln:StixObject)
            WHERE vuln.type = 'vulnerability'
              AND (vuln.name = $cve OR vuln.external_id = $cve)
              AND vuln.id <> obj.id
            MERGE (obj)-[r:REFERENCES_CVE]->(vuln)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C13_cve_crossref',
                r.cve_id = $cve,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            oid=obj_id, cve=cve_id,
            confidence=CONFIDENCE_SCORES.get('C13_cve_crossref', 90),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C14 — CVE severity propagation to related IOCs
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C14_cve_severity_tx(tx, vuln_id: str) -> int:
        """
        Propaga la criticidad de una CVE: si la vuln tiene score CVSS
        alto (≥7.0), marca los indicadores/malware conectados como
        high_severity_context = true.
        También busca malware que explota la misma CVE por mención
        en su texto/nombre.
        """
        result = tx.run(
            """
            MATCH (vuln:StixObject {id: $vid})
            WHERE vuln.type = 'vulnerability' AND vuln.name IS NOT NULL

            // Buscar malware/indicators que mencionan esta CVE
            WITH vuln, vuln.name AS cve_name
            OPTIONAL MATCH (related:StixObject)
            WHERE related.id <> vuln.id
              AND related.type IN ['malware', 'indicator', 'tool',
                                   'attack-pattern']
              AND (related.description IS NOT NULL
                   AND related.description CONTAINS cve_name)
            WITH vuln, collect(DISTINCT related) AS related_nodes
            WHERE size(related_nodes) > 0

            UNWIND related_nodes AS rel_node
            MERGE (rel_node)-[r:EXPLOITS_CVE]->(vuln)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C14_cve_severity',
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            vid=vuln_id,
            confidence=CONFIDENCE_SCORES.get('C14_cve_severity', 55),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C15 — Course-of-action → vulnerabilities / techniques
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C15_coa_link_tx(tx, coa_id: str) -> int:
        """
        Vincula course-of-action con vulnerabilidades y técnicas
        mencionadas en su descripción (por CVE-ID o Technique-ID).
        """
        result = tx.run(
            """
            MATCH (coa:StixObject {id: $cid})
            WHERE coa.type = 'course-of-action'
              AND coa.description IS NOT NULL

            // Buscar vulnerabilidades mencionadas
            OPTIONAL MATCH (vuln:StixObject {type: 'vulnerability'})
            WHERE vuln.name IS NOT NULL
              AND coa.description CONTAINS vuln.name
            WITH coa, collect(DISTINCT vuln) AS vulns

            // Buscar técnicas mencionadas (por external_id)
            OPTIONAL MATCH (tech:StixObject {type: 'attack-pattern'})
            WHERE tech.external_id IS NOT NULL
              AND coa.description CONTAINS tech.external_id
            WITH coa, vulns, collect(DISTINCT tech) AS techs

            // Crear relaciones con vulnerabilidades
            FOREACH (v IN vulns |
              MERGE (coa)-[r1:MITIGATES_CVE]->(v)
              SET r1.auto_correlated = true,
                  r1.confidence = $confidence,
                  r1.correlation_type = 'C15_coa_vuln',
                  r1.matched_at = datetime()
            )
            // Crear relaciones con técnicas
            FOREACH (t IN techs |
              MERGE (coa)-[r2:MITIGATES_TECHNIQUE]->(t)
              SET r2.auto_correlated = true,
                  r2.confidence = $confidence,
                  r2.correlation_type = 'C15_coa_technique',
                  r2.matched_at = datetime()
            )
            RETURN size(vulns) + size(techs) AS cnt
            """,
            cid=coa_id,
            confidence=CONFIDENCE_SCORES.get('C15_coa_link', 55),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C16 — Co-occurrence in same bundle
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C16_co_occurrence_tx(tx, bundle_ids: List[str]) -> int:
        """
        Vincula objetos "actionable" (indicator, malware, vulnerability,
        intrusion-set, campaign, tool) que aparecen en el mismo bundle
        con :CO_OCCURS_WITH.  Esto captura la inteligencia implícita
        de que fueron reportados juntos.
        """
        result = tx.run(
            """
            UNWIND $ids AS oid
            MATCH (n:StixObject {id: oid})
            WHERE n.type IN ['indicator', 'malware', 'vulnerability',
                             'intrusion-set', 'campaign', 'tool',
                             'attack-pattern', 'infrastructure']
            WITH collect(n) AS nodes
            WHERE size(nodes) >= 2
            UNWIND nodes AS a
            UNWIND nodes AS b
            WITH a, b
            WHERE a.id < b.id   // evitar duplicados y self-loops
            MERGE (a)-[r:CO_OCCURS_WITH]->(b)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C16_co_occurrence',
                r.bundle_time = datetime()
            RETURN count(*) AS cnt
            """,
            ids=bundle_ids,
            confidence=CONFIDENCE_SCORES.get('C16_co_occurrence', 60),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C17 — Temporal proximity
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C17_temporal_proximity_tx(
        tx, obj_ids: List[str], window_days: int
    ) -> int:
        """
        Vincula objetos creados en una ventana temporal similar
        (±N días) con objetos existentes del mismo contexto temático.
        Solo entre tipos actionable para evitar ruido.
        """
        result = tx.run(
            """
            UNWIND $ids AS oid
            MATCH (new:StixObject {id: oid})
            WHERE new.created IS NOT NULL
              AND new.type IN ['indicator', 'malware', 'vulnerability',
                               'campaign', 'intrusion-set']
            WITH new, new.created AS new_ts

            MATCH (existing:StixObject)
            WHERE existing.id <> new.id
              AND existing.created IS NOT NULL
              AND existing.type IN ['indicator', 'malware', 'vulnerability',
                                    'campaign', 'intrusion-set']
              AND existing.type = new.type
              AND abs(duration.between(
                    date(datetime(existing.created)), date(datetime(new_ts))
                  ).days) <= $window
              AND NOT (new)-[:CO_OCCURS_WITH]-(existing)
              AND NOT (new)-[:SAME_OBSERVABLE]-(existing)
            MERGE (new)-[r:TEMPORAL_PROXIMITY]->(existing)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C17_temporal',
                r.window_days = $window,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            ids=obj_ids, window=window_days,
            confidence=CONFIDENCE_SCORES.get('C17_temporal', 30),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C18 — Sector/victim targeting overlap
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C18_sector_targeting_tx(tx, actor_id: str) -> int:
        """
        Vincula actores que atacan los mismos sectores/identidades
        (víctimas) con :TARGETS_SAME_SECTOR.
        Busca a través de relaciones :TARGETS hacia identities con
        sectores coincidentes.
        """
        result = tx.run(
            """
            MATCH (a:StixObject {id: $aid})
            WHERE a.type = 'intrusion-set'

            // Encontrar víctimas/sectores del actor
            MATCH (a)-[:TARGETS]->(victim:StixObject)
            WHERE victim.type = 'identity'
              AND victim.sectors IS NOT NULL
            WITH a, collect(DISTINCT victim.sectors) AS flat_sectors_lists
            WITH a, reduce(s = [], x IN flat_sectors_lists | s + x) AS sectors
            WHERE size(sectors) > 0

            // Buscar otros actores que atacan los mismos sectores
            MATCH (other:StixObject {type: 'intrusion-set'})
            WHERE other.id <> a.id
            MATCH (other)-[:TARGETS]->(v2:StixObject {type: 'identity'})
            WHERE v2.sectors IS NOT NULL
              AND any(s IN v2.sectors WHERE s IN sectors)
            MERGE (a)-[r:TARGETS_SAME_SECTOR]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C18_sector_targeting',
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            aid=actor_id,
            confidence=CONFIDENCE_SCORES.get('C18_sector_targeting', 50),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0

    # ─────────────────────────────────────────────────────────────
    #  C19 — Geo-Clustering (actors targeting same region/country)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _C19_geo_cluster_tx(tx, actor_id: str) -> int:
        """
        Vincula actores/campañas que operan en las mismas regiones
        geográficas (a través de identities con country o locations).
        Crea :GEO_CLUSTER.
        """
        result = tx.run(
            """
            MATCH (a:StixObject {id: $aid})
            WHERE a.type IN ['intrusion-set', 'campaign']

            // Países vía identidades víctima
            OPTIONAL MATCH (a)-[:TARGETS]->(victim:StixObject {type: 'identity'})
            WHERE victim.country IS NOT NULL
            WITH a, collect(DISTINCT victim.country) AS id_countries

            // Países / regiones vía locations
            OPTIONAL MATCH (a)-[:TARGETS|LOCATED_AT|ORIGINATES_FROM*1..2]->
                           (loc:StixObject {type: 'location'})
            WHERE loc.country IS NOT NULL OR loc.region IS NOT NULL
            WITH a,
                 id_countries + collect(DISTINCT loc.country) AS raw_countries,
                 collect(DISTINCT loc.region) AS raw_regions
            WITH a,
                 [c IN raw_countries WHERE c IS NOT NULL] AS countries,
                 [r IN raw_regions   WHERE r IS NOT NULL] AS regions
            WHERE size(countries) > 0 OR size(regions) > 0

            // Otros actores con mismas coordenadas geográficas
            MATCH (other:StixObject)
            WHERE other.type IN ['intrusion-set', 'campaign']
              AND other.id <> a.id
            OPTIONAL MATCH (other)-[:TARGETS]->(v2:StixObject {type: 'identity'})
            WHERE v2.country IS NOT NULL
            WITH a, countries, regions, other,
                 collect(DISTINCT v2.country) AS o_id_countries
            OPTIONAL MATCH (other)-[:TARGETS|LOCATED_AT|ORIGINATES_FROM*1..2]->
                           (l2:StixObject {type: 'location'})
            WHERE l2.country IS NOT NULL OR l2.region IS NOT NULL
            WITH a, countries, regions, other,
                 o_id_countries + collect(DISTINCT l2.country) AS o_countries,
                 collect(DISTINCT l2.region) AS o_regions
            WITH a, other,
                 [c IN countries WHERE c IN o_countries] AS shared_countries,
                 [r IN regions   WHERE r IN o_regions]   AS shared_regions
            WHERE size(shared_countries) > 0 OR size(shared_regions) > 0

            MERGE (a)-[r:GEO_CLUSTER]->(other)
            SET r.auto_correlated = true,
                r.confidence = $confidence,
                r.correlation_type = 'C19_geo_cluster',
                r.shared_countries = shared_countries,
                r.shared_regions = shared_regions,
                r.matched_at = datetime()
            RETURN count(*) AS cnt
            """,
            aid=actor_id,
            confidence=CONFIDENCE_SCORES.get('C19_geo_cluster', 45),
        )
        rec = result.single()
        return rec["cnt"] if rec else 0


# ══════════════════════════════════════════════════════════════════════
#  Helpers de transformación STIX → Neo4j
# ══════════════════════════════════════════════════════════════════════


def _type_to_label(stix_type: str) -> str:
    """
    Convierte tipo STIX a label Neo4j.
    Misma convención que mitre-ingestor:  attack-pattern → Attack_pattern
    """
    if not stix_type:
        return "Unknown"
    return stix_type[0].upper() + stix_type[1:].replace("-", "_")


def _flatten_properties(obj: Dict) -> Dict[str, Any]:
    """
    Extrae propiedades compatibles con Neo4j de un objeto STIX.
    Las propiedades anidadas se serializan a JSON string.
    Los hashes del SCO 'file' se desglosan como hash_md5, hash_sha256, etc.
    """
    skip_keys = {"type", "id", "objects", "spec_version"}
    props: Dict[str, Any] = {}

    for key, value in obj.items():
        if key in skip_keys or value is None:
            continue

        # ── Hashes (file SCO) → campos individuales ───────────
        if key == "hashes" and isinstance(value, dict):
            for algo, digest in value.items():
                safe_key = f"hash_{algo.lower().replace('-', '')}"
                props[safe_key] = str(digest)
            continue

        # ── external_references → extraer external_id + URLs ──
        if key == "external_references" and isinstance(value, list):
            all_ext_ids: List[str] = []
            all_urls: List[str] = []
            for ref in value:
                if isinstance(ref, dict):
                    src = ref.get("source_name", "")
                    ext_id = ref.get("external_id")
                    url = ref.get("url")
                    if ext_id:
                        all_ext_ids.append(ext_id)
                    if url:
                        all_urls.append(url)
                    if src in (
                        "mitre-attack", "mobile-attack", "ics-attack",
                        "cve", "nvd", "capec",
                    ):
                        if ext_id:
                            props["external_id"] = ext_id
            if all_ext_ids:
                props["all_external_ids"] = all_ext_ids
            if all_urls:
                props["reference_urls"] = all_urls
            props[key] = json.dumps(value, default=str)
            continue

        # ── aliases → lista plana para correlación C01 ────────
        if key == "aliases" and isinstance(value, list):
            props["aliases"] = [str(v) for v in value]
            continue

        # ── sectors (identity) → lista para C18 ──────────────
        if key == "sectors" and isinstance(value, list):
            props["sectors"] = [str(v) for v in value]
            continue

        # ── kill_chain_phases → arrays legibles ───────────────
        if key == "kill_chain_phases" and isinstance(value, list):
            phases = [
                p.get("phase_name", "")
                for p in value if isinstance(p, dict)
            ]
            props["kill_chain_phases"] = phases
            tactics = list({
                p.get("kill_chain_name", "")
                for p in value if isinstance(p, dict)
            })
            props["kill_chain_names"] = tactics
            continue

        # ── object_marking_refs → lista de strings ────────────
        if key == "object_marking_refs" and isinstance(value, list):
            props[key] = value
            continue

        # ── Escalares ─────────────────────────────────────────
        if isinstance(value, (str, int, float, bool)):
            props[key] = value

        # ── Listas de escalares ───────────────────────────────
        elif isinstance(value, list):
            if all(isinstance(v, (str, int, float, bool)) for v in value):
                props[key] = value
            else:
                props[key] = json.dumps(value, default=str)

        # ── Dicts complejos → JSON string ─────────────────────
        elif isinstance(value, dict):
            props[key] = json.dumps(value, default=str)

    return props


# ══════════════════════════════════════════════════════════════════════
#  Parseo de mensajes Kafka → objetos STIX
# ══════════════════════════════════════════════════════════════════════


def parse_stix_message(raw: bytes) -> List[Dict]:
    """
    Interpreta un mensaje de Kafka como objetos STIX.
    Soporta: STIX Bundle, objeto suelto, JSON array, NDJSON.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    # Intento JSON
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON (un JSON por línea)
        objects = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    objects.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return [o for o in objects if isinstance(o, dict) and "id" in o]

    # Wrapper {"stix_bundle": {...}} (usado por intelowl-client y otros)
    if isinstance(data, dict) and "stix_bundle" in data:
        inner = data["stix_bundle"]
        if isinstance(inner, dict) and inner.get("type") == "bundle":
            return inner.get("objects", [])

    # STIX 2.1 Bundle
    if isinstance(data, dict) and data.get("type") == "bundle":
        return data.get("objects", [])

    # Objeto STIX suelto
    if isinstance(data, dict) and "type" in data and "id" in data:
        return [data]

    # Array de objetos
    if isinstance(data, list):
        return [o for o in data if isinstance(o, dict) and "id" in o]

    return []


# ══════════════════════════════════════════════════════════════════════
#  Procesamiento de un bundle completo
# ══════════════════════════════════════════════════════════════════════


def process_objects(ingestor: Neo4jIngestor, objects: List[Dict]) -> Tuple[int, int, int]:
    """
    Ingesta una lista de objetos STIX en Neo4j.
    Retorna (nodos, rels_explícitas, rels_implícitas).
    """
    # Separar nodos y relaciones explícitas
    nodes = [
        o for o in objects
        if o.get("type") != "relationship" and "id" in o
    ]
    rels = [
        o for o in objects
        if o.get("type") == "relationship"
        and o.get("source_ref") and o.get("target_ref")
    ]

    # 1. MERGE nodos
    n_nodes = ingestor.ingest_nodes(nodes)

    # 2. MERGE relaciones explícitas del bundle
    n_rels = ingestor.ingest_relationships(rels)

    # 3. Relaciones implícitas (created_by_ref, object_refs)
    n_implicit = ingestor.create_implicit_relationships(nodes)

    # 4. Correlación universal (18 estrategias: MITRE + IOCs + CVEs + APTs + …)
    if CORRELATE and nodes:
        try:
            ingestor.correlate_bundle(objects)
        except Exception as exc:
            log.warning(f"Error de correlación (no fatal): {exc}")

    return n_nodes, n_rels, n_implicit


# ══════════════════════════════════════════════════════════════════════
#  Main — Bucle principal del consumidor
# ══════════════════════════════════════════════════════════════════════


def main():
    log.info("═" * 60)
    log.info("  Skyfall-CTI · Consumer Neo4j  —  Universal Correlation")
    log.info("═" * 60)
    log.info(f"Kafka Broker:       {KAFKA_BROKER}")
    log.info(f"Kafka Topics:       {KAFKA_TOPICS}")
    log.info(f"Kafka Group:        {KAFKA_GROUP_ID}")
    log.info(f"Neo4j URI:          {NEO4J_URI}")
    log.info(f"Batch size:         {BATCH_SIZE}")
    log.info(f"Auto-correlate:     {CORRELATE}")
    log.info(f"TTP overlap min:    {TTP_OVERLAP_THRESHOLD}")
    log.info(f"Temporal window:    {TEMPORAL_WINDOW_DAYS} days")
    log.info(f"Correlation engine: 19 strategies (C01-C19)")

    # ── 1. Conectar a Neo4j (con reintentos) ─────────────────────
    ingestor = Neo4jIngestor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    for attempt in range(30):
        if ingestor.verify_connectivity():
            log.info("✓ Neo4j conectado")
            break
        log.info(f"  [{attempt + 1}/30] Neo4j arrancando… reintentando en 5 s")
        time.sleep(5)
    else:
        log.error("✗ Neo4j no disponible tras 150 s. Abortando.")
        sys.exit(1)

    ingestor.setup_indexes()
    ingestor.log_graph_stats()

    # ── 2. Conectar a Kafka (con reintentos) ─────────────────────
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": KAFKA_GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "max.poll.interval.ms": 300000,
    })

    for attempt in range(30):
        try:
            metadata = consumer.list_topics(timeout=5)
            log.info(
                f"✓ Kafka conectado — {len(metadata.topics)} topics disponibles"
            )
            break
        except KafkaException:
            log.info(f"  [{attempt + 1}/30] Kafka arrancando… reintentando en 5 s")
            time.sleep(5)
    else:
        log.error("✗ Kafka no disponible tras 150 s. Abortando.")
        ingestor.close()
        sys.exit(1)

    consumer.subscribe(KAFKA_TOPICS)
    log.info(f"✓ Suscrito a {KAFKA_TOPICS}")

    # ── 3. Contadores ─────────────────────────────────────────────
    total_msgs = 0
    total_nodes = 0
    total_rels = 0

    # ── 4. Bucle de consumo ───────────────────────────────────────
    try:
        while _running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.error(f"Error Kafka: {msg.error()}")
                continue

            topic = msg.topic()

            try:
                objects = parse_stix_message(msg.value())
                if not objects:
                    consumer.commit(message=msg)
                    continue

                n_nodes, n_rels, n_implicit = process_objects(ingestor, objects)

                total_msgs += 1
                total_nodes += n_nodes
                total_rels += n_rels + n_implicit

                log.info(
                    f"[{topic}] +{n_nodes} nodos, +{n_rels} rels, "
                    f"+{n_implicit} implícitas  "
                    f"(total: {total_msgs} msgs, {total_nodes} nodos, {total_rels} rels)"
                )

                consumer.commit(message=msg)

            except Exception as exc:
                log.error(
                    f"Error procesando mensaje de {topic}: {exc}",
                    exc_info=True,
                )
                # Commit para no reintentar mensajes envenenados
                consumer.commit(message=msg)

    except KeyboardInterrupt:
        pass
    finally:
        log.info(
            f"Shutdown. Totales: {total_msgs} msgs, "
            f"{total_nodes} nodos, {total_rels} rels"
        )
        consumer.close()
        ingestor.close()
        log.info("✓ Parada limpia")


if __name__ == "__main__":
    main()