from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
import stix2

# ──────────────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────────────

def _deterministic_id(type_: str, seed: str) -> str:
    """Genera un ID STIX determinístico a partir del tipo y una semilla."""
    return f"{type_}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _normalize_ts(ts: str) -> str:
    """Convierte timestamps ISO con +00:00 al formato Z aceptado por stix2."""
    if not ts or not isinstance(ts, str):
        return ts
    return ts.replace("+00:00", "Z").replace("+0000", "Z")


def _parse_infrastructure_types(
    usage_type: str, is_hosting: bool = False,
) -> List[str]:
    """
    Mapea el usageType de AbuseIPDB/ApiVoid a infrastructure_types (open-vocab STIX).

    Si is_hosting es True (p.ej. ApiVoid anonymity.is_hosting), se fuerza
    'hosting-provider' aunque el usageType no lo indique explícitamente.
    """
    types: List[str] = []
    if not usage_type:
        return ["hosting-provider"] if is_hosting else ["unknown"]

    usage_lower = usage_type.lower()
    if "data center" in usage_lower or "hosting" in usage_lower:
        types.append("hosting-provider")
    if "cdn" in usage_lower or "content delivery" in usage_lower:
        types.append("hosting-provider")
    if "isp" in usage_lower or "fixed line" in usage_lower:
        types.append("unknown")  # ISP residencial, no hosting
    if "mobile" in usage_lower:
        types.append("unknown")

    if is_hosting and "hosting-provider" not in types:
        types.append("hosting-provider")

    return list(dict.fromkeys(types)) or ["unknown"]  # deduplica preservando orden


# ──────────────────────────────────────────────────────────────────────
#  CONSTANTES
# ──────────────────────────────────────────────────────────────────────

SKYFALL_IDENTITY_ID = "identity--" + str(
    uuid.uuid5(uuid.NAMESPACE_URL, "https://skyfall-cti.local")
)

# Mapeo de categorías de AbuseIPDB a (MITRE ID, STIX Type)
# Esto permite crear objetos Attack-Pattern reales.
ABUSE_CAT_MAP = {
    # Categorías de Fuerza Bruta y Login
    "Brute Force": ("T1110", "brute-force"),
    "FTP Brute-Force": ("T1110", "brute-force"),
    "SSH": ("T1021.004", "unauthorized-access"),
    
    # Categorías de Escaneo y Reconocimiento
    "Port Scan": ("T1595.001", "network-traffic"),
    "Hacking": ("T1595", "malicious-activity"),
    
    # Categorías de Explotación y Web
    "Web App Attack": ("T1190", "unauthorized-access"),
    "Exploited Host": ("T1210", "compromised"),
    "SQL Injection": ("T1190", "unauthorized-access"),
    "Bad Web Bot": ("T1594", "network-traffic"),
    
    # Categorías de Spam y Fraude
    "Phishing": ("T1566", "social-engineering"),
    "Email Spam": ("T1566", "spam"),
    "Blog Spam": ("T1566", "spam"),
    "Web Spam": ("T1566", "spam"),
    "Fraud Orders": ("T1566", "malicious-activity"),
    
    # Categorías de Red e Infraestructura
    "DDoS Attack": ("T1498", "denial-of-service"),
    "Open Proxy": ("T1090", "anonymization"),
    "VPN IP": ("T1090", "anonymization"),
    "IoT Targeted": ("T1190", "malicious-activity"),
    "Spoofing": ("T1566", "social-engineering"),
}


# ──────────────────────────────────────────────────────────────────────
#  VEREDICTO GLOBAL: Confidence Aggregation
# ──────────────────────────────────────────────────────────────────────

def compute_global_confidence(analyzer_scores: Dict[str, Any]) -> int:
    """
    Calcula la confianza global del STIX Indicator (0-100) agregando
    los scores individuales de cada analizador con pesos ponderados.

    Claves esperadas en *analyzer_scores* (cada map_* las rellena):
        abuse_confidence  : int 0-100   (AbuseIPDB)
        vt_malicious      : int         (VirusTotal engines malicious)
        vt_total          : int         (VirusTotal engines total)
        apivoid_risk      : int 0-100   (ApiVoid risk_score)
        crowdsec_reputation: str        (Crowdsec: "malicious"/"suspicious"/…)
        crowdsec_total     : int 0-5    (Crowdsec scores.overall.total)
        blacklist_hits     : int        (acumulado de blacklists positivas)
    """
    weighted_sum = 0.0
    weights_used = 0.0

    # ── AbuseIPDB (peso 0.35) ────────────────────────────────────────
    abuse = analyzer_scores.get("abuse_confidence")
    if abuse is not None:
        weighted_sum += float(abuse) * 0.35
        weights_used += 0.35

    # ── VirusTotal (peso 0.30) ───────────────────────────────────────
    vt_mal = analyzer_scores.get("vt_malicious", 0)
    vt_total = analyzer_scores.get("vt_total", 0)
    if vt_total > 0:
        # Amplificamos la ratio ×5 para que 5/94 ≈ 27 % no quede bajo
        vt_score = min((vt_mal / vt_total) * 100.0 * 5.0, 100.0)
        weighted_sum += vt_score * 0.30
        weights_used += 0.30

    # ── ApiVoid (peso 0.15) ──────────────────────────────────────────
    apivoid = analyzer_scores.get("apivoid_risk")
    if apivoid is not None:
        weighted_sum += float(apivoid) * 0.15
        weights_used += 0.15

    # ── Crowdsec (peso 0.20) ─────────────────────────────────────────
    cs_rep = analyzer_scores.get("crowdsec_reputation")
    cs_total = analyzer_scores.get("crowdsec_total", 0)
    if cs_rep is not None:
        if cs_rep == "malicious":
            cs_score = 80 + min(cs_total * 4, 20)       # 80-100
        elif cs_rep == "suspicious":
            cs_score = 50 + min(cs_total * 6, 30)       # 50-80
        else:
            cs_score = min(cs_total * 10, 50)            # 0-50
        weighted_sum += float(cs_score) * 0.20
        weights_used += 0.20

    # ── Normalizar ───────────────────────────────────────────────────
    if weights_used > 0:
        final = int(weighted_sum / weights_used)
    else:
        final = 30  # sin datos → confianza baja por defecto

    # ── Reglas de suelo (floor rules) ────────────────────────────────
    abuse_val = analyzer_scores.get("abuse_confidence", 0)
    vt_mal_val = analyzer_scores.get("vt_malicious", 0)

    if abuse_val >= 90 or vt_mal_val >= 5:
        final = max(final, 90)
    elif abuse_val >= 50 or vt_mal_val >= 3:
        final = max(final, 60)

    return min(max(final, 0), 100)


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 1: AbuseIPDB (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_abuseipdb(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX reales de AbuseIPDB:
      - Infrastructure  (ISP + infrastructure_types)
      - AttackPattern ×N (categorías → MITRE)
      - Location        (país de origen)
      - Sighting        (avistamiento activo con fechas y conteo)
      - Note            (top 5 comentarios de reporters)
      - Relationships   (located-at, exhibits)

    Devuelve:
      new_objects  : objetos STIX para añadir al Bundle.
      summary_data : datos para enriquecer el Indicator final y para
                     compute_global_confidence().
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    data = report.get("data", {})
    categories_found = report.get("categories_found", {})

    # ── 1. Score y metadatos para el Indicator ───────────────────────
    summary_data["confidence"] = data.get("abuseConfidenceScore", 0)
    summary_data["description"] = (
        f"IP reportada {data.get('totalReports', 0)} veces por "
        f"{data.get('numDistinctUsers', 0)} usuarios distintos."
    )

    # Campos custom que se inyectarán en el Indicator como x_*
    summary_data["x_abuseipdb_total_reports"] = data.get("totalReports", 0)
    summary_data["x_abuseipdb_distinct_users"] = data.get("numDistinctUsers", 0)
    summary_data["x_abuseipdb_is_tor"] = data.get("isTor", False)
    summary_data["x_abuseipdb_is_whitelisted"] = data.get("isWhitelisted", False)
    summary_data["x_abuseipdb_country_code"] = data.get("countryCode")
    summary_data["x_abuseipdb_usage_type"] = data.get("usageType")
    summary_data["x_abuseipdb_domain"] = data.get("domain")
    summary_data["x_abuseipdb_last_reported"] = data.get("lastReportedAt")
    summary_data["x_abuseipdb_permalink"] = report.get("permalink")

    # Clave para compute_global_confidence()
    summary_data["abuse_confidence"] = data.get("abuseConfidenceScore", 0)

    # ── 2. Infrastructure (ISP + infrastructure_types) ───────────────
    isp = data.get("isp")
    usage_type = data.get("usageType", "")
    if isp:
        infra_types = _parse_infrastructure_types(usage_type)
        infra = stix2.Infrastructure(
            id=_deterministic_id("infrastructure", f"isp-{isp.lower()}"),
            name=isp,
            description=f"ISP/Hosting: {usage_type or 'Unknown'}",
            infrastructure_types=infra_types,
            created_by_ref=identity_id,
            custom_properties={"x_source": "AbuseIPDB"},
        )
        new_objects.append(infra)
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=infra.id,
            relationship_type="located-at",
            created_by_ref=identity_id,
            custom_properties={"x_source": "AbuseIPDB"},
        ))

    # ── 3. Location (país de origen de la IP) ────────────────────────
    country_code = data.get("countryCode")
    if country_code:
        location = stix2.Location(
            id=_deterministic_id("location", f"country-{country_code.upper()}"),
            name=data.get("countryName", country_code),
            country=country_code.upper(),
            created_by_ref=identity_id,
            custom_properties={"x_source": "AbuseIPDB"},
        )
        new_objects.append(location)
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=location.id,
            relationship_type="located-at",
            created_by_ref=identity_id,
            custom_properties={"x_source": "AbuseIPDB"},
        ))

    # ── 4. Attack Patterns (categorías → MITRE) ─────────────────────
    indicator_types: List[str] = ["malicious-activity"]
    for cat_name, count in categories_found.items():
        if count > 0 and cat_name in ABUSE_CAT_MAP:
            mitre_id, stix_label = ABUSE_CAT_MAP[cat_name]
            indicator_types.append(stix_label)

            ap = stix2.AttackPattern(
                id=_deterministic_id("attack-pattern", f"abuseipdb-{mitre_id}"),
                name=cat_name,
                custom_properties={
                    "x_mitre_id": mitre_id,
                    "x_source": "AbuseIPDB",
                },
                created_by_ref=identity_id,
            )
            new_objects.append(ap)
            new_objects.append(stix2.Relationship(
                source_ref=sco_id,
                target_ref=ap.id,
                relationship_type="exhibits",
                created_by_ref=identity_id,
                custom_properties={"x_source": "AbuseIPDB"},
            ))

    summary_data["indicator_types"] = list(set(indicator_types))

    # ── 5. Note (top 5 comentarios de reporters) ─────────────────────
    reports = data.get("reports", [])
    if reports:
        comments = [
            r.get("comment") for r in reports if r.get("comment")
        ][:5]
        if any(comments):
            note = stix2.Note(
                id=_deterministic_id("note", f"abuseipdb-comments-{sco_id}"),
                abstract="AbuseIPDB Reporter Comments Summary",
                content="- " + "\n- ".join(filter(None, comments)),
                object_refs=[sco_id],
                created_by_ref=identity_id,
                custom_properties={"x_source": "AbuseIPDB"},
            )
            new_objects.append(note)

    # ── 6. Sighting (avistamiento activo por reporters) ──────────────
    total_reports = data.get("totalReports", 0)
    if total_reports > 0:
        # Extraer first_seen / last_seen de las fechas de reports
        report_dates = [
            r["reportedAt"]
            for r in reports
            if r.get("reportedAt")
        ]
        first_seen = min(report_dates) if report_dates else None
        last_seen = max(report_dates) if report_dates else data.get("lastReportedAt")

        sighting_kwargs: Dict[str, Any] = {
            "id": _deterministic_id("sighting", f"abuseipdb-{sco_id}"),
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity_id],
            "count": total_reports,
            "created_by_ref": identity_id,
            "description": (
                f"AbuseIPDB: {total_reports} reports de "
                f"{data.get('numDistinctUsers', 0)} usuarios distintos. "
                f"Confidence score: {data.get('abuseConfidenceScore', 0)}/100."
            ),
            "custom_properties": {
                "x_source": "AbuseIPDB",
                "x_abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "x_distinct_reporters": data.get("numDistinctUsers", 0),
            },
        }
        if first_seen:
            sighting_kwargs["first_seen"] = _normalize_ts(first_seen)
        if last_seen:
            sighting_kwargs["last_seen"] = _normalize_ts(last_seen)

        sighting = stix2.Sighting(**sighting_kwargs)
        new_objects.append(sighting)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 2: VirusTotal v3 (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_virustotal(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX reales de VirusTotal v3 Get Observable:
      - Infrastructure   (ASN / propietario de red + RDAP netname)
      - DomainName ×N    (SCO por cada resolución DNS inversa)
      - Sighting         (avistamiento desde motores que detectaron malicioso)
      - Note (detections) (engines malicious/suspicious con detalle)
      - Note (cert)       (último certificado HTTPS observado)
      - Relationships     (resolves-to IP↔domain, consists-of ASN↔IP)

    Devuelve:
      new_objects  : objetos STIX para añadir al Bundle.
      summary_data : datos para enriquecer el Indicator final y para
                     compute_global_confidence().
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    vt_data = report.get("data", {})
    attrs = vt_data.get("attributes", {})
    relationships = vt_data.get("relationships", {})

    # ── 1. Estadísticas de análisis (clave para confidence) ──────────
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    total_engines = malicious + suspicious + harmless + undetected + timeout

    summary_data["vt_malicious"] = malicious
    summary_data["vt_suspicious"] = suspicious
    summary_data["vt_harmless"] = harmless
    summary_data["vt_undetected"] = undetected
    summary_data["vt_total"] = total_engines

    # Campos custom x_* para inyectar en el Indicator final
    summary_data["x_vt_malicious"] = malicious
    summary_data["x_vt_suspicious"] = suspicious
    summary_data["x_vt_harmless"] = harmless
    summary_data["x_vt_undetected"] = undetected
    summary_data["x_vt_total_engines"] = total_engines
    summary_data["x_vt_reputation"] = attrs.get("reputation", 0)
    summary_data["x_vt_asn"] = attrs.get("asn")
    summary_data["x_vt_as_owner"] = attrs.get("as_owner")
    summary_data["x_vt_network"] = attrs.get("network")
    summary_data["x_vt_country"] = attrs.get("country")
    summary_data["x_vt_continent"] = attrs.get("continent")
    summary_data["x_vt_jarm"] = attrs.get("jarm")
    summary_data["x_vt_regional_registry"] = attrs.get("regional_internet_registry")
    summary_data["x_vt_permalink"] = report.get("link")

    votes = attrs.get("total_votes", {})
    summary_data["x_vt_votes_malicious"] = votes.get("malicious", 0)
    summary_data["x_vt_votes_harmless"] = votes.get("harmless", 0)

    # ── 2. Filtrar engines malicious/suspicious ──────────────────────
    results = attrs.get("last_analysis_results", {})
    malicious_engines: List[str] = []
    suspicious_engines: List[str] = []
    for engine_name, detail in results.items():
        cat = detail.get("category", "")
        if cat == "malicious":
            malicious_engines.append(engine_name)
        elif cat == "suspicious":
            suspicious_engines.append(engine_name)

    summary_data["x_vt_malicious_engines"] = malicious_engines
    summary_data["x_vt_suspicious_engines"] = suspicious_engines

    # ── 3. Infrastructure (ASN / propietario de red) ─────────────────
    asn = attrs.get("asn")
    as_owner = attrs.get("as_owner")
    network = attrs.get("network")
    rdap = attrs.get("rdap", {})
    rdap_name = rdap.get("name", "")  # e.g. "TencentCloud"

    if asn and as_owner:
        infra_name = f"AS{asn} – {as_owner}"
        infra_desc_parts = [f"ASN: {asn}", f"Owner: {as_owner}"]
        if network:
            infra_desc_parts.append(f"Network: {network}")
        if rdap_name:
            infra_desc_parts.append(f"RDAP: {rdap_name}")
        registry = attrs.get("regional_internet_registry")
        if registry:
            infra_desc_parts.append(f"RIR: {registry}")

        # RDAP status para determinar tipo
        rdap_status = rdap.get("status", [])
        rdap_type = rdap.get("type", "")
        infra_types = ["hosting-provider"]  # cloud IPs suelen ser hosting
        if "ALLOCATED PORTABLE" in rdap_type.upper():
            infra_types = ["hosting-provider"]

        infra = stix2.Infrastructure(
            id=_deterministic_id("infrastructure", f"asn-{asn}"),
            name=infra_name,
            description=" | ".join(infra_desc_parts),
            infrastructure_types=infra_types,
            created_by_ref=identity_id,
            custom_properties={
                "x_source": "VirusTotal",
                "x_asn": asn,
                "x_network": network,
                "x_rdap_name": rdap_name,
            },
        )
        new_objects.append(infra)
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=infra.id,
            relationship_type="consists-of",
            description=f"IP belongs to AS{asn} ({as_owner})",
            created_by_ref=identity_id,
            custom_properties={"x_source": "VirusTotal"},
        ))

    # ── 4. Resoluciones DNS → DomainName SCOs + resolves-to ─────────
    resolutions_data = relationships.get("resolutions", {}).get("data", [])
    ip_id = vt_data.get("id", "")  # e.g. "1.12.251.79"
    domain_names: List[str] = []

    for res in resolutions_data:
        res_id = res.get("id", "")
        # El id de VT resolution es "{ip}{domain}" → extraer dominio
        if ip_id and res_id.startswith(ip_id):
            domain = res_id[len(ip_id):]
        else:
            domain = res_id
        if not domain:
            continue

        domain_names.append(domain)
        domain_sco = stix2.DomainName(
            value=domain,
            resolves_to_refs=[sco_id],
            custom_properties={"x_source": "VirusTotal"},
        )
        new_objects.append(domain_sco)
        new_objects.append(stix2.Relationship(
            source_ref=domain_sco.id,
            target_ref=sco_id,
            relationship_type="resolves-to",
            description=f"DNS resolution: {domain} → {ip_id}",
            created_by_ref=identity_id,
            custom_properties={"x_source": "VirusTotal"},
        ))

    if domain_names:
        summary_data["x_vt_resolved_domains"] = domain_names

    # ── 5. Sighting (engines que detectaron malicious) ───────────────
    if malicious > 0 or suspicious > 0:
        flagged_engines = malicious_engines + suspicious_engines
        sighting_desc = (
            f"VirusTotal: {malicious}/{total_engines} engines detected "
            f"malicous, {suspicious} suspicious. "
            f"Engines malicious: {', '.join(malicious_engines[:10])}."
        )

        sighting_kwargs: Dict[str, Any] = {
            "id": _deterministic_id("sighting", f"virustotal-{sco_id}"),
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity_id],
            "count": malicious + suspicious,
            "created_by_ref": identity_id,
            "description": sighting_desc,
            "custom_properties": {
                "x_source": "VirusTotal",
                "x_vt_malicious_count": malicious,
                "x_vt_suspicious_count": suspicious,
                "x_vt_total_engines": total_engines,
                "x_vt_flagged_engines": flagged_engines[:20],
            },
        }

        # last_analysis_date como last_seen (epoch → ISO)
        analysis_epoch = attrs.get("last_analysis_date")
        if analysis_epoch:
            analysis_dt = datetime.fromtimestamp(
                analysis_epoch, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            sighting_kwargs["last_seen"] = analysis_dt

        sighting = stix2.Sighting(**sighting_kwargs)
        new_objects.append(sighting)

    # ── 6. Note (detalle de detections por engine) ───────────────────
    if malicious > 0 or suspicious > 0:
        lines = [
            f"**VirusTotal Detection Summary** ({malicious} malicious, "
            f"{suspicious} suspicious de {total_engines} engines)\n"
        ]
        if malicious_engines:
            lines.append("**Malicious:**")
            for eng in sorted(malicious_engines):
                result = results.get(eng, {}).get("result", "malware")
                lines.append(f"  - {eng}: {result}")

        if suspicious_engines:
            lines.append("\n**Suspicious:**")
            for eng in sorted(suspicious_engines):
                result = results.get(eng, {}).get("result", "suspicious")
                lines.append(f"  - {eng}: {result}")

        note_detections = stix2.Note(
            id=_deterministic_id("note", f"vt-detections-{sco_id}"),
            abstract=f"VirusTotal: {malicious} malicious, {suspicious} suspicious",
            content="\n".join(lines),
            object_refs=[sco_id, indicator_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "VirusTotal"},
        )
        new_objects.append(note_detections)

    # ── 7. Note (certificado HTTPS) ──────────────────────────────────
    cert = attrs.get("last_https_certificate")
    if cert:
        subject_cn = cert.get("subject", {}).get("CN", "N/A")
        issuer_cn = cert.get("issuer", {}).get("CN", "N/A")
        issuer_o = cert.get("issuer", {}).get("O", "")
        validity = cert.get("validity", {})
        not_before = validity.get("not_before", "N/A")
        not_after = validity.get("not_after", "N/A")
        san = cert.get("extensions", {}).get("subject_alternative_name", [])
        thumbprint = cert.get("thumbprint_sha256", cert.get("thumbprint", ""))

        cert_lines = [
            f"**HTTPS Certificate observed on IP**\n",
            f"- **Subject CN:** {subject_cn}",
            f"- **Issuer:** {issuer_cn} ({issuer_o})",
            f"- **Valid:** {not_before} → {not_after}",
            f"- **SANs:** {', '.join(san) if san else 'N/A'}",
            f"- **SHA-256:** {thumbprint}",
        ]

        # Datos de clave pública
        pub_key = cert.get("public_key", {})
        algo = pub_key.get("algorithm", "")
        key_size = pub_key.get("rsa", {}).get("key_size") if algo == "RSA" else None
        if algo:
            cert_lines.append(f"- **Public Key:** {algo} {key_size or ''}")

        note_cert = stix2.Note(
            id=_deterministic_id("note", f"vt-cert-{sco_id}"),
            abstract=f"HTTPS Cert: {subject_cn} (issued by {issuer_cn})",
            content="\n".join(cert_lines),
            object_refs=[sco_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "VirusTotal"},
        )
        new_objects.append(note_cert)

        # Guardar datos del cert en summary para el Indicator
        summary_data["x_vt_cert_subject_cn"] = subject_cn
        summary_data["x_vt_cert_issuer"] = f"{issuer_cn} ({issuer_o})"
        summary_data["x_vt_cert_valid_until"] = not_after
        summary_data["x_vt_cert_san"] = san

    # ── 8. WHOIS / RDAP metadata en summary_data ────────────────────
    if rdap:
        # Extraer contactos de abuse de RDAP entities
        rdap_entities = rdap.get("entities", [])
        abuse_contacts: List[str] = []
        for ent in rdap_entities:
            if "abuse" in ent.get("roles", []):
                vcards = ent.get("vcard_array", [])
                for vc in vcards:
                    if isinstance(vc, dict) and vc.get("name") == "email":
                        vals = vc.get("values", [])
                        abuse_contacts.extend(vals)

        if abuse_contacts:
            summary_data["x_vt_rdap_abuse_contacts"] = abuse_contacts

        # Registration / last-changed dates from RDAP events
        rdap_events = rdap.get("events", [])
        for ev in rdap_events:
            action = ev.get("event_action", "")
            date = ev.get("event_date", "")
            if action == "registration" and date:
                summary_data["x_vt_rdap_registration_date"] = date
            elif action == "last changed" and date:
                summary_data["x_vt_rdap_last_changed"] = date

    # ── 9. Historical SSL certs count ────────────────────────────────
    hist_certs = relationships.get(
        "historical_ssl_certificates", {},
    ).get("data", [])
    if hist_certs:
        summary_data["x_vt_historical_ssl_count"] = len(hist_certs)
        # Primer cert visto (más antiguo por first_seen_date)
        first_dates = [
            c.get("context_attributes", {}).get("first_seen_date", "")
            for c in hist_certs if c.get("context_attributes")
        ]
        if first_dates:
            summary_data["x_vt_ssl_first_seen"] = min(
                d for d in first_dates if d
            ) if any(first_dates) else None

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 3: ApiVoid (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_apivoid(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX reales de ApiVoid IP Reputation:
      - Location         (país + ciudad + lat/lon para mapa)
      - Infrastructure   (ISP/cloud provider + infrastructure_types + ASN)
      - Note (blacklists)(engines que detectaron + referencias)
      - Sighting         (avistamiento basado en blacklist hits)
      - Relationships    (located-at, consists-of)

    summary_data aporta:
      - apivoid_risk     → compute_global_confidence() peso 0.15
      - blacklist_hits   → acumulado de blacklists positivas
      - x_apivoid_*      → campos custom para el Indicator final
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    info = report.get("information", {})
    asn_data = report.get("asn", {})
    anon = report.get("anonymity", {})
    bl = report.get("blacklists", {})
    risk = report.get("risk_score", {})

    # ── 1. Risk score y metadatos para confidence ────────────────────
    risk_score = risk.get("result", 0)
    summary_data["apivoid_risk"] = risk_score
    summary_data["x_apivoid_risk_score"] = risk_score

    # ── 2. Anonymity flags ───────────────────────────────────────────
    summary_data["x_apivoid_is_tor"] = anon.get("is_tor", False)
    summary_data["x_apivoid_is_vpn"] = anon.get("is_vpn", False)
    summary_data["x_apivoid_is_proxy"] = anon.get("is_proxy", False)
    summary_data["x_apivoid_is_relay"] = anon.get("is_relay", False)
    summary_data["x_apivoid_is_hosting"] = anon.get("is_hosting", False)
    summary_data["x_apivoid_is_webproxy"] = anon.get("is_webproxy", False)
    summary_data["x_apivoid_is_residential_proxy"] = anon.get(
        "is_residential_proxy", False,
    )

    # ── 3. Geo / ISP metadata ───────────────────────────────────────
    summary_data["x_apivoid_isp"] = info.get("isp")
    summary_data["x_apivoid_cloud_provider"] = info.get("cloud_provider")
    summary_data["x_apivoid_city"] = info.get("city_name")
    summary_data["x_apivoid_region"] = info.get("region_name")
    summary_data["x_apivoid_country_code"] = info.get("country_code")
    summary_data["x_apivoid_country_name"] = info.get("country_name")
    summary_data["x_apivoid_continent"] = info.get("continent_name")
    summary_data["x_apivoid_latitude"] = info.get("latitude")
    summary_data["x_apivoid_longitude"] = info.get("longitude")
    summary_data["x_apivoid_reverse_dns"] = info.get("reverse_dns") or None

    # Bot / service flags
    summary_data["x_apivoid_is_fake_bot"] = info.get("is_fake_bot", False)
    summary_data["x_apivoid_is_google_bot"] = info.get("is_google_bot", False)
    summary_data["x_apivoid_is_search_engine_bot"] = info.get(
        "is_search_engine_bot", False,
    )
    summary_data["x_apivoid_is_public_dns"] = info.get("is_public_dns", False)

    # ASN metadata
    summary_data["x_apivoid_asn"] = asn_data.get("asn")
    summary_data["x_apivoid_asname"] = asn_data.get("asname")
    summary_data["x_apivoid_asn_org"] = asn_data.get("org")
    summary_data["x_apivoid_asn_type"] = asn_data.get("type")
    summary_data["x_apivoid_abuse_email"] = asn_data.get("abuse_email")

    # ── 4. Location (ciudad + lat/lon + país) ────────────────────────
    country_code = info.get("country_code")
    latitude = info.get("latitude")
    longitude = info.get("longitude")

    if country_code:
        loc_kwargs: Dict[str, Any] = {
            "id": _deterministic_id(
                "location",
                f"apivoid-{country_code}-{info.get('city_name', 'unknown')}",
            ),
            "country": country_code.upper(),
            "created_by_ref": identity_id,
            "custom_properties": {
                "x_source": "ApiVoid",
            },
        }

        # Nombre descriptivo: Ciudad / Región / País
        name_parts: List[str] = []
        city = info.get("city_name")
        region = info.get("region_name")
        country_name = info.get("country_name", country_code)
        if city:
            name_parts.append(city)
            loc_kwargs["custom_properties"]["x_city"] = city
        if region:
            name_parts.append(region)
            loc_kwargs["custom_properties"]["x_region"] = region
        name_parts.append(country_name)
        loc_kwargs["name"] = " / ".join(name_parts)

        # Lat/lon para visualización en mapa
        if latitude is not None and longitude is not None:
            loc_kwargs["latitude"] = latitude
            loc_kwargs["longitude"] = longitude

        # Continente
        continent = info.get("continent_name")
        if continent:
            loc_kwargs["custom_properties"]["x_continent"] = continent

        location = stix2.Location(**loc_kwargs)
        new_objects.append(location)

        # IP → located-at → Location
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=location.id,
            relationship_type="located-at",
            description=(
                f"IP geolocated in {', '.join(name_parts)} "
                f"(lat={latitude}, lon={longitude}) via ApiVoid"
            ),
            created_by_ref=identity_id,
            custom_properties={"x_source": "ApiVoid"},
        ))

    # ── 5. Infrastructure (ISP + Cloud Provider) ─────────────────────
    isp = info.get("isp")
    cloud_provider = info.get("cloud_provider")
    is_hosting = anon.get("is_hosting", False)
    asn_str = asn_data.get("asn", "")  # e.g. "AS45090"

    if isp or cloud_provider:
        # Nombre: preferir cloud_provider si existe, sino ISP
        infra_name = cloud_provider if cloud_provider else isp
        infra_desc_parts = []
        if isp:
            infra_desc_parts.append(f"ISP: {isp}")
        if cloud_provider:
            infra_desc_parts.append(f"Cloud: {cloud_provider}")
        if asn_str:
            infra_desc_parts.append(f"ASN: {asn_str}")
        asn_org = asn_data.get("org")
        if asn_org:
            infra_desc_parts.append(f"Org: {asn_org}")
        cloud_domain = info.get("cloud_provider_domain")
        if cloud_domain:
            infra_desc_parts.append(f"Domain: {cloud_domain}")

        # infrastructure_types via helper
        asn_type = asn_data.get("type", "")  # "business", "isp", etc.
        usage_hint = cloud_provider or asn_type
        infra_types = _parse_infrastructure_types(usage_hint, is_hosting)

        infra = stix2.Infrastructure(
            id=_deterministic_id(
                "infrastructure",
                f"apivoid-{(cloud_provider or isp or '').lower()}",
            ),
            name=infra_name,
            description=" | ".join(infra_desc_parts),
            infrastructure_types=infra_types,
            created_by_ref=identity_id,
            custom_properties={
                "x_source": "ApiVoid",
                "x_is_hosting": is_hosting,
                "x_asn": asn_str,
                "x_asn_type": asn_type,
                **({"x_cloud_domain": cloud_domain} if cloud_domain else {}),
                **({"x_abuse_email": asn_data.get("abuse_email")}
                   if asn_data.get("abuse_email") else {}),
            },
        )
        new_objects.append(infra)

        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=infra.id,
            relationship_type="consists-of",
            description=f"IP hosted on {infra_name} ({asn_str})",
            created_by_ref=identity_id,
            custom_properties={"x_source": "ApiVoid"},
        ))

    # ── 6. Blacklists → Note + Sighting ─────────────────────────────
    engines = bl.get("engines", {})
    detections = bl.get("detections", 0)
    engines_count = bl.get("engines_count", 0)
    detection_rate = bl.get("detection_rate", "0%")

    summary_data["blacklist_hits"] = detections
    summary_data["x_apivoid_bl_detections"] = detections
    summary_data["x_apivoid_bl_engines_count"] = engines_count
    summary_data["x_apivoid_bl_detection_rate"] = detection_rate

    # Recopilar engines que detectaron
    detected_engines: List[Dict[str, str]] = []
    for _idx, eng in engines.items():
        if eng.get("detected"):
            detected_engines.append({
                "name": eng.get("name", ""),
                "reference": eng.get("reference", ""),
            })

    summary_data["x_apivoid_bl_detected_engines"] = [
        e["name"] for e in detected_engines
    ]

    if detected_engines:
        bl_lines = [
            f"**ApiVoid Blacklist Report** — {detections}/{engines_count} "
            f"engines ({detection_rate})\n",
        ]
        for eng in detected_engines:
            bl_lines.append(
                f"  - **{eng['name']}** → [{eng['reference']}]({eng['reference']})"
            )

        note_bl = stix2.Note(
            id=_deterministic_id("note", f"apivoid-blacklists-{sco_id}"),
            abstract=(
                f"ApiVoid: {detections} blacklist hits "
                f"({detection_rate}) de {engines_count} engines"
            ),
            content="\n".join(bl_lines),
            object_refs=[sco_id, indicator_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "ApiVoid"},
        )
        new_objects.append(note_bl)

        # Sighting basado en blacklist hits
        sighting = stix2.Sighting(
            id=_deterministic_id("sighting", f"apivoid-{sco_id}"),
            sighting_of_ref=indicator_id,
            where_sighted_refs=[identity_id],
            count=detections,
            created_by_ref=identity_id,
            description=(
                f"ApiVoid: IP detectada en {detections} blacklists "
                f"({detection_rate}): "
                f"{', '.join(e['name'] for e in detected_engines)}. "
                f"Risk score: {risk_score}/100."
            ),
            custom_properties={
                "x_source": "ApiVoid",
                "x_risk_score": risk_score,
                "x_detection_rate": detection_rate,
                "x_detected_engines": [e["name"] for e in detected_engines],
            },
        )
        new_objects.append(sighting)

    # ── 7. Note (resumen de anonymity) ───────────────────────────────
    active_anon = {k: v for k, v in anon.items() if v is True}
    if active_anon:
        anon_lines = [
            "**ApiVoid Anonymity Flags**\n",
        ]
        for flag, _val in active_anon.items():
            # "is_hosting" → "Hosting"
            label = flag.replace("is_", "").replace("_", " ").title()
            anon_lines.append(f"  - ✓ **{label}**")

        note_anon = stix2.Note(
            id=_deterministic_id("note", f"apivoid-anonymity-{sco_id}"),
            abstract=f"ApiVoid: {len(active_anon)} anonymity flags active",
            content="\n".join(anon_lines),
            object_refs=[sco_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "ApiVoid"},
        )
        new_objects.append(note_anon)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 4: UrlScan Search (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_urlscan(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX de UrlScan Search:
      - DomainName ×N   (SCO por cada dominio encontrado en scans)
      - URL ×N          (SCO por cada URL escaneada)
      - Note            (resumen de actividad web observada)
      - Sighting        (avistamientos de la IP en scans públicos)
      - Relationships   (resolves-to, related-to)

    Si no hay resultados (total=0), solo aporta flags booleanos
    al summary_data indicando que la IP no tiene actividad web conocida.
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    total = report.get("total", 0)
    results = report.get("results", [])
    has_more = report.get("has_more", False)

    summary_data["x_urlscan_total"] = total
    summary_data["x_urlscan_has_more"] = has_more
    summary_data["x_urlscan_found"] = total > 0

    # ── Sin resultados → early return con flag ───────────────────────
    if total == 0 or not results:
        return new_objects, summary_data

    # ── 1. Procesar cada scan result ─────────────────────────────────
    seen_domains: Dict[str, str] = {}   # domain → domain_sco_id
    seen_urls: List[str] = []
    scan_summaries: List[str] = []
    malicious_count = 0
    scan_countries: List[str] = []

    for scan in results[:20]:  # limitar a 20 scans
        task = scan.get("task", {})
        page = scan.get("page", {})
        stats_scan = scan.get("stats", {})
        verdicts = scan.get("verdicts", {})

        scan_url = task.get("url", "")
        scan_domain = page.get("domain", "")
        scan_country = page.get("country", "")
        scan_ip = page.get("ip", "")
        scan_server = page.get("server", "")
        scan_time = task.get("time", "")
        overall_verdict = verdicts.get("overall", {})
        is_malicious = overall_verdict.get("malicious", False)

        if is_malicious:
            malicious_count += 1

        if scan_country and scan_country not in scan_countries:
            scan_countries.append(scan_country)

        # DomainName SCO (deduplicado)
        if scan_domain and scan_domain not in seen_domains:
            domain_sco = stix2.DomainName(
                value=scan_domain,
                custom_properties={"x_source": "UrlScan"},
            )
            new_objects.append(domain_sco)
            seen_domains[scan_domain] = domain_sco.id

            new_objects.append(stix2.Relationship(
                source_ref=domain_sco.id,
                target_ref=sco_id,
                relationship_type="resolves-to",
                description=f"UrlScan: {scan_domain} hosted on IP",
                created_by_ref=identity_id,
                custom_properties={"x_source": "UrlScan"},
            ))

        # URL SCO
        if scan_url and scan_url not in seen_urls:
            seen_urls.append(scan_url)
            url_sco = stix2.URL(
                value=scan_url,
                custom_properties={"x_source": "UrlScan"},
            )
            new_objects.append(url_sco)

            # URL → related-to → IP
            new_objects.append(stix2.Relationship(
                source_ref=url_sco.id,
                target_ref=sco_id,
                relationship_type="related-to",
                description=f"UrlScan: URL hosted on IP",
                created_by_ref=identity_id,
                custom_properties={"x_source": "UrlScan"},
            ))

        # Línea de resumen por scan
        verdict_label = "MALICIOUS" if is_malicious else "clean"
        scan_summaries.append(
            f"  - [{verdict_label}] {scan_url or scan_domain} "
            f"({scan_country}) — {scan_time}"
        )

    # ── 2. summary_data enrichment ───────────────────────────────────
    summary_data["x_urlscan_domains"] = list(seen_domains.keys())
    summary_data["x_urlscan_urls_count"] = len(seen_urls)
    summary_data["x_urlscan_malicious_scans"] = malicious_count
    summary_data["x_urlscan_countries"] = scan_countries

    # ── 3. Note (resumen de actividad web) ───────────────────────────
    note_lines = [
        f"**UrlScan Activity Report** — {total} scans found"
        f"{' (more available)' if has_more else ''}\n",
        f"- **Domains:** {len(seen_domains)}",
        f"- **URLs:** {len(seen_urls)}",
        f"- **Malicious verdicts:** {malicious_count}/{min(total, 20)}",
        f"- **Countries:** {', '.join(scan_countries) if scan_countries else 'N/A'}",
        "",
        "**Scan Details:**",
    ]
    note_lines.extend(scan_summaries[:10])
    if len(scan_summaries) > 10:
        note_lines.append(f"  ... y {len(scan_summaries) - 10} más")

    note = stix2.Note(
        id=_deterministic_id("note", f"urlscan-{sco_id}"),
        abstract=f"UrlScan: {total} scans, {malicious_count} malicious, "
                 f"{len(seen_domains)} domains",
        content="\n".join(note_lines),
        object_refs=[sco_id, indicator_id],
        created_by_ref=identity_id,
        custom_properties={"x_source": "UrlScan"},
    )
    new_objects.append(note)

    # ── 4. Sighting (si hay scans) ───────────────────────────────────
    # Extraer first/last scan times
    scan_times = [
        s.get("task", {}).get("time", "")
        for s in results if s.get("task", {}).get("time")
    ]
    sighting_kwargs: Dict[str, Any] = {
        "id": _deterministic_id("sighting", f"urlscan-{sco_id}"),
        "sighting_of_ref": indicator_id,
        "where_sighted_refs": [identity_id],
        "count": total,
        "created_by_ref": identity_id,
        "description": (
            f"UrlScan: IP observada en {total} scans públicos. "
            f"{malicious_count} marcados maliciosos. "
            f"Dominios: {', '.join(list(seen_domains.keys())[:5])}."
        ),
        "custom_properties": {
            "x_source": "UrlScan",
            "x_total_scans": total,
            "x_malicious_scans": malicious_count,
            "x_domains_count": len(seen_domains),
        },
    }
    if scan_times:
        sighting_kwargs["first_seen"] = min(scan_times)
        sighting_kwargs["last_seen"] = max(scan_times)

    sighting = stix2.Sighting(**sighting_kwargs)
    new_objects.append(sighting)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 5: URLhaus (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_urlhaus(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX de URLhaus (abuse.ch):
      - Si hay URLs maliciosas: Malware SCOs, URL SCOs, Note, Sighting
      - Si no hay resultados: solo flag booleano x_urlhaus_found

    URLhaus puede devolver:
      a) query_status: "no_results"  → IP limpia en URLhaus
      b) query_status: "ok" + urls[] → URLs maliciosas asociadas
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    query_status = report.get("query_status", "no_results")
    urls = report.get("urls", [])

    summary_data["x_urlhaus_found"] = query_status != "no_results" and len(urls) > 0
    summary_data["x_urlhaus_query_status"] = query_status

    # ── Sin resultados → early return ────────────────────────────────
    if query_status == "no_results" or not urls:
        summary_data["x_urlhaus_url_count"] = 0
        return new_objects, summary_data

    # ── 1. Procesar URLs maliciosas ──────────────────────────────────
    summary_data["x_urlhaus_url_count"] = len(urls)
    online_count = 0
    threat_types: List[str] = []
    tags_all: List[str] = []
    url_lines: List[str] = []

    for entry in urls[:20]:  # limitar
        url_val = entry.get("url", "")
        url_status = entry.get("url_status", "")  # "online" / "offline"
        threat = entry.get("threat", "")           # "malware_download" etc.
        date_added = entry.get("date_added", "")
        tags = entry.get("tags", []) or []

        if url_status == "online":
            online_count += 1
        if threat and threat not in threat_types:
            threat_types.append(threat)
        tags_all.extend(t for t in tags if t not in tags_all)

        # URL SCO
        if url_val:
            url_sco = stix2.URL(
                value=url_val,
                custom_properties={"x_source": "URLhaus"},
            )
            new_objects.append(url_sco)
            new_objects.append(stix2.Relationship(
                source_ref=sco_id,
                target_ref=url_sco.id,
                relationship_type="related-to",
                description=f"URLhaus: malicious URL hosted on IP ({url_status})",
                created_by_ref=identity_id,
                custom_properties={"x_source": "URLhaus"},
            ))

        status_icon = "🔴" if url_status == "online" else "⚫"
        url_lines.append(
            f"  - {status_icon} [{url_status}] {url_val} — "
            f"{threat} ({date_added}) tags: {', '.join(tags) if tags else 'N/A'}"
        )

    summary_data["x_urlhaus_online_count"] = online_count
    summary_data["x_urlhaus_threat_types"] = threat_types
    summary_data["x_urlhaus_tags"] = tags_all[:20]

    # ── 2. Note (resumen de URLs maliciosas) ─────────────────────────
    note_lines = [
        f"**URLhaus Malicious URLs Report**\n",
        f"- **Total URLs:** {len(urls)}",
        f"- **Online:** {online_count}",
        f"- **Threat types:** {', '.join(threat_types) if threat_types else 'N/A'}",
        f"- **Tags:** {', '.join(tags_all[:10]) if tags_all else 'N/A'}",
        "",
        "**URL Details:**",
    ]
    note_lines.extend(url_lines[:10])
    if len(url_lines) > 10:
        note_lines.append(f"  ... y {len(url_lines) - 10} más")

    note = stix2.Note(
        id=_deterministic_id("note", f"urlhaus-{sco_id}"),
        abstract=f"URLhaus: {len(urls)} malicious URLs, {online_count} online",
        content="\n".join(note_lines),
        object_refs=[sco_id, indicator_id],
        created_by_ref=identity_id,
        custom_properties={"x_source": "URLhaus"},
    )
    new_objects.append(note)

    # ── 3. Sighting ──────────────────────────────────────────────────
    sighting = stix2.Sighting(
        id=_deterministic_id("sighting", f"urlhaus-{sco_id}"),
        sighting_of_ref=indicator_id,
        where_sighted_refs=[identity_id],
        count=len(urls),
        created_by_ref=identity_id,
        description=(
            f"URLhaus: {len(urls)} malicious URLs associated with IP, "
            f"{online_count} currently online. "
            f"Threats: {', '.join(threat_types)}."
        ),
        custom_properties={
            "x_source": "URLhaus",
            "x_url_count": len(urls),
            "x_online_count": online_count,
            "x_threat_types": threat_types,
        },
    )
    new_objects.append(sighting)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 6: ThreatFox (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

def map_threatfox(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX de ThreatFox (abuse.ch):
      - Si hay IOCs: Malware SDOs, AttackPattern, Note, Sighting
      - Si no hay resultados: solo flag booleano x_threatfox_found

    ThreatFox puede devolver:
      a) query_status: "no_result"  → IP no encontrada
      b) query_status: "ok" + data[] → IOCs asociados con malware/botnet
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    query_status = report.get("query_status", "no_result")
    data = report.get("data", [])

    # Si data es string ("Your search did not yield any results") → sin datos
    if isinstance(data, str):
        data = []

    summary_data["x_threatfox_found"] = query_status == "ok" and len(data) > 0
    summary_data["x_threatfox_query_status"] = query_status

    # ── Sin resultados → early return ────────────────────────────────
    if query_status != "ok" or not data:
        summary_data["x_threatfox_ioc_count"] = 0
        return new_objects, summary_data

    # ── 1. Procesar IOCs ─────────────────────────────────────────────
    summary_data["x_threatfox_ioc_count"] = len(data)
    malware_names: List[str] = []
    threat_types: List[str] = []
    tags_all: List[str] = []
    ioc_lines: List[str] = []
    seen_malware: Dict[str, str] = {}  # malware_name → malware_sdo_id

    for ioc in data[:20]:
        ioc_val = ioc.get("ioc", "")
        ioc_type = ioc.get("ioc_type", "")
        threat_type = ioc.get("threat_type", "")       # "botnet_cc", "payload_delivery"
        malware_name = ioc.get("malware_printable", "")  # e.g. "Cobalt Strike"
        malware_alias = ioc.get("malware_alias", "")
        confidence = ioc.get("confidence_level", 0)
        first_seen = ioc.get("first_seen_utc", "")
        last_seen = ioc.get("last_seen_utc", "")
        reporter = ioc.get("reporter", "")
        tags = ioc.get("tags", []) or []

        if threat_type and threat_type not in threat_types:
            threat_types.append(threat_type)
        if malware_name and malware_name not in malware_names:
            malware_names.append(malware_name)
        tags_all.extend(t for t in tags if t not in tags_all)

        # Malware SDO (deduplicado por nombre)
        if malware_name and malware_name not in seen_malware:
            malware_sdo = stix2.Malware(
                id=_deterministic_id("malware", f"threatfox-{malware_name.lower()}"),
                name=malware_name,
                is_family=True,
                description=(
                    f"ThreatFox: {malware_name}"
                    f"{f' (alias: {malware_alias})' if malware_alias else ''}"
                ),
                created_by_ref=identity_id,
                custom_properties={
                    "x_source": "ThreatFox",
                    **({"x_alias": malware_alias} if malware_alias else {}),
                },
            )
            new_objects.append(malware_sdo)
            seen_malware[malware_name] = malware_sdo.id

            # Indicator → indicates → Malware
            new_objects.append(stix2.Relationship(
                source_ref=indicator_id,
                target_ref=malware_sdo.id,
                relationship_type="indicates",
                description=f"ThreatFox: IP associated with {malware_name}",
                created_by_ref=identity_id,
                custom_properties={"x_source": "ThreatFox"},
            ))

        ioc_lines.append(
            f"  - **{ioc_type}** {ioc_val} — {malware_name} "
            f"({threat_type}) confidence: {confidence}% "
            f"[{first_seen}]"
        )

    summary_data["x_threatfox_malware_names"] = malware_names
    summary_data["x_threatfox_threat_types"] = threat_types
    summary_data["x_threatfox_tags"] = tags_all[:20]

    # ── 2. Note ──────────────────────────────────────────────────────
    note_lines = [
        f"**ThreatFox IOC Report**\n",
        f"- **IOCs found:** {len(data)}",
        f"- **Malware families:** {', '.join(malware_names) if malware_names else 'N/A'}",
        f"- **Threat types:** {', '.join(threat_types) if threat_types else 'N/A'}",
        f"- **Tags:** {', '.join(tags_all[:10]) if tags_all else 'N/A'}",
        "",
        "**IOC Details:**",
    ]
    note_lines.extend(ioc_lines[:10])
    if len(ioc_lines) > 10:
        note_lines.append(f"  ... y {len(ioc_lines) - 10} más")

    note = stix2.Note(
        id=_deterministic_id("note", f"threatfox-{sco_id}"),
        abstract=f"ThreatFox: {len(data)} IOCs, malware: {', '.join(malware_names[:3])}",
        content="\n".join(note_lines),
        object_refs=[sco_id, indicator_id],
        created_by_ref=identity_id,
        custom_properties={"x_source": "ThreatFox"},
    )
    new_objects.append(note)

    # ── 3. Sighting ──────────────────────────────────────────────────
    sighting_kwargs: Dict[str, Any] = {
        "id": _deterministic_id("sighting", f"threatfox-{sco_id}"),
        "sighting_of_ref": indicator_id,
        "where_sighted_refs": [identity_id],
        "count": len(data),
        "created_by_ref": identity_id,
        "description": (
            f"ThreatFox: {len(data)} IOCs linked to IP. "
            f"Malware: {', '.join(malware_names[:5])}. "
            f"Threats: {', '.join(threat_types)}."
        ),
        "custom_properties": {
            "x_source": "ThreatFox",
            "x_ioc_count": len(data),
            "x_malware_families": malware_names,
            "x_threat_types": threat_types,
        },
    }

    # first/last seen de los IOCs
    seen_dates = [
        ioc.get("first_seen_utc", "")
        for ioc in data if ioc.get("first_seen_utc")
    ]
    if seen_dates:
        sighting_kwargs["first_seen"] = min(seen_dates)
    last_dates = [
        ioc.get("last_seen_utc", "")
        for ioc in data if ioc.get("last_seen_utc")
    ]
    if last_dates:
        sighting_kwargs["last_seen"] = max(last_dates)

    sighting = stix2.Sighting(**sighting_kwargs)
    new_objects.append(sighting)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 7: Crowdsec (Lógica Personalizada)
# ──────────────────────────────────────────────────────────────────────

# Mapeo ISO-3166 alpha-2 → nombre legible para target_countries
_COUNTRY_NAMES = {
    "AT": "Austria", "AU": "Australia", "BE": "Belgium", "BR": "Brazil",
    "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "CZ": "Czech Republic", "DE": "Germany", "DK": "Denmark",
    "EG": "Egypt", "ES": "Spain", "FI": "Finland", "FR": "France",
    "GB": "United Kingdom", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India",
    "IR": "Iran", "IT": "Italy", "JP": "Japan", "KR": "South Korea",
    "KP": "North Korea", "MX": "Mexico", "MY": "Malaysia", "NL": "Netherlands",
    "NO": "Norway", "NZ": "New Zealand", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RU": "Russia",
    "SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "TH": "Thailand",
    "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "US": "United States",
    "VN": "Vietnam", "ZA": "South Africa",
}


def map_crowdsec(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    Extrae objetos STIX reales de Crowdsec CTI:
      - Location (origen)        (ciudad + lat/lon de la IP)
      - Location ×N (targets)    (países atacados con conteo de reporters)
      - AttackPattern ×N         (mitre_techniques → SDOs reales)
      - Sighting                 (con first/last seen + behaviors)
      - Note (behaviors)         (detalle de behaviors + attack_details)
      - Note (target_countries)  (mapa geográfico de ataques)
      - Note (references)        (blocklists donde aparece)
      - Relationships            (located-at, targets, exhibits)

    summary_data aporta:
      - crowdsec_reputation → compute_global_confidence() peso 0.20
      - crowdsec_total      → overall.total score
      - x_crowdsec_*        → campos custom para el Indicator final
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    scores = report.get("scores", {})
    overall = scores.get("overall", {})
    last_day = scores.get("last_day", {})
    last_month = scores.get("last_month", {})
    history = report.get("history", {})
    location_data = report.get("location", {})
    behaviors = report.get("behaviors", [])
    attack_details = report.get("attack_details", [])
    mitre_techniques = report.get("mitre_techniques", [])
    target_countries = report.get("target_countries", {})
    references = report.get("references", [])
    reputation = report.get("reputation", "unknown")

    # ── 1. Claves para compute_global_confidence() ───────────────────
    summary_data["crowdsec_reputation"] = reputation
    summary_data["crowdsec_total"] = overall.get("total", 0)

    # ── 2. Scores y metadatos custom ─────────────────────────────────
    summary_data["x_crowdsec_reputation"] = reputation
    summary_data["x_crowdsec_confidence"] = report.get("confidence")
    summary_data["x_crowdsec_background_noise"] = report.get("background_noise")
    summary_data["x_crowdsec_background_noise_score"] = report.get(
        "background_noise_score",
    )
    summary_data["x_crowdsec_ip_range"] = report.get("ip_range")
    summary_data["x_crowdsec_ip_range_score"] = report.get("ip_range_score")
    summary_data["x_crowdsec_as_num"] = report.get("as_num")
    summary_data["x_crowdsec_as_name"] = report.get("as_name")
    summary_data["x_crowdsec_reverse_dns"] = report.get("reverse_dns")
    summary_data["x_crowdsec_proxy_or_vpn"] = report.get("proxy_or_vpn", False)
    summary_data["x_crowdsec_link"] = report.get("link")

    # Scores desglosados (overall, last_day, last_month)
    summary_data["x_crowdsec_score_overall"] = overall
    summary_data["x_crowdsec_score_last_day"] = last_day
    summary_data["x_crowdsec_score_last_month"] = last_month

    # History
    summary_data["x_crowdsec_first_seen"] = history.get("first_seen")
    summary_data["x_crowdsec_last_seen"] = history.get("last_seen")
    summary_data["x_crowdsec_days_age"] = history.get("days_age")

    # ── 3. Location (origen de la IP) ────────────────────────────────
    cs_country = location_data.get("country")
    cs_city = location_data.get("city")
    cs_lat = location_data.get("latitude")
    cs_lon = location_data.get("longitude")

    if cs_country:
        loc_name_parts = []
        if cs_city:
            loc_name_parts.append(cs_city)
        country_name = _COUNTRY_NAMES.get(cs_country, cs_country)
        loc_name_parts.append(country_name)

        loc_kwargs: Dict[str, Any] = {
            "id": _deterministic_id(
                "location",
                f"crowdsec-origin-{cs_country}-{cs_city or 'unknown'}",
            ),
            "name": " / ".join(loc_name_parts),
            "country": cs_country.upper(),
            "created_by_ref": identity_id,
            "custom_properties": {
                "x_source": "Crowdsec",
            },
        }
        if cs_lat is not None and cs_lon is not None:
            loc_kwargs["latitude"] = cs_lat
            loc_kwargs["longitude"] = cs_lon
        if cs_city:
            loc_kwargs["custom_properties"]["x_city"] = cs_city

        origin_loc = stix2.Location(**loc_kwargs)
        new_objects.append(origin_loc)
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=origin_loc.id,
            relationship_type="located-at",
            description=(
                f"IP geolocated in {', '.join(loc_name_parts)} "
                f"(lat={cs_lat}, lon={cs_lon}) via Crowdsec"
            ),
            created_by_ref=identity_id,
            custom_properties={"x_source": "Crowdsec"},
        ))

    # ── 4. TARGET COUNTRIES → Location ×N + Relationship "targets" ──
    #  Dato clave para el mapa geográfico de ataques.
    #  Cada país recibe un Location STIX y el Indicator apunta "targets".
    if target_countries:
        summary_data["x_crowdsec_target_countries"] = target_countries

        # Ordenar por número de reporters (descendente)
        sorted_targets = sorted(
            target_countries.items(), key=lambda x: x[1], reverse=True,
        )
        total_target_reporters = sum(target_countries.values())

        for country_code, reporter_count in sorted_targets:
            cname = _COUNTRY_NAMES.get(country_code, country_code)
            pct = (
                round((reporter_count / total_target_reporters) * 100, 1)
                if total_target_reporters > 0 else 0
            )

            target_loc = stix2.Location(
                id=_deterministic_id(
                    "location", f"crowdsec-target-{country_code.upper()}",
                ),
                name=f"{cname} ({country_code})",
                country=country_code.upper(),
                created_by_ref=identity_id,
                custom_properties={
                    "x_source": "Crowdsec",
                    "x_targeting_evidence": "crowdsec-reporters",
                    "x_reporter_count": reporter_count,
                    "x_target_percentage": pct,
                },
            )
            new_objects.append(target_loc)

            # Indicator → targets → Location (país atacado)
            new_objects.append(stix2.Relationship(
                source_ref=indicator_id,
                target_ref=target_loc.id,
                relationship_type="targets",
                description=(
                    f"Crowdsec: IP attacked {cname} — "
                    f"{reporter_count} reporters ({pct}% of total attacks)"
                ),
                created_by_ref=identity_id,
                custom_properties={
                    "x_source": "Crowdsec",
                    "x_reporter_count": reporter_count,
                },
            ))

        # Note resumen geográfico con tabla de países
        geo_lines = [
            "**Crowdsec Geographic Attack Distribution**\n",
            f"- **Total reporters across countries:** {total_target_reporters}",
            f"- **Countries attacked:** {len(target_countries)}",
            "",
            "| Country | Reporters | % |",
            "|---------|-----------|---|",
        ]
        for cc, count in sorted_targets:
            name = _COUNTRY_NAMES.get(cc, cc)
            pct = (
                round((count / total_target_reporters) * 100, 1)
                if total_target_reporters > 0 else 0
            )
            geo_lines.append(f"| {name} ({cc}) | {count} | {pct}% |")

        note_geo = stix2.Note(
            id=_deterministic_id("note", f"crowdsec-targets-{sco_id}"),
            abstract=(
                f"Crowdsec: IP attacks {len(target_countries)} countries, "
                f"top: {sorted_targets[0][0]} "
                f"({sorted_targets[0][1]} reporters)"
            ),
            content="\n".join(geo_lines),
            object_refs=[sco_id, indicator_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "Crowdsec"},
        )
        new_objects.append(note_geo)

    # ── 5. MITRE Techniques → AttackPattern SDOs ────────────────────
    mitre_ids: List[str] = []
    for tech in mitre_techniques:
        tech_id = tech.get("name", "")       # e.g. "T1110"
        tech_label = tech.get("label", "")    # e.g. "Brute Force"
        tech_desc = tech.get("description", "")

        if not tech_id:
            continue
        mitre_ids.append(tech_id)

        ap = stix2.AttackPattern(
            id=_deterministic_id("attack-pattern", f"crowdsec-{tech_id}"),
            name=tech_label or tech_id,
            description=tech_desc,
            created_by_ref=identity_id,
            custom_properties={
                "x_mitre_id": tech_id,
                "x_source": "Crowdsec",
            },
        )
        new_objects.append(ap)
        new_objects.append(stix2.Relationship(
            source_ref=sco_id,
            target_ref=ap.id,
            relationship_type="exhibits",
            description=f"Crowdsec: IP exhibits {tech_label} ({tech_id})",
            created_by_ref=identity_id,
            custom_properties={"x_source": "Crowdsec"},
        ))

    summary_data["x_crowdsec_mitre_techniques"] = mitre_ids

    # ── 6. Sighting (temporal data de history) ───────────────────────
    sighting_kwargs: Dict[str, Any] = {
        "id": _deterministic_id("sighting", f"crowdsec-{sco_id}"),
        "sighting_of_ref": indicator_id,
        "where_sighted_refs": [identity_id],
        "count": overall.get("aggressiveness", 1),
        "created_by_ref": identity_id,
        "description": (
            f"Crowdsec: reputation={reputation}, "
            f"overall score={overall.get('total', 0)}/5, "
            f"aggressiveness={overall.get('aggressiveness', 0)}/5, "
            f"threat={overall.get('threat', 0)}/5. "
            f"Behaviors: {', '.join(b.get('label', '') for b in behaviors)}. "
            f"Active for {history.get('days_age', '?')} days."
        ),
        "custom_properties": {
            "x_source": "Crowdsec",
            "x_reputation": reputation,
            "x_score_total": overall.get("total", 0),
            "x_score_aggressiveness": overall.get("aggressiveness", 0),
            "x_score_threat": overall.get("threat", 0),
            "x_score_trust": overall.get("trust", 0),
            "x_score_anomaly": overall.get("anomaly", 0),
            "x_behaviors": [b.get("name", "") for b in behaviors],
        },
    }

    first_seen = history.get("first_seen")
    last_seen = history.get("last_seen")
    if first_seen:
        sighting_kwargs["first_seen"] = _normalize_ts(first_seen)
    if last_seen:
        sighting_kwargs["last_seen"] = _normalize_ts(last_seen)

    cs_sighting = stix2.Sighting(**sighting_kwargs)
    new_objects.append(cs_sighting)

    # ── 7. Note (behaviors + attack_details) ─────────────────────────
    if behaviors or attack_details:
        beh_lines = [
            "**Crowdsec Behavior & Attack Analysis**\n",
            f"- **Reputation:** {reputation}",
            f"- **Overall score:** {overall.get('total', 0)}/5 "
            f"(aggr={overall.get('aggressiveness', 0)}, "
            f"threat={overall.get('threat', 0)}, "
            f"trust={overall.get('trust', 0)}, "
            f"anomaly={overall.get('anomaly', 0)})",
            f"- **Background noise:** {report.get('background_noise', 'N/A')} "
            f"(score: {report.get('background_noise_score', 'N/A')})",
            f"- **Active since:** {history.get('first_seen', 'N/A')} "
            f"({history.get('days_age', '?')} days)",
            "",
        ]

        if behaviors:
            beh_lines.append("**Behaviors:**")
            for b in behaviors:
                beh_lines.append(
                    f"  - **{b.get('label', b.get('name', ''))}**: "
                    f"{b.get('description', '')}"
                )
            beh_lines.append("")

        if attack_details:
            beh_lines.append("**Attack Scenarios (CrowdSec scenarios):**")
            for a in attack_details:
                beh_lines.append(
                    f"  - **{a.get('label', a.get('name', ''))}**: "
                    f"{a.get('description', '')}"
                )

        note_beh = stix2.Note(
            id=_deterministic_id("note", f"crowdsec-behaviors-{sco_id}"),
            abstract=(
                f"Crowdsec: {reputation}, score {overall.get('total', 0)}/5, "
                f"{len(behaviors)} behaviors, "
                f"{len(attack_details)} attack scenarios"
            ),
            content="\n".join(beh_lines),
            object_refs=[sco_id, indicator_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "Crowdsec"},
        )
        new_objects.append(note_beh)

    # ── 8. Note (blocklists / references) ────────────────────────────
    if references:
        ref_names = [
            r.get("label", r.get("name", "")) for r in references
        ]
        summary_data["x_crowdsec_blocklists"] = ref_names

        ref_lines = [
            f"**Crowdsec Blocklist Memberships** ({len(references)} lists)\n",
        ]
        for r in references:
            ref_lines.append(
                f"  - **{r.get('label', r.get('name', ''))}**: "
                f"{r.get('description', '')}"
            )

        note_refs = stix2.Note(
            id=_deterministic_id("note", f"crowdsec-blocklists-{sco_id}"),
            abstract=f"Crowdsec: IP in {len(references)} blocklists",
            content="\n".join(ref_lines),
            object_refs=[sco_id, indicator_id],
            created_by_ref=identity_id,
            custom_properties={"x_source": "Crowdsec"},
        )
        new_objects.append(note_refs)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ANALIZADOR 8: FireHol IPList (Booleano)
# ──────────────────────────────────────────────────────────────────────

def map_firehol(
    report: Dict[str, Any],
    sco_id: str,
    identity_id: str,
    indicator_id: str,
) -> Tuple[List[stix2.base._STIXBase], Dict[str, Any]]:
    """
    FireHol devuelve un dict {list_name: bool} indicando si la IP
    aparece en cada lista consultada (e.g. firehol_level1.netset).

    Si aparece en alguna lista → Sighting + Note.
    Si no aparece → solo summary_data informativo.
    """
    new_objects: List[stix2.base._STIXBase] = []
    summary_data: Dict[str, Any] = {}

    # Detectar en cuáles listas aparece
    matched_lists: List[str] = []
    for list_name, found in report.items():
        if found is True:
            matched_lists.append(list_name)

    summary_data["x_firehol_lists_checked"] = list(report.keys())
    summary_data["x_firehol_matched"] = matched_lists
    summary_data["x_firehol_hit"] = len(matched_lists) > 0

    # Aporta a blacklist_hits para compute_global_confidence()
    summary_data["blacklist_hits_firehol"] = len(matched_lists)

    if not matched_lists:
        return new_objects, summary_data

    # ── Sighting (IP presente en listas FireHol) ─────────────────────
    sighting = stix2.Sighting(
        id=_deterministic_id("sighting", f"firehol-{sco_id}"),
        sighting_of_ref=indicator_id,
        where_sighted_refs=[identity_id],
        count=len(matched_lists),
        created_by_ref=identity_id,
        description=(
            f"FireHol: IP found in {len(matched_lists)} blocklist(s): "
            f"{', '.join(matched_lists)}"
        ),
        custom_properties={
            "x_source": "FireHol",
            "x_matched_lists": matched_lists,
        },
    )
    new_objects.append(sighting)

    # ── Note ─────────────────────────────────────────────────────────
    note = stix2.Note(
        id=_deterministic_id("note", f"firehol-{sco_id}"),
        abstract=f"FireHol: IP in {len(matched_lists)} list(s)",
        content=(
            f"**FireHol IPList Check**\n\n"
            f"- **Lists matched:** {', '.join(matched_lists)}\n"
            f"- **Lists checked:** {', '.join(report.keys())}"
        ),
        object_refs=[sco_id, indicator_id],
        created_by_ref=identity_id,
        custom_properties={"x_source": "FireHol"},
    )
    new_objects.append(note)

    return new_objects, summary_data


# ──────────────────────────────────────────────────────────────────────
#  ORQUESTADOR: job_to_stix_bundle
# ──────────────────────────────────────────────────────────────────────

# Mapeo  nombre de analizador IntelOwl  →  función de conversión
_ANALYZER_MAP: Dict[str, Any] = {
    "AbuseIPDB": map_abuseipdb,
    "VirusTotal_v3_Get_Observable": map_virustotal,
    "APIVoid": map_apivoid,
    "UrlScan_Search": map_urlscan,
    "URLhaus": map_urlhaus,
    "ThreatFox": map_threatfox,
    "Crowdsec": map_crowdsec,
    "FireHol_IPList": map_firehol,
}

import logging as _logging

_log = _logging.getLogger("stix_converter_ip")


def job_to_stix_bundle(job_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convierte el resultado completo de un job IntelOwl (IP) en un
    STIX 2.1 Bundle serializable como JSON.

    Pasos:
      1. Crea objetos base: Identity, IPv4Address SCO, Indicator SDO.
      2. Recorre analyzer_reports[], enruta cada uno a su map_*().
      3. Agrega summary_data de cada analizador → compute_global_confidence().
      4. Enriquece el Indicator con todos los custom props (x_*).
      5. Ensambla Bundle deduplicado por ID.

    Retorna un dict JSON-serializable con la estructura STIX Bundle.
    """
    # ── Extraer observable (la IP) ───────────────────────────────────
    observable = (
        job_result.get("observable_name")
        or job_result.get("observable", {}).get("value", "")
        or job_result.get("name", "unknown")
    )

    # ── 1. Objetos base ──────────────────────────────────────────────
    identity = stix2.Identity(
        id=SKYFALL_IDENTITY_ID,
        name="Skyfall-CTI",
        identity_class="system",
        description="Automated CTI enrichment platform",
    )

    ipv4_sco = stix2.IPv4Address(value=observable)
    sco_id = ipv4_sco.id

    # Indicator placeholder (se reconstruirá con custom props al final)
    indicator_id = _deterministic_id("indicator", f"ip-{observable}")

    # ── 2. Recorrer analyzer_reports ─────────────────────────────────
    all_objects: List[stix2.base._STIXBase] = [identity, ipv4_sco]
    merged_summary: Dict[str, Any] = {}
    processed_analyzers: List[str] = []
    failed_analyzers: List[str] = []

    for ar in job_result.get("analyzer_reports", []):
        analyzer_name = ar.get("name", "")
        status = ar.get("status", "")
        report = ar.get("report", {})

        # Solo reports exitosos
        if status not in ("SUCCESS", "success"):
            _log.debug("Skipping %s (status=%s)", analyzer_name, status)
            if analyzer_name:
                failed_analyzers.append(analyzer_name)
            continue

        # Buscar función mapeadora
        map_fn = _ANALYZER_MAP.get(analyzer_name)
        if map_fn is None:
            _log.debug("No map_* for analyzer '%s', skipping", analyzer_name)
            continue

        try:
            objects, summary = map_fn(
                report=report,
                sco_id=sco_id,
                identity_id=SKYFALL_IDENTITY_ID,
                indicator_id=indicator_id,
            )
            all_objects.extend(objects)
            merged_summary.update(summary)
            processed_analyzers.append(analyzer_name)
            _log.info(
                "  ✓ %s → %d objetos STIX", analyzer_name, len(objects),
            )
        except Exception as exc:
            _log.warning(
                "  ✗ %s map error: %s", analyzer_name, exc, exc_info=True,
            )
            failed_analyzers.append(analyzer_name)

    # ── 3. Confidence global ─────────────────────────────────────────
    confidence = compute_global_confidence(merged_summary)

    # ── 4. Construir Indicator enriquecido ───────────────────────────
    # Reunir indicator_types de los summary_data
    indicator_types = merged_summary.get("indicator_types", [])
    if not indicator_types:
        indicator_types = ["malicious-activity"]

    # Custom properties: todos los x_* del merged_summary
    custom_props: Dict[str, Any] = {
        "x_source": "Skyfall-CTI",
        "x_analyzers_processed": processed_analyzers,
        "x_analyzers_failed": failed_analyzers,
    }
    for key, val in merged_summary.items():
        if key.startswith("x_"):
            custom_props[key] = val

    indicator = stix2.Indicator(
        id=indicator_id,
        name=f"Malicious IP: {observable}",
        description=(
            f"IP {observable} enriched by Skyfall-CTI via "
            f"{len(processed_analyzers)} analyzers: "
            f"{', '.join(processed_analyzers)}"
        ),
        indicator_types=list(dict.fromkeys(indicator_types)),
        pattern=f"[ipv4-addr:value = '{observable}']",
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        confidence=confidence,
        created_by_ref=SKYFALL_IDENTITY_ID,
        custom_properties=custom_props,
    )
    all_objects.append(indicator)

    # Indicator → based-on → IPv4Address
    all_objects.append(stix2.Relationship(
        source_ref=indicator_id,
        target_ref=sco_id,
        relationship_type="based-on",
        description=f"Indicator derived from analysis of {observable}",
        created_by_ref=SKYFALL_IDENTITY_ID,
        custom_properties={"x_source": "Skyfall-CTI"},
    ))

    # ── 5. Deduplicar por ID y serializar ────────────────────────────
    seen_ids: Dict[str, stix2.base._STIXBase] = {}
    for obj in all_objects:
        obj_id = str(obj.get("id", ""))
        if obj_id and obj_id not in seen_ids:
            seen_ids[obj_id] = obj

    bundle = stix2.Bundle(objects=list(seen_ids.values()), allow_custom=True)

    # Retornar como dict serializable
    return json.loads(bundle.serialize())