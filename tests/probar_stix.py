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
            sighting_kwargs["first_seen"] = first_seen
        if last_seen:
            sighting_kwargs["last_seen"] = last_seen

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
        sighting_kwargs["first_seen"] = first_seen
    if last_seen:
        sighting_kwargs["last_seen"] = last_seen

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
        object_refs=[sco_id],
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

    bundle = stix2.Bundle(objects=list(seen_ids.values()))

    # Retornar como dict serializable
    return json.loads(bundle.serialize())

if __name__ == "__main__":
    # 1. Aquí pegamos el JSON que te devolvió IntelOwl (el que pusiste al principio del chat)
    # Lo he abreviado para el ejemplo, pero tú pega el JSON COMPLETO.
    datos_analisis = json.JSONDecoder(strict=False).decode("""
{
  "id": 2745,
  "user": {
    "username": "admin"
  },
  "tags": [],
  "comments": [],
  "status": "reported_with_fails",
  "pivots_to_execute": [],
  "analyzers_to_execute": [
    "AbuseIPDB",
    "ApiVoid",
    "Crowdsec",
    "FireHol_IPList",
    "IPApi",
    "InQuest_REPdb",
    "MalwareBazaar_Google_Observable",
    "Shodan_Search",
    "TalosReputation",
    "ThreatFox",
    "TorProject",
    "URLhaus",
    "UrlScan_Search",
    "VirusTotal_v3_Get_Observable"
  ],
  "analyzers_requested": [
    "AbuseIPDB",
    "ApiVoid",
    "Crowdsec",
    "FireHol_IPList",
    "IPApi",
    "InQuest_REPdb",
    "MalwareBazaar_Google_Observable",
    "Shodan_Search",
    "TalosReputation",
    "ThreatFox",
    "TorProject",
    "URLhaus",
    "UrlScan_Search",
    "VirusTotal_v3_Get_Observable"
  ],
  "connectors_to_execute": [],
  "connectors_requested": [],
  "visualizers_to_execute": [
    "IP_Reputation"
  ],
  "playbook_requested": "SkyfallCTIipReputation",
  "playbook_to_execute": "SkyfallCTIipReputation",
  "investigation_id": null,
  "investigation_name": null,
  "permissions": {
    "kill": true,
    "delete": true,
    "plugin_actions": true
  },
  "data_model": {
    "id": 5926,
    "analyzers_report": [],
    "ietf_report": [],
    "evaluation": "malicious",
    "reliability": 10,
    "kill_chain_phase": null,
    "external_references": [
      "https://www.abuseipdb.com/check/1.12.251.79"
    ],
    "related_threats": [],
    "tags": [
      "port scan",
      "brute force",
      "ftp brute-force",
      "ssh",
      "phishing",
      "email spam",
      "spoofing",
      "web app attack",
      "exploited host",
      "hacking"
    ],
    "malware_family": null,
    "additional_info": {
      "description": "AbuseIPDB is a service where users can report malicious IP addresses attacking their infrastructure.This IP address has been categorized with some malicious categories",
      "distinct_users": 78
    },
    "date": "2026-03-06T09:07:17.444025Z",
    "asn": null,
    "asn_rank": null,
    "certificates": null,
    "org_name": null,
    "country_code": "cn",
    "registered_country_code": null,
    "isp": "tencent cloud computing (beijing) co., ltd.",
    "resolutions": []
  },
  "file_name": "1.12.251.79",
  "file_mimetype": null,
  "is_sample": false,
  "observable_name": "1.12.251.79",
  "observable_classification": "ip",
  "md5": "6e259096cc56e82df72d99894828f30e",
  "analyzer_reports": [
    {
      "name": "Shodan_Search",
      "process_time": 0.68,
      "status": "FAILED",
      "end_time": "2026-03-06T09:07:18.059391Z",
      "parameters": {
        "shodan_analysis": "search"
      },
      "type": "analyzer",
      "id": 25399,
      "report": {},
      "errors": [
        "403 Client Error: Forbidden for url: https://api.shodan.io/shodan/host/1.12.251.79?key=WOT76YxsAVmMhRV1ViVLpgXKrBq8B6v8&minify=True"
      ],
      "start_time": "2026-03-06T09:07:17.382615Z",
      "data_model": null,
      "description": "scan an IP against Shodan Search API"
    },
    {
      "name": "FireHol_IPList",
      "process_time": 0.34,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:17.703839Z",
      "parameters": {
        "list_names": [
          "firehol_level1.netset"
        ]
      },
      "type": "analyzer",
      "id": 25395,
      "report": {
        "firehol_level1.netset": false
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.362663Z",
      "data_model": null,
      "description": "Check if an IP is in FireHol's IPList. Refer to [FireHol's IPList](https://iplists.firehol.org/)."
    },
    {
      "name": "InQuest_REPdb",
      "process_time": 0.76,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.123547Z",
      "parameters": {
        "inquest_analysis": "repdb_search"
      },
      "type": "analyzer",
      "id": 25397,
      "report": {
        "data": [
          {
            "data": "1.12.251.79",
            "source": "blocklist",
            "derived": "45090",
            "data_type": "ip",
            "source_url": "http://lists.blocklist.de",
            "created_date": "2026-02-06T11:57:49",
            "derived_type": "asn_num"
          }
        ],
        "link": "https://labs.inquest.net/repdb",
        "success": true
      },
      "errors": [
        "No API key retrieved"
      ],
      "start_time": "2026-03-06T09:07:17.367001Z",
      "data_model": null,
      "description": "Reputation Database - search REPdb"
    },
    {
      "name": "ApiVoid",
      "process_time": 0.96,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.319666Z",
      "parameters": {},
      "type": "analyzer",
      "id": 25393,
      "report": {
        "ip": "1.12.251.79",
        "asn": {
          "asn": "AS45090",
          "org": "Shenzhen Tencent Computer Systems Company",
          "rir": "APNIC",
          "type": "business",
          "route": "1.12.0.0/14",
          "asname": "TENCENT-NET-AP",
          "domain": "tencent.com",
          "status": "active",
          "address": "Tencent Building, Kejizhongyi Avenue, Hi-techPark,Nanshan District,Shenzhen",
          "created": "2010-05-11",
          "updated": "2021-10-27",
          "abuse_email": "tencent_noc@tencent.com",
          "country_code": "CN",
          "total_ipv4_ips": 12644608,
          "days_since_created": 5778,
          "days_since_updated": 1591,
          "total_ipv4_prefixes": 2257,
          "total_ipv6_prefixes": 47
        },
        "version": "IPv4",
        "anonymity": {
          "is_tor": false,
          "is_vpn": false,
          "is_proxy": false,
          "is_relay": false,
          "is_hosting": true,
          "is_webproxy": false,
          "is_residential_proxy": false
        },
        "blacklists": {
          "engines": {
            "0": {
              "name": "0spam",
              "detected": false,
              "reference": "https://0spam.org/",
              "elapsed_ms": 0
            },
            "1": {
              "name": "Anti-Attacks BL",
              "detected": false,
              "reference": "https://www.anti-attacks.com/",
              "elapsed_ms": 0
            },
            "2": {
              "name": "AntiSpam_by_CleanTalk",
              "detected": false,
              "reference": "https://cleantalk.org/",
              "elapsed_ms": 0
            },
            "3": {
              "name": "APEWS-L2",
              "detected": false,
              "reference": "http://www.apews.org/",
              "elapsed_ms": 0
            },
            "4": {
              "name": "AZORult Tracker",
              "detected": false,
              "reference": "https://azorult-tracker.net/",
              "elapsed_ms": 0
            },
            "5": {
              "name": "Backscatterer",
              "detected": false,
              "reference": "https://www.backscatterer.org/",
              "elapsed_ms": 164
            },
            "6": {
              "name": "Barracuda_Reputation_BL",
              "detected": false,
              "reference": "https://barracudacentral.org/lookups",
              "elapsed_ms": 67
            },
            "7": {
              "name": "BitNinja",
              "detected": true,
              "reference": "https://bitninja.com/",
              "elapsed_ms": 0
            },
            "8": {
              "name": "BlockedServersRBL",
              "detected": false,
              "reference": "https://www.blockedservers.com/",
              "elapsed_ms": 280
            },
            "9": {
              "name": "Blocklist.net.ua",
              "detected": false,
              "reference": "https://blocklist.net.ua/",
              "elapsed_ms": 0
            },
            "10": {
              "name": "BlockList_de",
              "detected": false,
              "reference": "https://www.blocklist.de/",
              "elapsed_ms": 0
            },
            "11": {
              "name": "Botscout (Last Caught)",
              "detected": false,
              "reference": "https://botscout.com/",
              "elapsed_ms": 0
            },
            "12": {
              "name": "Botvrij.eu",
              "detected": false,
              "reference": "https://botvrij.eu/",
              "elapsed_ms": 0
            },
            "13": {
              "name": "Brute Force Blocker",
              "detected": false,
              "reference": "https://danger.rulez.sk/index.php/bruteforceblocker/",
              "elapsed_ms": 0
            },
            "14": {
              "name": "Bsdly",
              "detected": false,
              "reference": "https://www.bsdly.net/",
              "elapsed_ms": 0
            },
            "15": {
              "name": "Charles Haley",
              "detected": false,
              "reference": "https://charles.the-haleys.org/",
              "elapsed_ms": 0
            },
            "16": {
              "name": "CI Army List",
              "detected": false,
              "reference": "https://cinsscore.com/#list",
              "elapsed_ms": 0
            },
            "17": {
              "name": "CSpace Hostings IP BL",
              "detected": false,
              "reference": "https://cspacehostings.com/",
              "elapsed_ms": 0
            },
            "18": {
              "name": "Darklist.de",
              "detected": false,
              "reference": "https://www.darklist.de/",
              "elapsed_ms": 0
            },
            "19": {
              "name": "Dataplane.org",
              "detected": false,
              "reference": "https://dataplane.org/",
              "elapsed_ms": 0
            },
            "20": {
              "name": "EFnet_RBL",
              "detected": false,
              "reference": "https://rbl.efnetrbl.org/multicheck.php",
              "elapsed_ms": 105
            },
            "21": {
              "name": "ELLIO IP Feed",
              "detected": false,
              "reference": "https://ellio.tech/",
              "elapsed_ms": 0
            },
            "22": {
              "name": "Etnetera BL",
              "detected": false,
              "reference": "https://security.etnetera.cz/",
              "elapsed_ms": 0
            },
            "23": {
              "name": "Feodo Tracker",
              "detected": false,
              "reference": "https://feodotracker.abuse.ch/",
              "elapsed_ms": 0
            },
            "24": {
              "name": "FSpamList",
              "detected": false,
              "reference": "https://fspamlist.com/",
              "elapsed_ms": 0
            },
            "25": {
              "name": "GPF DNS Block List",
              "detected": false,
              "reference": "https://www.gpf-comics.com/dnsbl/export.php",
              "elapsed_ms": 0
            },
            "26": {
              "name": "GreenSnow Blocklist",
              "detected": false,
              "reference": "https://greensnow.co/",
              "elapsed_ms": 0
            },
            "27": {
              "name": "HoneyDB",
              "detected": false,
              "reference": "https://honeydb.io/",
              "elapsed_ms": 0
            },
            "28": {
              "name": "ImproWare Antispam",
              "detected": false,
              "reference": "https://antispam.imp.ch/",
              "elapsed_ms": 211
            },
            "29": {
              "name": "InterServer IP List",
              "detected": false,
              "reference": "https://sigs.interserver.net/",
              "elapsed_ms": 0
            },
            "30": {
              "name": "IPSpamList",
              "detected": false,
              "reference": "https://www.ipspamlist.com/ip-lookup/",
              "elapsed_ms": 0
            },
            "31": {
              "name": "IPsum",
              "detected": true,
              "reference": "https://github.com/stamparm/ipsum",
              "elapsed_ms": 0
            },
            "32": {
              "name": "IPThreat",
              "detected": false,
              "reference": "https://ipthreat.net/",
              "elapsed_ms": 0
            },
            "33": {
              "name": "ISX.fr DNSBL",
              "detected": false,
              "reference": "https://bl.isx.fr/",
              "elapsed_ms": 0
            },
            "34": {
              "name": "JamesBrine IP List",
              "detected": false,
              "reference": "https://jamesbrine.com.au/",
              "elapsed_ms": 0
            },
            "35": {
              "name": "JustSpam_org",
              "detected": false,
              "reference": "http://www.justspam.org/",
              "elapsed_ms": 167
            },
            "36": {
              "name": "Known Scanning Service",
              "detected": false,
              "reference": "https://www.novirusthanks.org/",
              "elapsed_ms": 0
            },
            "37": {
              "name": "LAPPS Grid Blacklist",
              "detected": false,
              "reference": "https://lappsgrid.org/",
              "elapsed_ms": 0
            },
            "38": {
              "name": "Liquid Binary",
              "detected": false,
              "reference": "https://liquidbinary.com/",
              "elapsed_ms": 0
            },
            "39": {
              "name": "M4lwhere Intel",
              "detected": false,
              "reference": "https://m4lwhere.org/",
              "elapsed_ms": 0
            },
            "40": {
              "name": "Mark Smith Blocked IPs",
              "detected": false,
              "reference": "https://www.marksmith.it/",
              "elapsed_ms": 0
            },
            "41": {
              "name": "Montysecurity",
              "detected": false,
              "reference": "https://github.com/montysecurity/C2-Tracker",
              "elapsed_ms": 0
            },
            "42": {
              "name": "Myip.ms Blacklist",
              "detected": false,
              "reference": "https://myip.ms/browse/blacklist",
              "elapsed_ms": 0
            },
            "43": {
              "name": "NERD CESNET",
              "detected": false,
              "reference": "https://nerd.cesnet.cz/",
              "elapsed_ms": 0
            },
            "44": {
              "name": "NEU SSH Black list",
              "detected": false,
              "reference": "http://antivirus.neu.edu.cn/scan/",
              "elapsed_ms": 0
            },
            "45": {
              "name": "Nginx Bad Bot Blocker",
              "detected": false,
              "reference": "https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker",
              "elapsed_ms": 0
            },
            "46": {
              "name": "NOC_RUB_DE",
              "detected": false,
              "reference": "https://noc.rub.de/web/",
              "elapsed_ms": 0
            },
            "47": {
              "name": "NoIntegrity BL",
              "detected": false,
              "reference": "https://www.nointegrity.org/",
              "elapsed_ms": 0
            },
            "48": {
              "name": "NordSpam",
              "detected": false,
              "reference": "https://www.nordspam.com/",
              "elapsed_ms": 0
            },
            "49": {
              "name": "NoVirusThanks",
              "detected": false,
              "reference": "https://www.novirusthanks.com/",
              "elapsed_ms": 0
            },
            "50": {
              "name": "NUBI Bad IPs",
              "detected": false,
              "reference": "https://www.nubi-network.com/",
              "elapsed_ms": 0
            },
            "51": {
              "name": "Null Route Networks",
              "detected": false,
              "reference": "https://www.nullroutenetworks.com/",
              "elapsed_ms": 0
            },
            "52": {
              "name": "OpenPhish",
              "detected": false,
              "reference": "https://www.openphish.com/",
              "elapsed_ms": 0
            },
            "53": {
              "name": "Peter-s NUUG IP BL",
              "detected": false,
              "reference": "https://home.nuug.no/~peter/",
              "elapsed_ms": 0
            },
            "54": {
              "name": "PhishTank",
              "detected": false,
              "reference": "https://www.phishtank.com/",
              "elapsed_ms": 0
            },
            "55": {
              "name": "PlonkatronixBL",
              "detected": false,
              "reference": "https://plonkatronix.com/",
              "elapsed_ms": 0
            },
            "56": {
              "name": "PSBL",
              "detected": false,
              "reference": "https://psbl.org/",
              "elapsed_ms": 51
            },
            "57": {
              "name": "Redstout Threat IP list",
              "detected": false,
              "reference": "https://www.redstout.com/",
              "elapsed_ms": 0
            },
            "58": {
              "name": "Ring-u NOC",
              "detected": false,
              "reference": "https://portal.ring-u.com/portal/portal.php",
              "elapsed_ms": 0
            },
            "59": {
              "name": "RJM Blocklist",
              "detected": false,
              "reference": "https://rjmblocklist.com/",
              "elapsed_ms": 0
            },
            "60": {
              "name": "Rutgers Drop List",
              "detected": false,
              "reference": "https://www.rutgers.edu/",
              "elapsed_ms": 0
            },
            "61": {
              "name": "S5hbl",
              "detected": true,
              "reference": "https://www.usenix.org.uk/content/rbl.html",
              "elapsed_ms": 48
            },
            "62": {
              "name": "Sblam",
              "detected": false,
              "reference": "https://sblam.com/",
              "elapsed_ms": 0
            },
            "63": {
              "name": "SpamCop",
              "detected": false,
              "reference": "https://www.spamcop.net/",
              "elapsed_ms": 25
            },
            "64": {
              "name": "SpamRATS",
              "detected": false,
              "reference": "https://www.spamrats.com/",
              "elapsed_ms": 103
            },
            "65": {
              "name": "SSL Blacklist",
              "detected": false,
              "reference": "https://sslbl.abuse.ch/",
              "elapsed_ms": 0
            },
            "66": {
              "name": "Stratosphere Research",
              "detected": false,
              "reference": "https://www.stratosphereips.org/",
              "elapsed_ms": 0
            },
            "67": {
              "name": "Talos IP Blacklist",
              "detected": false,
              "reference": "https://www.talosintelligence.com/",
              "elapsed_ms": 0
            },
            "68": {
              "name": "Threat Crowd",
              "detected": false,
              "reference": "https://www.threatcrowd.org/",
              "elapsed_ms": 0
            },
            "69": {
              "name": "Threat Sourcing",
              "detected": false,
              "reference": "https://www.threatsourcing.com/",
              "elapsed_ms": 0
            },
            "70": {
              "name": "ThreatLog",
              "detected": false,
              "reference": "https://www.threatlog.com/",
              "elapsed_ms": 0
            },
            "71": {
              "name": "Threatview",
              "detected": false,
              "reference": "https://threatview.io/",
              "elapsed_ms": 0
            },
            "72": {
              "name": "TweetFeed",
              "detected": false,
              "reference": "https://github.com/0xDanielLopez/TweetFeed",
              "elapsed_ms": 0
            },
            "73": {
              "name": "UCEPROTECT Level 1",
              "detected": false,
              "reference": "https://www.uceprotect.net/en/index.php",
              "elapsed_ms": 0
            },
            "74": {
              "name": "URLhaus",
              "detected": false,
              "reference": "https://urlhaus.abuse.ch/",
              "elapsed_ms": 0
            },
            "75": {
              "name": "USTC IP BL",
              "detected": false,
              "reference": "http://blackip.ustc.edu.cn/",
              "elapsed_ms": 0
            },
            "76": {
              "name": "ViriBack C2 Tracker",
              "detected": false,
              "reference": "https://tracker.viriback.com/",
              "elapsed_ms": 0
            },
            "77": {
              "name": "VoIP Blacklist",
              "detected": false,
              "reference": "https://www.voipbl.org/",
              "elapsed_ms": 0
            },
            "78": {
              "name": "VXVault",
              "detected": false,
              "reference": "https://www.voipbl.org/",
              "elapsed_ms": 0
            }
          },
          "detections": 3,
          "scan_time_ms": 281,
          "engines_count": 79,
          "detection_rate": "3%"
        },
        "elapsed_ms": 522,
        "risk_score": {
          "result": 70
        },
        "information": {
          "asn": "AS45090",
          "isp": "Tencent Cloud Computing (Beijing) Co. Ltd.",
          "is_eu": false,
          "currency": "CNY",
          "is_bogon": false,
          "latitude": 23.127361,
          "city_name": "Guangzhou",
          "longitude": 113.26457,
          "emoji_flag": "🇨🇳",
          "aws_service": "",
          "is_fake_bot": false,
          "region_name": "Guangdong",
          "reverse_dns": "",
          "calling_code": "86",
          "country_code": "CN",
          "country_name": "China",
          "edge_service": "",
          "is_satellite": false,
          "currency_name": "Chinese Yuan",
          "is_google_bot": false,
          "is_public_dns": false,
          "cloud_provider": "Tencent Cloud",
          "continent_code": "AS",
          "continent_name": "Asia",
          "currency_symbol": "CN¥",
          "is_spamhaus_drop": false,
          "is_google_service": false,
          "emoji_flag_unicode": "U+1F1E8 U+1F1F3",
          "edge_service_domain": "",
          "currency_name_plural": "Chinese yuan",
          "is_search_engine_bot": false,
          "related_service_name": "",
          "related_service_type": "",
          "cloud_provider_domain": "tencentcloud.com",
          "currency_symbol_native": "CN¥",
          "related_service_domain": "",
          "is_major_provider_spf_ip": false
        }
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.363657Z",
      "data_model": null,
      "description": "[ApiVoid](https://www.apivoid.com/) provides JSON APIs useful for cyber threat analysis, threat detection and threat prevention, reducing and automating the manual work of security analysts."
    },
    {
      "name": "VirusTotal_v3_Get_Observable",
      "process_time": 0.98,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.368747Z",
      "parameters": {
        "max_tries": 10,
        "url_sub_path": "",
        "poll_distance": 30,
        "rescan_max_tries": 5,
        "rescan_poll_distance": 120,
        "include_sigma_analyses": true,
        "relationships_elements": 1,
        "force_active_scan_if_old": false,
        "relationships_to_request": [],
        "include_behaviour_summary": true,
        "days_to_say_that_a_scan_is_old": 30
      },
      "type": "analyzer",
      "id": 25405,
      "report": {
        "data": {
          "id": "1.12.251.79",
          "type": "ip_address",
          "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79"
          },
          "attributes": {
            "asn": 45090,
            "jarm": "3fd3fd0003fd3fd21c42d42d000000bdfc58c9a46434368cf60aa440385763",
            "rdap": {
              "name": "TencentCloud",
              "type": "ALLOCATED PORTABLE",
              "links": [
                {
                  "rel": "self",
                  "href": "https://rdap.apnic.net/ip/1.12.0.0/14",
                  "type": "application/rdap+json",
                  "media": "",
                  "title": "",
                  "value": "https://rdap.apnic.net/ip/1.12.251.79",
                  "href_lang": []
                }
              ],
              "events": [
                {
                  "links": [],
                  "event_date": "2010-05-10T22:46:58Z",
                  "event_actor": "",
                  "event_action": "registration"
                },
                {
                  "links": [],
                  "event_date": "2023-11-28T00:51:33Z",
                  "event_actor": "",
                  "event_action": "last changed"
                }
              ],
              "handle": "1.12.0.0 - 1.15.255.255",
              "port43": "whois.apnic.net",
              "status": [
                "active"
              ],
              "country": "CN",
              "notices": [
                {
                  "type": "",
                  "links": [],
                  "title": "Source",
                  "description": [
                    "Objects returned came from source",
                    "APNIC"
                  ]
                },
                {
                  "type": "",
                  "links": [
                    {
                      "rel": "terms-of-service",
                      "href": "http://www.apnic.net/db/dbcopyright.html",
                      "type": "text/html",
                      "media": "",
                      "title": "",
                      "value": "https://rdap.apnic.net/ip/1.12.251.79",
                      "href_lang": []
                    }
                  ],
                  "title": "Terms and Conditions",
                  "description": [
                    "This is the APNIC WHOIS Database query service. The objects are in RDAP format."
                  ]
                },
                {
                  "type": "",
                  "links": [
                    {
                      "rel": "inaccuracy-report",
                      "href": "https://www.apnic.net/manage-ip/using-whois/abuse-and-spamming/invalid-contact-form",
                      "type": "text/html",
                      "media": "",
                      "title": "",
                      "value": "https://rdap.apnic.net/ip/1.12.251.79",
                      "href_lang": []
                    }
                  ],
                  "title": "Whois Inaccuracy Reporting",
                  "description": [
                    "If you see inaccuracies in the results, please visit: "
                  ]
                }
              ],
              "remarks": [
                {
                  "type": "",
                  "links": [],
                  "title": "description",
                  "description": [
                    "Tencent cloud computing (Beijing) Co., Ltd.",
                    "Floor 6, Yinke Building,38 Haidian St,",
                    "Haidian District Beijing"
                  ]
                }
              ],
              "entities": [
                {
                  "url": "",
                  "lang": "",
                  "links": [],
                  "roles": [
                    "abuse"
                  ],
                  "events": [],
                  "handle": "",
                  "port43": "",
                  "status": [],
                  "autnums": [],
                  "remarks": [],
                  "entities": [],
                  "networks": [],
                  "public_ids": [],
                  "vcard_array": [],
                  "as_event_actor": [],
                  "rdap_conformance": [],
                  "object_class_name": ""
                },
                {
                  "url": "",
                  "lang": "",
                  "links": [
                    {
                      "rel": "self",
                      "href": "https://rdap.apnic.net/entity/JX1747-AP",
                      "type": "application/rdap+json",
                      "media": "",
                      "title": "",
                      "value": "https://rdap.apnic.net/ip/1.12.251.79",
                      "href_lang": []
                    }
                  ],
                  "roles": [
                    "technical"
                  ],
                  "events": [
                    {
                      "links": [],
                      "event_date": "2013-11-04T03:12:01Z",
                      "event_actor": "",
                      "event_action": "registration"
                    },
                    {
                      "links": [],
                      "event_date": "2021-09-17T00:38:09Z",
                      "event_actor": "",
                      "event_action": "last changed"
                    }
                  ],
                  "handle": "JX1747-AP",
                  "port43": "",
                  "status": [],
                  "autnums": [],
                  "remarks": [],
                  "entities": [],
                  "networks": [],
                  "public_ids": [],
                  "vcard_array": [
                    {
                      "name": "version",
                      "type": "text",
                      "values": [
                        "4.0"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "fn",
                      "type": "text",
                      "values": [
                        "Jimmy Xiao"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "kind",
                      "type": "text",
                      "values": [
                        "individual"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "adr",
                      "type": "text",
                      "values": [
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""
                      ],
                      "parameters": {
                        "label": [
                          "9F, FIYTA Building, Gaoxinnanyi Road,Southern\nDistrict of Hi-tech Park, Shenzhen"
                        ]
                      }
                    },
                    {
                      "name": "tel",
                      "type": "text",
                      "values": [
                        "+86-755-86013388-80224"
                      ],
                      "parameters": {
                        "type": [
                          "voice"
                        ]
                      }
                    },
                    {
                      "name": "email",
                      "type": "text",
                      "values": [
                        "klayliang@tencent.com"
                      ],
                      "parameters": {}
                    }
                  ],
                  "as_event_actor": [],
                  "rdap_conformance": [],
                  "object_class_name": "entity"
                },
                {
                  "url": "",
                  "lang": "",
                  "links": [
                    {
                      "rel": "self",
                      "href": "https://rdap.apnic.net/entity/JT1125-AP",
                      "type": "application/rdap+json",
                      "media": "",
                      "title": "",
                      "value": "https://rdap.apnic.net/ip/1.12.251.79",
                      "href_lang": []
                    }
                  ],
                  "roles": [
                    "administrative"
                  ],
                  "events": [
                    {
                      "links": [],
                      "event_date": "2013-11-04T03:12:01Z",
                      "event_actor": "",
                      "event_action": "registration"
                    },
                    {
                      "links": [],
                      "event_date": "2024-03-19T08:21:31Z",
                      "event_actor": "",
                      "event_action": "last changed"
                    }
                  ],
                  "handle": "JT1125-AP",
                  "port43": "",
                  "status": [],
                  "autnums": [],
                  "remarks": [],
                  "entities": [],
                  "networks": [],
                  "public_ids": [],
                  "vcard_array": [
                    {
                      "name": "version",
                      "type": "text",
                      "values": [
                        "4.0"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "fn",
                      "type": "text",
                      "values": [
                        "James Tian"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "kind",
                      "type": "text",
                      "values": [
                        "individual"
                      ],
                      "parameters": {}
                    },
                    {
                      "name": "adr",
                      "type": "text",
                      "values": [
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""
                      ],
                      "parameters": {
                        "label": [
                          "9F, FIYTA Building, Gaoxinnanyi Road,Southern\nDistrict of Hi-tech Park, Shenzhen"
                        ]
                      }
                    },
                    {
                      "name": "tel",
                      "type": "text",
                      "values": [
                        "+86-755-86013388-84952"
                      ],
                      "parameters": {
                        "type": [
                          "voice"
                        ]
                      }
                    },
                    {
                      "name": "email",
                      "type": "text",
                      "values": [
                        "johnsonqu@tencent.com"
                      ],
                      "parameters": {}
                    }
                  ],
                  "as_event_actor": [],
                  "rdap_conformance": [],
                  "object_class_name": "entity"
                }
              ],
              "ip_version": "v4",
              "cidr0_cidrs": [
                {
                  "length": 14,
                  "v4prefix": "1.12.0.0",
                  "v6prefix": ""
                }
              ],
              "end_address": "1.15.255.255",
              "parent_handle": "",
              "start_address": "1.12.0.0",
              "rdap_conformance": [
                "history_version_0",
                "nro_rdap_profile_0",
                "cidr0",
                "rdap_level_0"
              ],
              "object_class_name": "ip network",
              "arin_originas0_originautnums": []
            },
            "tags": [],
            "whois": "inetnum: 1.12.0.0 - 1.15.255.255\nnetname: TencentCloud\ndescr: Tencent cloud computing (Beijing) Co., Ltd.\ndescr: Floor 6, Yinke Building,38 Haidian St,\ndescr: Haidian District Beijing\ncountry: CN\nadmin-c: JT1125-AP\ntech-c: JX1747-AP\nabuse-c: AC1601-AP\nstatus: ALLOCATED PORTABLE\nmnt-by: MAINT-CNNIC-AP\nmnt-irt: IRT-TENCENTCLOUD-CN\nmnt-lower: MAINT-CNNIC-AP\nmnt-routes: MAINT-CNNIC-AP\nlast-modified: 2023-11-28T00:51:33Z\nsource: APNIC\nirt: IRT-TencentCloud-CN\naddress: 9F, FIYTA Building, Gaoxinnanyi Road, Southern\naddress: District of Hi-tech Park, Shenzhen\ne-mail: tencent_noc@tencent.com\nadmin-c: JT1125-AP\ntech-c: JX1747-AP\nabuse-mailbox: abuse@tencent.com\nremarks: abuse@tencent.com was validated on 2025-10-29\nremarks: tencent_noc@tencent.com was validated on 2025-10-29\nauth: # Filtered\nmnt-by: MAINT-CNNIC-AP\nlast-modified: 2025-11-18T00:34:40Z\nsource: APNIC\nrole: ABUSE CNNICCN\ncountry: ZZ\naddress: Beijing, China\nphone: +000000000\ne-mail: ipas@cnnic.cn\nadmin-c: IP50-AP\ntech-c: IP50-AP\nnic-hdl: AC1601-AP\nremarks: Generated from irt object IRT-CNNIC-CN\nremarks: ipas@cnnic.cn is invalid\nabuse-mailbox: ipas@cnnic.cn\nmnt-by: APNIC-ABUSE\nlast-modified: 2025-09-19T17:20:32Z\nsource: APNIC\nperson: James Tian\naddress: 9F, FIYTA Building, Gaoxinnanyi Road,Southern\naddress: District of Hi-tech Park, Shenzhen\ncountry: CN\nphone: +86-755-86013388-84952\ne-mail: johnsonqu@tencent.com\nnic-hdl: JT1125-AP\nmnt-by: MAINT-CNNIC-AP\nlast-modified: 2024-03-19T08:21:31Z\nsource: APNIC\nperson: Jimmy Xiao\naddress: 9F, FIYTA Building, Gaoxinnanyi Road,Southern\naddress: District of Hi-tech Park, Shenzhen\ncountry: CN\nphone: +86-755-86013388-80224\ne-mail: klayliang@tencent.com\nnic-hdl: JX1747-AP\nmnt-by: MAINT-CNNIC-AP\nlast-modified: 2021-09-17T00:38:09Z\nsource: APNIC\nroute: 1.12.0.0/14\norigin: AS45090\ndescr: China Internet Network Information Center\n Floor1, Building No.1 C/-Chinese Academy of Sciences\n 4, South 4th Street\n Haidian District,\nmnt-by: MAINT-CNNIC-AP\nlast-modified: 2020-02-25T01:10:58Z\nsource: APNIC\n",
            "country": "CN",
            "network": "1.12.128.0/17",
            "as_owner": "Shenzhen Tencent Computer Systems Company Limited",
            "continent": "AS",
            "reputation": 0,
            "whois_date": 1767832854,
            "total_votes": {
              "harmless": 0,
              "malicious": 0
            },
            "last_analysis_date": 1770386632,
            "last_analysis_stats": {
              "timeout": 0,
              "harmless": 58,
              "malicious": 5,
              "suspicious": 4,
              "undetected": 27
            },
            "last_analysis_results": {
              "Axur": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Axur"
              },
              "Bkav": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Bkav"
              },
              "CRDF": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "CRDF"
              },
              "Cyan": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Cyan"
              },
              "DNS8": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "DNS8"
              },
              "ESET": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ESET"
              },
              "Lumu": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Lumu"
              },
              "Cyble": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Cyble"
              },
              "Ermes": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Ermes"
              },
              "IPsum": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "IPsum"
              },
              "VIPRE": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "VIPRE"
              },
              "Abusix": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Abusix"
              },
              "Dr.Web": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Dr.Web"
              },
              "G-Data": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "G-Data"
              },
              "Lionic": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Lionic"
              },
              "Sophos": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Sophos"
              },
              "Acronis": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Acronis"
              },
              "Blueliv": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Blueliv"
              },
              "Certego": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Certego"
              },
              "CyRadar": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "CyRadar"
              },
              "Quttera": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Quttera"
              },
              "Spam404": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Spam404"
              },
              "URLhaus": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "URLhaus"
              },
              "Webroot": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Webroot"
              },
              "ZeroFox": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "ZeroFox"
              },
              "AlphaSOC": {
                "method": "blacklist",
                "result": "suspicious",
                "category": "suspicious",
                "engine_name": "AlphaSOC"
              },
              "AutoShun": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "AutoShun"
              },
              "Emsisoft": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Emsisoft"
              },
              "Fortinet": {
                "method": "blacklist",
                "result": "malware",
                "category": "malicious",
                "engine_name": "Fortinet"
              },
              "Guardpot": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Guardpot"
              },
              "Malwared": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Malwared"
              },
              "Mimecast": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Mimecast"
              },
              "Netcraft": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Netcraft"
              },
              "PREBYTES": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "PREBYTES"
              },
              "SOCRadar": {
                "method": "blacklist",
                "result": "suspicious",
                "category": "suspicious",
                "engine_name": "SOCRadar"
              },
              "URLQuery": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "URLQuery"
              },
              "VX Vault": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "VX Vault"
              },
              "ViriBack": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ViriBack"
              },
              "ZeroCERT": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ZeroCERT"
              },
              "0xSI_f33d": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "0xSI_f33d"
              },
              "Antiy-AVL": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Antiy-AVL"
              },
              "CINS Army": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "CINS Army"
              },
              "Cluster25": {
                "method": "blacklist",
                "result": "malicious",
                "category": "malicious",
                "engine_name": "Cluster25"
              },
              "GreenSnow": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "GreenSnow"
              },
              "GreyNoise": {
                "method": "blacklist",
                "result": "malicious",
                "category": "malicious",
                "engine_name": "GreyNoise"
              },
              "Kaspersky": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Kaspersky"
              },
              "OpenPhish": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "OpenPhish"
              },
              "PhishFort": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "PhishFort"
              },
              "PhishLabs": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "PhishLabs"
              },
              "Phishtank": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Phishtank"
              },
              "Scantitan": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Scantitan"
              },
              "Seclookup": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Seclookup"
              },
              "Trustwave": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Trustwave"
              },
              "benkow.cc": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "benkow.cc"
              },
              "AlienVault": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "AlienVault"
              },
              "Gridinsoft": {
                "method": "blacklist",
                "result": "suspicious",
                "category": "suspicious",
                "engine_name": "Gridinsoft"
              },
              "MalwareURL": {
                "method": "blacklist",
                "result": "malware",
                "category": "malicious",
                "engine_name": "MalwareURL"
              },
              "Quick Heal": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Quick Heal"
              },
              "SafeToOpen": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "SafeToOpen"
              },
              "ThreatHive": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ThreatHive"
              },
              "ADMINUSLabs": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ADMINUSLabs"
              },
              "BitDefender": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "BitDefender"
              },
              "ChainPatrol": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "ChainPatrol"
              },
              "Criminal IP": {
                "method": "blacklist",
                "result": "malicious",
                "category": "malicious",
                "engine_name": "Criminal IP"
              },
              "ESTsecurity": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "ESTsecurity"
              },
              "SecureBrain": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "SecureBrain"
              },
              "PrecisionSec": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "PrecisionSec"
              },
              "SCUMWARE.org": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "SCUMWARE.org"
              },
              "securolytics": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "securolytics"
              },
              "Chong Lua Dao": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Chong Lua Dao"
              },
              "MalwarePatrol": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "MalwarePatrol"
              },
              "StopForumSpam": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "StopForumSpam"
              },
              "EmergingThreats": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "EmergingThreats"
              },
              "Sansec eComscan": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Sansec eComscan"
              },
              "desenmascara.me": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "desenmascara.me"
              },
              "Heimdal Security": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Heimdal Security"
              },
              "Juniper Networks": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Juniper Networks"
              },
              "Sucuri SiteCheck": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Sucuri SiteCheck"
              },
              "alphaMountain.ai": {
                "method": "blacklist",
                "result": "suspicious",
                "category": "suspicious",
                "engine_name": "alphaMountain.ai"
              },
              "Bfore.Ai PreCrime": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Bfore.Ai PreCrime"
              },
              "Phishing Database": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Phishing Database"
              },
              "AILabs (MONITORAPP)": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "AILabs (MONITORAPP)"
              },
              "CSIS Security Group": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "CSIS Security Group"
              },
              "Google Safebrowsing": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Google Safebrowsing"
              },
              "Yandex Safebrowsing": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Yandex Safebrowsing"
              },
              "Hunt.io Intelligence": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Hunt.io Intelligence"
              },
              "Snort IP sample list": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Snort IP sample list"
              },
              "Xcitium Verdict Cloud": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Xcitium Verdict Cloud"
              },
              "GCP Abuse Intelligence": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "GCP Abuse Intelligence"
              },
              "CMC Threat Intelligence": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "CMC Threat Intelligence"
              },
              "Forcepoint ThreatSeeker": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "Forcepoint ThreatSeeker"
              },
              "malwares.com URL checker": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "malwares.com URL checker"
              },
              "Viettel Threat Intelligence": {
                "method": "blacklist",
                "result": "clean",
                "category": "harmless",
                "engine_name": "Viettel Threat Intelligence"
              },
              "ArcSight Threat Intelligence": {
                "method": "blacklist",
                "result": "unrated",
                "category": "undetected",
                "engine_name": "ArcSight Threat Intelligence"
              }
            },
            "last_https_certificate": {
              "size": 1283,
              "issuer": {
                "C": "US",
                "O": "Let's Encrypt",
                "CN": "R12"
              },
              "subject": {
                "CN": "tmavc.mavk.cn"
              },
              "version": "V3",
              "validity": {
                "not_after": "2026-05-07 12:53:15",
                "not_before": "2026-02-06 12:53:16"
              },
              "extensions": {
                "CA": false,
                "key_usage": [
                  "digitalSignature",
                  "keyEncipherment"
                ],
                "extended_key_usage": [
                  "serverAuth",
                  "clientAuth"
                ],
                "certificate_policies": [
                  "2.23.140.1.2.1"
                ],
                "ca_information_access": {
                  "CA Issuers": "http://r12.i.lencr.org/"
                },
                "subject_key_identifier": "a206ac81336a59b45ae54178f65ca0d83a9101fd",
                "1.3.6.1.4.1.11129.2.4.2": "0481fb00f900760016832dabf0a9250f0ff03aa545ffc8bfc823d0874bf60429",
                "crl_distribution_points": [
                  "http://r12.c.lencr.org/20.crl"
                ],
                "authority_key_identifier": {
                  "keyid": "00b529f22d8e6f31e89b4cad783efadce90cd1d2"
                },
                "subject_alternative_name": [
                  "tmavc.mavk.cn"
                ]
              },
              "public_key": {
                "rsa": {
                  "modulus": "bef7cca64d2f178814e8e9f009c1ee3e8ec4f20c3016e3cef817bdbf6ba7cb03a605f8364ff551d69366a9dd941135b2b859d281b7c6f57c990fbc9d15294a4811e331130f0fecad1e7db0755111f8934d0e5cc0c893e86faae5402af0e479fe17102d92ea1da02c8bea003d02b00a49a01e8da1efb8d208dcdf926a6384f742a15a32b555f0f677fa5d682194c741091ed261a428a20345483f74ae49c0ef1238eb5131ff7db363cc49b52d38a88c67064c4003d42a7ca5bc31f3855af20817101955d45dd02e4af8217533dde888ca8d070922366f641e143b8f1e97b7d3cdba50868a13dedfcec8c81ecaad1dfbce9d37781776453320267612ed764e51e7",
                  "exponent": "10001",
                  "key_size": 2048
                },
                "algorithm": "RSA"
              },
              "thumbprint": "9c48fa3cccd7705aa693c4f6923d343fb2d720ae",
              "serial_number": "61766bc8742684b26fc0cc977ddd4aacc13",
              "cert_signature": {
                "signature": "40af693a182ab0cb707ea3ea66debf240b439cc10a03fc5f7cc5052815c5f95eea0b7c9f5ff1d0426e619d28a42621c3d5fcc16275598000f3c27d27c6f984b90fc86a523a5494775339e8835c93304dece01475e8b80c618bae0664fbd6daf1630bd1acae5fa61716c917e7816634e95c35e6d0582551488a52836d67eaaca50601bfb4d28a03896b8d5361f14cce388e3c1373a5f1cc9a528a9aa88c68e1477e36c89ad350ea55cbcef051dc78ffcbfa8d3b38f4492a3d8c596572a52469093e9b951aad811e76d76c331163d1d56f4e5abaf84c8a563279983656e0d0eb7a1406397fa9c50619f9ba3fcdc267b0a2227296c93271cbb4067d78506f0443c7",
                "signature_algorithm": "sha256RSA"
              },
              "thumbprint_sha256": "94c198768c1f487dcff63e2c715f008d0e01073200a99e06e45c1a99c9b3ded2"
            },
            "last_modification_date": 1770386917,
            "regional_internet_registry": "APNIC",
            "last_https_certificate_date": 1770386916
          },
          "relationships": {
            "collections": {
              "data": [],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/collections?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/collections"
              }
            },
            "resolutions": {
              "data": [
                {
                  "id": "1.12.251.79rbsvcx.kxzu.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79rmacvb.kxzo.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79tmavc.mavk.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79trnbnd.ktbv.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79yyr.xxsq.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79wwuu.pt6f.cn",
                  "type": "resolution"
                },
                {
                  "id": "1.12.251.79hmcvb.rnvnr.cn",
                  "type": "resolution"
                }
              ],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/resolutions?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/resolutions"
              }
            },
            "referrer_files": {
              "data": [],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/referrer_files?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/referrer_files"
              }
            },
            "historical_whois": {
              "data": [
                {
                  "id": "fcbe4126d715e49ea87680891694348e27274b447a8dd6d53fc699ab6161031f",
                  "type": "whois"
                }
              ],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/historical_whois?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/historical_whois"
              }
            },
            "communicating_files": {
              "data": [],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/communicating_files?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/communicating_files"
              }
            },
            "historical_ssl_certificates": {
              "data": [
                {
                  "id": "94c198768c1f487dcff63e2c715f008d0e01073200a99e06e45c1a99c9b3ded2",
                  "type": "ssl_cert",
                  "context_attributes": {
                    "port": "443",
                    "first_seen_date": "2026-02-06"
                  }
                },
                {
                  "id": "f309fcf04652b3f7704ead5c0a293f223812a946d71617de85eeae4f42ed9725",
                  "type": "ssl_cert",
                  "context_attributes": {
                    "port": "443",
                    "first_seen_date": "2026-01-13"
                  }
                },
                {
                  "id": "905883e0c152e3e0fec292bed85b38b7c3cf52b9eefb16f9cf6ef16dc4e6f78a",
                  "type": "ssl_cert",
                  "context_attributes": {
                    "port": "443",
                    "first_seen_date": "2025-11-24"
                  }
                }
              ],
              "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/relationships/historical_ssl_certificates?limit=20",
                "related": "https://www.virustotal.com/api/v3/ip_addresses/1.12.251.79/historical_ssl_certificates"
              }
            }
          }
        },
        "link": "https://www.virustotal.com/gui/ip-address/1.12.251.79"
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.393536Z",
      "data_model": null,
      "description": "search an observable in the VirusTotal DB"
    },
    {
      "name": "UrlScan_Search",
      "process_time": 0.66,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.043559Z",
      "parameters": {
        "search_size": 100,
        "urlscan_analysis": "search"
      },
      "type": "analyzer",
      "id": 25404,
      "report": {
        "took": 271,
        "total": 0,
        "results": [],
        "has_more": false
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.388329Z",
      "data_model": null,
      "description": "Search an IP/domain/url/hash against [URLScan API](https://urlscan.io/docs/api/)."
    },
    {
      "name": "URLhaus",
      "process_time": 0.89,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.296063Z",
      "parameters": {
        "disable": false
      },
      "type": "analyzer",
      "id": 25403,
      "report": {
        "query_status": "no_results"
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.404694Z",
      "data_model": null,
      "description": "Query a domain or URL against URLhaus API"
    },
    {
      "name": "IPApi",
      "process_time": 0.91,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.275659Z",
      "parameters": {
        "lang": "",
        "fields": ""
      },
      "type": "analyzer",
      "id": 25396,
      "report": {
        "ip_info": [
          {
            "as": "AS45090 Shenzhen Tencent Computer Systems Company Limited",
            "isp": "China Internet Network Information Center",
            "lat": 23.1181,
            "lon": 113.2539,
            "org": "Tencent cloud computing (Beijing) Co., Ltd.",
            "zip": "",
            "city": "Guangzhou",
            "query": "1.12.251.79",
            "region": "GD",
            "status": "success",
            "country": "China",
            "timezone": "Asia/Shanghai",
            "regionName": "Guangdong",
            "countryCode": "CN"
          }
        ],
        "dns_info": {
          "dns": {
            "ip": "3.70.39.83",
            "geo": "Germany - Amazon Technologies Inc."
          },
          "edns": {
            "ip": "90.166.139.0",
            "geo": "Spain - Orange Espagne SA"
          }
        }
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.363229Z",
      "data_model": null,
      "description": "Gives information about [IPs](https://ip-api.com/docs/api:batch) and [DNS](https://ip-api.com/docs/dns)"
    },
    {
      "name": "TorProject",
      "process_time": 8.15,
      "status": "FAILED",
      "end_time": "2026-03-06T09:07:25.541824Z",
      "parameters": {},
      "type": "analyzer",
      "id": 25402,
      "report": {},
      "errors": [
        "Failed extraction of tor db"
      ],
      "start_time": "2026-03-06T09:07:17.392423Z",
      "data_model": null,
      "description": "check if an IP is a Tor Exit Node"
    },
    {
      "name": "ThreatFox",
      "process_time": 1.04,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.428448Z",
      "parameters": {
        "disable": false
      },
      "type": "analyzer",
      "id": 25401,
      "report": {
        "data": "Your search did not yield any results",
        "query_status": "no_result"
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.389139Z",
      "data_model": null,
      "description": "search for an IOC in ThreatFox's database"
    },
    {
      "name": "TalosReputation",
      "process_time": 0.08,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:17.456144Z",
      "parameters": {},
      "type": "analyzer",
      "id": 25400,
      "report": {
        "found": false
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.379276Z",
      "data_model": {
        "id": 5923,
        "analyzers_report": [
          25400
        ],
        "ietf_report": [],
        "evaluation": null,
        "reliability": 5,
        "kill_chain_phase": null,
        "external_references": [],
        "related_threats": [],
        "tags": null,
        "malware_family": null,
        "additional_info": {},
        "date": "2026-03-06T09:07:17.444025Z",
        "asn": null,
        "asn_rank": null,
        "certificates": null,
        "org_name": null,
        "country_code": null,
        "registered_country_code": null,
        "isp": null,
        "resolutions": []
      },
      "description": "check an IP reputation from Talos downloaded IP list"
    },
    {
      "name": "MalwareBazaar_Google_Observable",
      "process_time": 2.99,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:20.469912Z",
      "parameters": {},
      "type": "analyzer",
      "id": 25398,
      "report": {},
      "errors": [],
      "start_time": "2026-03-06T09:07:17.477310Z",
      "data_model": null,
      "description": "Check if a particular IP, domain or url is known to MalwareBazaar using google search"
    },
    {
      "name": "Crowdsec",
      "process_time": 0.53,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:17.892527Z",
      "parameters": {},
      "type": "analyzer",
      "id": 25394,
      "report": {
        "ip": "1.12.251.79",
        "cves": [],
        "link": "https://app.crowdsec.net/cti/1.12.251.79",
        "as_num": 45090,
        "scores": {
          "overall": {
            "total": 5,
            "trust": 5,
            "threat": 4,
            "anomaly": 1,
            "aggressiveness": 5
          },
          "last_day": {
            "total": 1,
            "trust": 2,
            "threat": 4,
            "anomaly": 1,
            "aggressiveness": 0
          },
          "last_week": {
            "total": 1,
            "trust": 2,
            "threat": 4,
            "anomaly": 1,
            "aggressiveness": 0
          },
          "last_month": {
            "total": 4,
            "trust": 5,
            "threat": 4,
            "anomaly": 1,
            "aggressiveness": 3
          }
        },
        "as_name": "Shenzhen Tencent Computer Systems Company Limited",
        "history": {
          "days_age": 27,
          "full_age": 35,
          "last_seen": "2026-03-06T02:00:00+00:00",
          "first_seen": "2026-01-12T17:45:00+00:00"
        },
        "ip_range": "1.12.128.0/17",
        "location": {
          "city": "Guangzhou",
          "country": "CN",
          "latitude": 23.1181,
          "longitude": 113.2539
        },
        "behaviors": [
          {
            "name": "ssh:bruteforce",
            "label": "SSH Bruteforce",
            "references": [],
            "description": "IP has been reported for performing brute force on ssh services."
          },
          {
            "name": "generic:exploit",
            "label": "Exploitation attempt",
            "references": [],
            "description": "IP has been reported trying to exploit known vulnerability/CVE on unspecified protocols."
          }
        ],
        "confidence": "high",
        "references": [
          {
            "name": "list:crowdsec_hosting_blocklist",
            "label": "Hosting Services Attackers",
            "references": [],
            "description": "Contains IPs frequently attacking hosting providers. If you operate a web hosting service, block these IPs to reduce security alerts, establish a safer perimeter, and minimize downtime to better serve your customers."
          },
          {
            "name": "list:crowdsec_bruteforce",
            "label": "Bruteforce Attackers",
            "references": [],
            "description": "Contains IPs that have been mainly reported for performing Bruteforce. Proactively block these IPs to prevent bruteforce attempts on your systems and establish an overall safer perimeter."
          },
          {
            "name": "list:crowdsec_healthcare_blocklist",
            "label": "Healthcare Attackers",
            "references": [],
            "description": "Contains IPs identified as frequently attacking healthcare sector organizations. Block these IPs to reduce security alerts and establish a safer perimeter to protect critical systems."
          }
        ],
        "reputation": "malicious",
        "ip_range_24": null,
        "reverse_dns": null,
        "proxy_or_vpn": false,
        "attack_details": [
          {
            "name": "crowdsecurity/ssh-slow-bf",
            "label": "SSH Slow Bruteforce",
            "references": [],
            "description": "Detect slow ssh bruteforce"
          },
          {
            "name": "crowdsecurity/suricata-major-severity",
            "label": "Suricata Severity 1 Event",
            "references": [],
            "description": "Detect exploit attempts via emerging threat rules"
          },
          {
            "name": "crowdsecurity/ssh-time-based-bf",
            "label": "SSH Time-Based Bruteforce",
            "references": [],
            "description": "Detect time-based ssh bruteforce attempts that evade rate limiting (with false positive reduction)"
          },
          {
            "name": "crowdsecurity/configserver-lfd-bf",
            "label": "SSH Bruteforce",
            "references": [],
            "description": "Detects SSH bruteforce attempts blocked by ConfigServer."
          },
          {
            "name": "crowdsecurity/ssh-bf",
            "label": "SSH Bruteforce",
            "references": [],
            "description": "Detect ssh bruteforce"
          },
          {
            "name": "crowdsecurity/ssh-time-based-bf_user-enum",
            "label": "SSH Time-Based User Enumeration",
            "references": [],
            "description": "Detect time-based ssh user enum bruteforce attempts (with false positive reduction)"
          }
        ],
        "ip_range_score": 5,
        "classifications": {
          "classifications": [],
          "false_positives": []
        },
        "background_noise": "medium",
        "mitre_techniques": [
          {
            "name": "T1110",
            "label": "Brute Force",
            "references": [],
            "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained."
          },
          {
            "name": "T1190",
            "label": "Exploit Public-Facing Application",
            "references": [],
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network."
          },
          {
            "name": "T1595",
            "label": "Active Scanning",
            "references": [],
            "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting."
          },
          {
            "name": "T1589",
            "label": "Gather Victim Identity Information",
            "references": [],
            "description": "Adversaries may gather information about the victim's identity that can be used during targeting."
          }
        ],
        "target_countries": {
          "AT": 2,
          "AU": 14,
          "DE": 34,
          "FI": 1,
          "FR": 21,
          "GB": 3,
          "NL": 3,
          "RU": 2,
          "UA": 6,
          "US": 7
        },
        "ip_range_24_score": null,
        "background_noise_score": 7,
        "ip_range_24_reputation": null
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.359455Z",
      "data_model": {
        "id": 5924,
        "analyzers_report": [
          25394
        ],
        "ietf_report": [],
        "evaluation": null,
        "reliability": 5,
        "kill_chain_phase": null,
        "external_references": [],
        "related_threats": [],
        "tags": null,
        "malware_family": null,
        "additional_info": {},
        "date": "2026-03-06T09:07:17.885789Z",
        "asn": null,
        "asn_rank": null,
        "certificates": null,
        "org_name": null,
        "country_code": null,
        "registered_country_code": null,
        "isp": null,
        "resolutions": []
      },
      "description": "check if an IP was reported on [Crowdsec](https://www.crowdsec.net/) Smoke Dataset"
    },
    {
      "name": "AbuseIPDB",
      "process_time": 0.74,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:18.091506Z",
      "parameters": {
        "max_age": 180,
        "verbose": true,
        "max_reports": 200
      },
      "type": "analyzer",
      "id": 25392,
      "report": {
        "data": {
          "isp": "Tencent cloud computing (Beijing) Co., Ltd.",
          "isTor": false,
          "domain": "tencent.com",
          "reports": [
            {
              "comment": "PERMA offender. Observed 9025 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-03-06T00:59:11+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 8808 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-03-04T23:59:16+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 8598 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-03-03T23:00:18+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 8387 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-03-02T22:59:08+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 8155 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-03-01T22:00:13+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 7943 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-28T21:59:07+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 7710 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-27T21:00:12+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 7489 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-26T19:29:19+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 7204 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-25T04:00:17+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 6972 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-24T02:59:02+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 6736 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-23T02:00:11+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 6508 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-22T02:00:04+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 6283 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-21T02:00:04+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 6047 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-20T01:59:04+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 5804 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-19T01:00:07+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 5605 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-18T00:59:04+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 5118 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-15T23:59:06+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 4869 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-14T23:00:06+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 4629 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-13T22:59:04+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 4370 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-12T22:00:06+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 4158 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-11T18:00:07+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 3735 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-09T10:00:10+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 3527 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-08T10:00:05+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 3304 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-07T08:00:40+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-06T20:11:25+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 3074 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-06T05:59:03+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-05T20:11:23+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 2840 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-05T05:00:03+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "ThreatBook Intelligence: Zombie,IDC more details on https://threatbook.io/ip/1.12.251.79",
              "categories": [
                5
              ],
              "reportedAt": "2026-02-05T00:03:29+00:00",
              "reporterId": 56171,
              "reporterCountryCode": "CN",
              "reporterCountryName": "China",
              "categories_human_readable": [
                "FTP Brute-Force"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T13:11:36+00:00",
              "reporterId": 231769,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-02-04T12:07:29.188Z ACCEPT host=::ffff:1.12.251.79 port=60696 fd=7 n=4/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T12:37:18+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-02-04T13:34:53.497665+01:00 hosting15 sshd[1414906]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-02-04T13:34:54.777704+01:00 hosting15 sshd[1414906]: Failed password for invalid user viridian from 1.12.251.79 port 39006 ssh2\n2026-02-04T13:34:58.723883+01:00 hosting15 sshd[1414909]: Invalid user viridian from 1.12.251.79 port 39010\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T12:34:59+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 13:23:40 pegasus sshd[857856]: Invalid user hwmf from 1.12.251.79 port 52148\nFeb  4 13:23:41 pegasus sshd[857856]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nFeb  4 13:23:43 pegasus sshd[857856]: Failed password for invalid user hwmf from 1.12.251.79 port 52148 ssh2\nFeb  4 13:23:47 pegasus sshd[857894]: Invalid user hwmf from 1.12.251.79 port 52158",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T12:23:47+00:00",
              "reporterId": 12987,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T12:19:00+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Fail2Ban triggered a ban on 1.12.251.79 for postfix-sasl",
              "categories": [
                7,
                11,
                17
              ],
              "reportedAt": "2026-02-04T12:17:26+00:00",
              "reporterId": 94865,
              "reporterCountryCode": "AU",
              "reporterCountryName": "Australia",
              "categories_human_readable": [
                "Phishing",
                "Email Spam",
                "Spoofing"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T12:08:15+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 12:58:48 odin sshd[28220]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  4 12:58:49 odin sshd[28220]: Failed password for invalid user admin from 1.12.251.79 port 54036 ssh2\nFeb  4 12:58:53 odin sshd[28222]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T11:58:53+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 12:30:10 smtp sshd[3837793]: Failed password for invalid user admin from 1.12.251.79 port 55508 ssh2\n\r\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T11:30:11+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 13:29:47 www4 sshd\\[22700\\]: Invalid user admin from 1.12.251.79\nFeb  4 13:29:47 www4 sshd\\[22700\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nFeb  4 13:29:49 www4 sshd\\[22700\\]: Failed password for invalid user admin from 1.12.251.79 port 55738 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T11:29:51+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T11:23:13+00:00",
              "reporterId": 169612,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-02-04T10:46:54+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "2026-02-04T11:28:29.284214+01:00 hosting13 sshd[1077820]: Failed password for invalid user admin from 1.12.251.79 port 59858 ssh2\n2026-02-04T11:28:33.093880+01:00 hosting13 sshd[1077884]: Invalid user admin from 1.12.251.79 port 54006\n2026-02-04T11:28:33.304817+01:00 hosting13 sshd[1077884]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-02-04T11:28:35.318781+01:00 hosting13 sshd[1077884]: Failed password for invalid user admin from 1.12.251.79 port 54006 ssh2\n2026-02-04T11:37:38.305316+01:00 hosting13 sshd[1080116]: Invalid user admin from 1.12.251.79 port 39812\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:37:38+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:34:48+00:00",
              "reporterId": 37710,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:19:49+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "FFM Feb  4 11:09:29 websrv01 sshd[3481694]: Invalid user admin from 1.12.251.79 port 51064\nFeb  4 11:09:30 websrv01 sshd[3481694]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  4 11:09:32 websrv01 sshd[3481694]: Failed password for invalid user admin from 1.12.251.79 port 51064 ssh2\nFeb  4 11:09:35 websrv01 sshd[3481707]: Invalid user admin from 1.12.251.79 port 51066",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:19:38+00:00",
              "reporterId": 50559,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Blocked for probing SSH accounts",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:07:45+00:00",
              "reporterId": 29016,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 11:05:59 odin sshd[32434]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  4 11:06:01 odin sshd[32434]: Failed password for invalid user admin from 1.12.251.79 port 60378 ssh2\nFeb  4 11:06:03 odin sshd[32462]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:06:04+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-02-03T08:23:51.581893cocheando sshd[9244]: Invalid user admin from 1.12.251.79 port 37356\n2026-02-03T08:23:53.278421cocheando sshd[9247]: Invalid user admin from 1.12.251.79 port 37362\n2026-02-04T11:06:01.584944cocheando sshd[27117]: Invalid user admin from 1.12.251.79 port 40726\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:06:02+00:00",
              "reporterId": 103226,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  4 11:04:03 pegasus sshd[815577]: Invalid user admin from 1.12.251.79 port 58882\nFeb  4 11:04:03 pegasus sshd[815577]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nFeb  4 11:04:05 pegasus sshd[815577]: Failed password for invalid user admin from 1.12.251.79 port 58882 ssh2\nFeb  4 11:04:07 pegasus sshd[815590]: Invalid user admin from 1.12.251.79 port 58890",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:04:08+00:00",
              "reporterId": 12987,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-04T10:02:40+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "PERMA offender. Observed 2611 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-04T04:00:08+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-03T20:11:22+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "UFW:High-frequency access to unused ports",
              "categories": [
                14
              ],
              "reportedAt": "2026-02-03T19:09:06+00:00",
              "reporterId": 96389,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Port Scan"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-02-03T09:23:54.283Z ACCEPT host=::ffff:1.12.251.79 port=40786 fd=8 n=5/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T10:42:21+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T09:31:51+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 10:11:55 odin sshd[10841]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  3 10:11:56 odin sshd[10841]: Failed password for invalid user admin from 1.12.251.79 port 57934 ssh2\nFeb  3 10:11:58 odin sshd[10851]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T09:11:59+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Invalid user admin from 1.12.251.79 port 47804",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:42:51+00:00",
              "reporterId": 88899,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Invalid user admin from 1.12.251.79 port 47804",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:42:51+00:00",
              "reporterId": 88899,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Invalid user admin from 1.12.251.79 port 47804",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:42:51+00:00",
              "reporterId": 88899,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Invalid user admin from 1.12.251.79 port 47804",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:42:51+00:00",
              "reporterId": 88899,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 09:39:42 smtp sshd[3618903]: Failed password for invalid user admin from 1.12.251.79 port 52218 ssh2\n\r\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:39:43+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 10:39:30 www4 sshd\\[26692\\]: Invalid user admin from 1.12.251.79\nFeb  3 10:39:31 www4 sshd\\[26692\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nFeb  3 10:39:33 www4 sshd\\[26692\\]: Failed password for invalid user admin from 1.12.251.79 port 53436 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:39:35+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 09:39:02 lnxweb62 sshd[19193]: Failed password for invalid user admin from 1.12.251.79 port 49782 ssh2\nFeb  3 09:39:03 lnxweb62 sshd[19193]: Connection closed by invalid user admin 1.12.251.79 port 49782 [preauth]\nFeb  3 09:39:04 lnxweb62 sshd[19545]: Invalid user admin from 1.12.251.79 port 49790\nFeb  3 09:39:05 lnxweb62 sshd[19545]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  3 09:39:07 lnxweb62 sshd[19545]: Failed password for invalid user admin from 1.12.251.79 port 49790 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T08:39:08+00:00",
              "reporterId": 18914,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SmallGuard.fr/Prestashop SSH Login Failed",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-03T08:22:03+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "2026-02-03T08:45:06.288275+01:00 hosting13 sshd[504066]: Failed password for invalid user admin from 1.12.251.79 port 56360 ssh2\n2026-02-03T08:45:08.437115+01:00 hosting13 sshd[504075]: Invalid user admin from 1.12.251.79 port 56362\n2026-02-03T08:45:08.651148+01:00 hosting13 sshd[504075]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-02-03T08:45:11.062817+01:00 hosting13 sshd[504075]: Failed password for invalid user admin from 1.12.251.79 port 56362 ssh2\n2026-02-03T08:53:55.208170+01:00 hosting13 sshd[506530]: Invalid user admin from 1.12.251.79 port 35900\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:53:55+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:51:06+00:00",
              "reporterId": 37710,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "FFM Feb  3 08:27:51 websrv01 sshd[3102714]: Invalid user admin from 1.12.251.79 port 60566\nFeb  3 08:27:51 websrv01 sshd[3102714]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  3 08:27:53 websrv01 sshd[3102714]: Failed password for invalid user admin from 1.12.251.79 port 60566 ssh2\nFeb  3 08:28:01 websrv01 sshd[3102718]: Invalid user admin from 1.12.251.79 port 60582",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:38:02+00:00",
              "reporterId": 50559,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:37:56+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:26:41+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Blocked for probing SSH accounts",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:25:50+00:00",
              "reporterId": 29016,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 08:23:48 odin sshd[16874]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nFeb  3 08:23:51 odin sshd[16874]: Failed password for invalid user admin from 1.12.251.79 port 43442 ssh2\nFeb  3 08:23:55 odin sshd[16882]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:23:55+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  3 08:21:31 pegasus sshd[4088334]: Invalid user admin from 1.12.251.79 port 52148\nFeb  3 08:21:31 pegasus sshd[4088334]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nFeb  3 08:21:33 pegasus sshd[4088334]: Failed password for invalid user admin from 1.12.251.79 port 52148 ssh2\nFeb  3 08:21:36 pegasus sshd[4088353]: Invalid user admin from 1.12.251.79 port 52156",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:21:37+00:00",
              "reporterId": 12987,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:19:48+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-02-03T07:14:28+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "2026-02-03T08:13:51.452566+01:00 phishsim sshd[89892]: Invalid user admin from 1.12.251.79 port 34108\n2026-02-03T08:13:53.305891+01:00 phishsim sshd[89894]: Invalid user admin from 1.12.251.79 port 34124\n...",
              "categories": [
                21
              ],
              "reportedAt": "2026-02-03T07:13:53+00:00",
              "reporterId": 29244,
              "reporterCountryCode": "CZ",
              "reporterCountryName": "Czechia",
              "categories_human_readable": [
                "Web App Attack"
              ]
            },
            {
              "comment": "Feb  3 09:05:20 www6 sshd[2551965]: Invalid user admin from 1.12.251.79 port 34448\nFeb  3 09:05:23 www6 sshd[2551965]: Failed password for invalid user admin from 1.12.251.79 port 34448 ssh2\nFeb  3 09:05:27 www6 sshd[2551969]: Invalid user admin from 1.12.251.79 port 34456\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-03T07:05:28+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "PERMA offender. Observed 2354 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-03T02:00:41+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-02T20:11:21+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-02-02T04:38:48.057Z ACCEPT host=::ffff:1.12.251.79 port=35364 fd=13 n=10/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T06:02:52+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "<jail> banned by fail2ban",
              "categories": [
                18,
                21
              ],
              "reportedAt": "2026-02-02T06:00:07+00:00",
              "reporterId": 267320,
              "reporterCountryCode": "CZ",
              "reporterCountryName": "Czechia",
              "categories_human_readable": [
                "Brute Force",
                "Web App Attack"
              ]
            },
            {
              "comment": "Feb  2 07:53:06 www4 sshd\\[29914\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nFeb  2 07:53:08 www4 sshd\\[29914\\]: Failed password for root from 1.12.251.79 port 54720 ssh2\nFeb  2 07:53:11 www4 sshd\\[29918\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T05:53:13+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  2 06:53:09 smtp sshd[3400927]: Failed password for invalid user root from 1.12.251.79 port 49480 ssh2\n\r\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T05:53:10+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SmallGuard.fr/Prestashop SSH Login Failed",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-02T05:36:59+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T05:03:16+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T04:55:47+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T04:52:47+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Unauthorized connection attempt detected, SSH Brute-Force",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-02-02T04:50:46+00:00",
              "reporterId": 57005,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  2 06:48:06 tuotantolaitos sshd[102932]: Failed password for root from 1.12.251.79 port 38310 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T04:48:09+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-02-02T04:47:53+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "1.12.251.79 (CN/China/-), 9 distributed sshd attacks on account [redacted]",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T04:07:30+00:00",
              "reporterId": 22685,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "CrowdSec ban for AbuseIPDB Top List",
              "categories": [
                18,
                21
              ],
              "reportedAt": "2026-02-02T02:01:12+00:00",
              "reporterId": 256090,
              "reporterCountryCode": "GB",
              "reporterCountryName": "United Kingdom of Great Britain and Northern Ireland",
              "categories_human_readable": [
                "Brute Force",
                "Web App Attack"
              ]
            },
            {
              "comment": "Fail2Ban: Dovecot Attack 1.12.251.79 1769994828.0(JST)",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-02T01:13:48+00:00",
              "reporterId": 164986,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "PERMA offender. Observed 2114 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-02-01T23:59:05+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-01T20:11:20+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "SmallGuard.fr/Prestashop SSH Login Failed",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-01T03:27:14+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T02:46:04+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-02-01T02:14:18.948Z ACCEPT host=::ffff:1.12.251.79 port=42904 fd=5 n=2/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T02:40:48+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T02:31:31+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-02-01T03:29:11.178658+01:00 aligw01.aneirin.net sshd-session[23680]: Failed password for root from 1.12.251.79 port 49374 ssh2\n2026-02-01T03:29:12.033146+01:00 aligw01.aneirin.net sshd-session[23680]: Connection closed by authenticating user root 1.12.251.79 port 49374 [preauth]\n2026-02-01T03:29:15.260575+01:00 aligw01.aneirin.net sshd-session[23682]: Failed password for root from 1.12.251.79 port 40742 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T02:29:15+00:00",
              "reporterId": 84348,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  1 04:23:46 tuotantolaitos sshd[62656]: Failed password for root from 1.12.251.79 port 38362 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T02:23:49+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "(sshd) Failed SSH login from 1.12.251.79 (CN/China/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Feb  1 12:34:36 ded01 sshd[13098]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nFeb  1 12:34:38 ded01 sshd[13098]: Failed password for root from 1.12.251.79 port 39814 ssh2\nFeb  1 12:34:40 ded01 sshd[13143]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nFeb  1 12:34:42 ded01 sshd[13143]: Failed password for root from 1.12.251.79 port 51252 ssh2\nFeb  1 13:18:55 ded01 sshd[43251]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root",
              "categories": [
                14
              ],
              "reportedAt": "2026-02-01T02:19:00+00:00",
              "reporterId": 52306,
              "reporterCountryCode": "AU",
              "reporterCountryName": "Australia",
              "categories_human_readable": [
                "Port Scan"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-02-01T01:30:03+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "Feb  1 02:27:56 lnxweb62 sshd[2030]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nFeb  1 02:27:58 lnxweb62 sshd[2030]: Failed password for root from 1.12.251.79 port 41480 ssh2\nFeb  1 02:28:00 lnxweb62 sshd[2030]: Connection closed by authenticating user root 1.12.251.79 port 41480 [preauth]\nFeb  1 02:29:17 lnxweb62 sshd[2868]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nFeb  1 02:29:19 lnxweb62 sshd[2868]: Failed password for root from 1.12.251.79 port 48990 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T01:29:21+00:00",
              "reporterId": 18914,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Feb  1 01:18:35 dlcentre3 sshd[18231]: Failed password for root from 1.12.251.79 port 49662 ssh2",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T01:18:37+00:00",
              "reporterId": 45767,
              "reporterCountryCode": "GB",
              "reporterCountryName": "United Kingdom of Great Britain and Northern Ireland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-02-01 01:13:17,621 quad proftpd[537253] quad (1.12.251.79[1.12.251.79]): USER root: no such user found from 1.12.251.79 [1.12.251.79] to 2.56.97.107:22",
              "categories": [
                18,
                20,
                22
              ],
              "reportedAt": "2026-02-01T01:13:18+00:00",
              "reporterId": 56979,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "Exploited Host",
                "SSH"
              ]
            },
            {
              "comment": "Fail2Ban: Dovecot Attack 1.12.251.79 1769907507.0(JST)",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T00:58:28+00:00",
              "reporterId": 164986,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T00:56:14+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-31 18:49:54.406876-0600  localhost sshd-session[82587]: Failed password for root from 1.12.251.79 port 40768 ssh2",
              "categories": [
                18
              ],
              "reportedAt": "2026-02-01T00:51:09+00:00",
              "reporterId": 42391,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Jan 30 17:20:23 global2 sshd[29741]: Failed password for root from 1.12.251.79 port 33182 ssh2\nJan 30 17:20:26 global2 sshd[29743]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 17:20:28 global2 sshd[29743]: Failed password for root from 1.12.251.79 port 33190 ssh2\nJan 31 19:49:30 global2 sshd[45028]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 31 19:49:32 global2 sshd[45028]: Failed password for root from 1.12.251.79 port 53764 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T00:49:32+00:00",
              "reporterId": 149436,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-02-01T01:17:33.567626+01:00 donarev419.com sshd[1914426]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-02-01T01:17:35.822578+01:00 donarev419.com sshd[1914426]: Failed password for root from 1.12.251.79 port 34700 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T00:17:36+00:00",
              "reporterId": 246098,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH Login failed",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-02-01T00:15:23+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-01-30T22:59:16+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "Jan 30 23:57:14 lnxweb62 sshd[488]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 23:57:17 lnxweb62 sshd[488]: Failed password for root from 1.12.251.79 port 50334 ssh2\nJan 30 23:57:19 lnxweb62 sshd[488]: Connection closed by authenticating user root 1.12.251.79 port 50334 [preauth]\nJan 30 23:58:31 lnxweb62 sshd[1281]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 23:58:34 lnxweb62 sshd[1281]: Failed password for root from 1.12.251.79 port 42438 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T22:58:35+00:00",
              "reporterId": 18914,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 30 22:48:26 dlcentre3 sshd[3674]: Failed password for root from 1.12.251.79 port 53868 ssh2",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T22:49:10+00:00",
              "reporterId": 45767,
              "reporterCountryCode": "GB",
              "reporterCountryName": "United Kingdom of Great Britain and Northern Ireland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-30 22:43:25,686 quad proftpd[268266] quad (1.12.251.79[1.12.251.79]): USER root: no such user found from 1.12.251.79 [1.12.251.79] to 2.56.97.107:22",
              "categories": [
                18,
                20,
                22
              ],
              "reportedAt": "2026-01-30T22:43:26+00:00",
              "reporterId": 56979,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "Exploited Host",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T22:27:01+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-30 16:20:46.070832-0600  localhost sshd-session[90262]: Failed password for root from 1.12.251.79 port 56288 ssh2",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-30T22:21:09+00:00",
              "reporterId": 42391,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Jan 30 22:19:01 dabeau sshd[14373]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 22:19:02 dabeau sshd[14373]: Failed password for root from 1.12.251.79 port 33572 ssh2\nJan 30 22:19:05 dabeau sshd[14424]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 22:19:07 dabeau sshd[14424]: Failed password for root from 1.12.251.79 port 33574 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T22:19:07+00:00",
              "reporterId": 40939,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-30T22:43:21.986911+01:00 donarev419.com sshd[889335]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-30T22:43:24.222517+01:00 donarev419.com sshd[889335]: Failed password for root from 1.12.251.79 port 39724 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T21:43:25+00:00",
              "reporterId": 246098,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 30 23:20:29 www4 sshd\\[19721\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\nJan 30 23:20:31 www4 sshd\\[19721\\]: Failed password for root from 1.12.251.79 port 53326 ssh2\nJan 30 23:20:34 www4 sshd\\[19732\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T21:20:35+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-30T21:17:45+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-30T20:11:19+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Jan 29 20:30:08 dlcentre3 sshd[29435]: Failed password for root from 1.12.251.79 port 55040 ssh2",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T20:30:12+00:00",
              "reporterId": 45767,
              "reporterCountryCode": "GB",
              "reporterCountryName": "United Kingdom of Great Britain and Northern Ireland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-29 20:25:01,828 quad proftpd[68768] quad (1.12.251.79[1.12.251.79]): USER root: no such user found from 1.12.251.79 [1.12.251.79] to 2.56.97.107:22",
              "categories": [
                18,
                20,
                22
              ],
              "reportedAt": "2026-01-29T20:25:02+00:00",
              "reporterId": 56979,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "Exploited Host",
                "SSH"
              ]
            },
            {
              "comment": "SSH brute force attacks",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T20:15:06+00:00",
              "reporterId": 258806,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-29 14:08:52.322617-0600  localhost sshd-session[3499]: Failed password for root from 1.12.251.79 port 45716 ssh2",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-29T20:11:12+00:00",
              "reporterId": 42391,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "2026-01-22T16:21:49.574835-06:00 lab sshd[2712158]: Connection closed by authenticating user root 1.12.251.79 port 40994 [preauth]\n2026-01-22T16:21:50.964103-06:00 lab sshd[2712160]: Connection closed by authenticating user root 1.12.251.79 port 52794 [preauth]\n2026-01-29T14:08:33.127266-06:00 lab sshd[2802534]: Connection closed by authenticating user root 1.12.251.79 port 54880 [preauth]\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T20:08:33+00:00",
              "reporterId": 64346,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-29T20:31:08.368772+01:00 donarev419.com sshd[19055]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-29T20:31:09.658562+01:00 donarev419.com sshd[19055]: Failed password for root from 1.12.251.79 port 45436 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T19:31:10+00:00",
              "reporterId": 246098,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-29T20:24:38.458674whm11.palvelukanava.fi sshd[2966482]: Failed password for root from 1.12.251.79 port 39786 ssh2\n2026-01-29T21:05:35.258534whm11.palvelukanava.fi sshd[2977870]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-29T21:05:37.095227whm11.palvelukanava.fi sshd[2977870]: Failed password for root from 1.12.251.79 port 51390 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T19:05:37+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T19:03:15+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "1.12.251.79 (CN/China/-), 8 distributed sshd attacks on account [redacted]",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T18:46:19+00:00",
              "reporterId": 22685,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 29 20:28:46 sauna sshd[126668]: Failed password for root from 1.12.251.79 port 40712 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-29T18:28:50+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "PERMA offender. Observed 1470 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-01-29T07:59:08+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "UFW:High-frequency access to unused ports",
              "categories": [
                14
              ],
              "reportedAt": "2026-01-28T22:39:20+00:00",
              "reporterId": 96389,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Port Scan"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-28T20:11:16+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "ssh",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T17:23:07+00:00",
              "reporterId": 191063,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-28T18:04:30.403692+01:00 donarev419.com sshd[3989487]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-28T18:04:32.999742+01:00 donarev419.com sshd[3989487]: Failed password for root from 1.12.251.79 port 35514 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T17:04:33+00:00",
              "reporterId": 246098,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-28T17:53:53.014525whm11.palvelukanava.fi sshd[2498081]: Failed password for root from 1.12.251.79 port 35888 ssh2\n2026-01-28T18:37:28.892767whm11.palvelukanava.fi sshd[2512406]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-28T18:37:31.153908whm11.palvelukanava.fi sshd[2512406]: Failed password for root from 1.12.251.79 port 48328 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T16:37:31+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T16:35:08+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 28 17:58:25 sauna sshd[29373]: Failed password for root from 1.12.251.79 port 54650 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T15:58:29+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-01-28T15:03:34.086Z ACCEPT host=::ffff:1.12.251.79 port=54010 fd=6 n=4/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T15:16:54+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-28T15:11:45+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Repeated attacks detected by Fail2Ban in recidive jail",
              "categories": [
                15
              ],
              "reportedAt": "2026-01-28T10:04:39+00:00",
              "reporterId": 169612,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Hacking"
              ]
            },
            {
              "comment": "FTP brute-force attack detected by Fail2Ban in plesk-proftpd jail",
              "categories": [
                5
              ],
              "reportedAt": "2026-01-28T04:49:32+00:00",
              "reporterId": 169612,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "FTP Brute-Force"
              ]
            },
            {
              "comment": "PERMA offender. Observed 1240 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-01-28T04:37:43+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "Brute-force attack via SMTP AUTH. Repeated login failures on mail server.",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-28T00:28:08+00:00",
              "reporterId": 206066,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-27T15:11:59+00:00",
              "reporterId": 231769,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-27T14:45:34+00:00",
              "reporterId": 169612,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "PERMA offender. Observed 1135 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-01-27T04:11:49+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-26T20:11:14+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-01-26T10:06:35.099Z ACCEPT host=::ffff:1.12.251.79 port=59462 fd=4 n=2/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T11:34:57+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-26T12:48:22.172510whm11.palvelukanava.fi sshd[1565031]: Failed password for root from 1.12.251.79 port 54566 ssh2\n2026-01-26T13:31:50.663041whm11.palvelukanava.fi sshd[1579621]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=root\n2026-01-26T13:31:52.670206whm11.palvelukanava.fi sshd[1579621]: Failed password for root from 1.12.251.79 port 40652 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T11:31:53+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 26 12:52:51 sauna sshd[81818]: Failed password for root from 1.12.251.79 port 51520 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T10:52:53+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-01-26T10:39:00+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T10:15:46+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T09:57:42+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 26 10:56:02 odin sshd[18875]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 26 10:56:04 odin sshd[18875]: Failed password for invalid user bb84quantum from 1.12.251.79 port 39248 ssh2\nJan 26 10:56:06 odin sshd[18886]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T09:56:07+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Unauthorized connection attempt detected, SSH Brute-Force",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-01-26T09:50:33+00:00",
              "reporterId": 57005,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T09:26:49+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 26 10:26:15 smtp sshd[2074483]: Failed password for invalid user westergard from 1.12.251.79 port 39464 ssh2\n\r\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-26T09:26:16+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "CrowdSec: import to_import.txt- 56363 ips",
              "categories": [
                14
              ],
              "reportedAt": "2026-01-26T08:17:32+00:00",
              "reporterId": 228623,
              "reporterCountryCode": "SG",
              "reporterCountryName": "Singapore",
              "categories_human_readable": [
                "Port Scan"
              ]
            },
            {
              "comment": "PERMA offender. Observed 983 times.",
              "categories": [
                14,
                18
              ],
              "reportedAt": "2026-01-26T00:00:12+00:00",
              "reporterId": 259031,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-25T20:11:13+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "2026-01-25T08:34:12.278776+00:00 nbg01-02-mon sshd[1068935]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-01-25T08:34:14.243341+00:00 nbg01-02-mon sshd[1068935]: Failed password for invalid user bitfleet from 1.12.251.79 port 39140 ssh2\n2026-01-25T08:34:16.113464+00:00 nbg01-02-mon sshd[1068937]: Invalid user bitfleet from 1.12.251.79 port 39150\n...",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-25T08:34:16+00:00",
              "reporterId": 57515,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Automated abuse report by SpeedIT Security Team",
              "categories": [
                18,
                20,
                22
              ],
              "reportedAt": "2026-01-25T08:28:03+00:00",
              "reporterId": 77159,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "Exploited Host",
                "SSH"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T08:11:45+00:00",
              "reporterId": 231769,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-25T10:10:26.819742whm11.palvelukanava.fi sshd[1092143]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\n2026-01-25T10:10:29.019714whm11.palvelukanava.fi sshd[1092143]: Failed password for invalid user burtboultonhaywood from 1.12.251.79 port 36138 ssh2\n2026-01-25T10:10:31.125837whm11.palvelukanava.fi sshd[1092176]: Invalid user burtboultonhaywood from 1.12.251.79 port 57268\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T08:10:31+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-01-25T08:00:04+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "2026-01-25T08:50:03.258612+01:00 hosting15 sshd[925306]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-01-25T08:50:05.549113+01:00 hosting15 sshd[925306]: Failed password for invalid user viridian from 1.12.251.79 port 40932 ssh2\n2026-01-25T08:50:09.254426+01:00 hosting15 sshd[925419]: Invalid user viridian from 1.12.251.79 port 40942\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:50:09+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 25 08:39:40 pegasus sshd[655976]: Invalid user hwmf from 1.12.251.79 port 43632\nJan 25 08:39:40 pegasus sshd[655976]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nJan 25 08:39:42 pegasus sshd[655976]: Failed password for invalid user hwmf from 1.12.251.79 port 43632 ssh2\nJan 25 08:39:44 pegasus sshd[655985]: Invalid user hwmf from 1.12.251.79 port 43644",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:39:45+00:00",
              "reporterId": 12987,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:34:52+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Fail2Ban triggered a ban on 1.12.251.79 for postfix-sasl",
              "categories": [
                7,
                11,
                17
              ],
              "reportedAt": "2026-01-25T07:33:13+00:00",
              "reporterId": 94865,
              "reporterCountryCode": "AU",
              "reporterCountryName": "Australia",
              "categories_human_readable": [
                "Phishing",
                "Email Spam",
                "Spoofing"
              ]
            },
            {
              "comment": "Unauthorized connection attempt detected, SSH Brute-Force",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:20:19+00:00",
              "reporterId": 57005,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:15:41+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 25 08:13:59 odin sshd[28427]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 25 08:14:00 odin sshd[28427]: Failed password for invalid user bb84quantum from 1.12.251.79 port 39038 ssh2\nJan 25 08:14:04 odin sshd[28453]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T07:14:05+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T06:37:47+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 25 07:37:14 smtp sshd[1859499]: Failed password for invalid user westergard from 1.12.251.79 port 34534 ssh2\n\r\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T06:37:14+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 25 08:36:55 www4 sshd\\[29272\\]: Invalid user vellux from 1.12.251.79\nJan 25 08:36:56 www4 sshd\\[29272\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nJan 25 08:36:58 www4 sshd\\[29272\\]: Failed password for invalid user vellux from 1.12.251.79 port 37242 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T06:37:00+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 25 07:36:25 lnxweb62 sshd[15024]: Failed password for invalid user mission9 from 1.12.251.79 port 49350 ssh2\nJan 25 07:36:26 lnxweb62 sshd[15024]: Connection closed by invalid user mission9 1.12.251.79 port 49350 [preauth]\nJan 25 07:36:28 lnxweb62 sshd[15041]: Invalid user mission9 from 1.12.251.79 port 49360\nJan 25 07:36:28 lnxweb62 sshd[15041]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 25 07:36:30 lnxweb62 sshd[15041]: Failed password for invalid user mission9 from 1.12.251.79 port 49360 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-25T06:36:31+00:00",
              "reporterId": 18914,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SmallGuard.fr/Prestashop SSH Login Failed",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-25T06:18:29+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "Fail2Ban: Dovecot Attack 1.12.251.79 1769297883.0(JST)",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T23:38:03+00:00",
              "reporterId": 164986,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "list.rtbh.com.tr report: tcp/0",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-24T20:11:12+00:00",
              "reporterId": 162131,
              "reporterCountryCode": "TR",
              "reporterCountryName": "Turkey",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "2026-01-24T07:21:54.709274whm11.palvelukanava.fi sshd[617271]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\n2026-01-24T07:21:56.159545whm11.palvelukanava.fi sshd[617271]: Failed password for invalid user burtboultonhaywood from 1.12.251.79 port 41428 ssh2\n2026-01-24T07:21:59.557697whm11.palvelukanava.fi sshd[617312]: Invalid user burtboultonhaywood from 1.12.251.79 port 41436\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T05:22:00+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SSH abuse or brute-force attack detected by Fail2Ban in ssh jail",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T05:11:39+00:00",
              "reporterId": 231769,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "2026-01-24T05:59:46.561618+01:00 hosting15 sshd[585059]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-01-24T05:59:49.032980+01:00 hosting15 sshd[585059]: Failed password for invalid user viridian from 1.12.251.79 port 60576 ssh2\n2026-01-24T05:59:51.619119+01:00 hosting15 sshd[585064]: Invalid user viridian from 1.12.251.79 port 60964\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:59:52+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Report-by-bigbear3",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:45:10+00:00",
              "reporterId": 130737,
              "reporterCountryCode": "DE",
              "reporterCountryName": "Germany",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Fail2Ban triggered a ban on 1.12.251.79 for postfix-sasl",
              "categories": [
                7,
                11,
                17
              ],
              "reportedAt": "2026-01-24T04:43:35+00:00",
              "reporterId": 94865,
              "reporterCountryCode": "AU",
              "reporterCountryName": "Australia",
              "categories_human_readable": [
                "Phishing",
                "Email Spam",
                "Spoofing"
              ]
            },
            {
              "comment": "SSH login attempts (endlessh): 2026-01-24T04:33:25.623Z ACCEPT host=::ffff:1.12.251.79 port=45158 fd=6 n=3/4096",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:41:57+00:00",
              "reporterId": 115234,
              "reporterCountryCode": "US",
              "reporterCountryName": "United States of America",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Brute Force",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:26:13+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 24 05:24:47 odin sshd[8781]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 24 05:24:48 odin sshd[8781]: Failed password for invalid user bb84quantum from 1.12.251.79 port 45432 ssh2\nJan 24 05:24:52 odin sshd[8785]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:24:53+00:00",
              "reporterId": 51418,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 23 23:21:44 www3 sshd[2338846]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 23 23:21:46 www3 sshd[2338846]: Failed password for invalid user valhallamountainlodge from 1.12.251.79 port 38372 ssh2\nJan 23 23:21:49 www3 sshd[2338848]: Invalid user valhallamountainlodge from 1.12.251.79 port 38388\nJan 23 23:21:49 www3 sshd[2338848]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \nJan 23 23:21:51 www3 sshd[2338848]: Failed password for invalid user valhallamountainlodge from 1.12.251.79 port 38388 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:21:52+00:00",
              "reporterId": 57667,
              "reporterCountryCode": "CA",
              "reporterCountryName": "Canada",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:21:27+00:00",
              "reporterId": 34960,
              "reporterCountryCode": "BE",
              "reporterCountryName": "Belgium",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 24 05:03:03 smtp sshd[1647244]: Failed password for invalid user westergard from 1.12.251.79 port 36334 ssh2\n\r\nJan 23 02:21:29 smtp sshd[1434196]: Failed password for invalid user root from 1.12.251.79 port 52770 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:03:04+00:00",
              "reporterId": 180770,
              "reporterCountryCode": "SE",
              "reporterCountryName": "Sweden",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 24 06:00:15 www4 sshd\\[37840\\]: Invalid user vellux from 1.12.251.79\nJan 24 06:00:15 www4 sshd\\[37840\\]: pam_unix\\(sshd:auth\\): authentication failure\\; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nJan 24 06:00:18 www4 sshd\\[37840\\]: Failed password for invalid user vellux from 1.12.251.79 port 32782 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T04:00:20+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "SmallGuard.fr/Prestashop SSH Login Failed",
              "categories": [
                18
              ],
              "reportedAt": "2026-01-24T03:37:27+00:00",
              "reporterId": 186589,
              "reporterCountryCode": "FR",
              "reporterCountryName": "France",
              "categories_human_readable": [
                "Brute Force"
              ]
            },
            {
              "comment": "SSH bruteforce [BY]",
              "categories": [
                22
              ],
              "reportedAt": "2026-01-24T03:17:30+00:00",
              "reporterId": 119867,
              "reporterCountryCode": "BY",
              "reporterCountryName": "Belarus",
              "categories_human_readable": [
                "SSH"
              ]
            },
            {
              "comment": "2026-01-24T04:02:01.664420+01:00 hosting13 sshd[3618909]: Invalid user dfaviation from 1.12.251.79 port 48420\n2026-01-24T04:02:01.850292+01:00 hosting13 sshd[3618909]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79 \n2026-01-24T04:02:03.756179+01:00 hosting13 sshd[3618909]: Failed password for invalid user dfaviation from 1.12.251.79 port 48420 ssh2\n2026-01-24T04:09:48.584823+01:00 hosting13 sshd[3623505]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79  user=brunodoedens\n2026-01-24T04:09:50.264527+01:00 hosting13 sshd[3623505]: Failed password for brunodoedens from 1.12.251.79 port 39570 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T03:09:50+00:00",
              "reporterId": 77277,
              "reporterCountryCode": "NL",
              "reporterCountryName": "Netherlands",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "",
              "categories": [
                14,
                18,
                22
              ],
              "reportedAt": "2026-01-24T03:07:13+00:00",
              "reporterId": 37710,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Port Scan",
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Jan 24 05:01:14 sauna sshd[133411]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.12.251.79\nJan 24 05:01:17 sauna sshd[133411]: Failed password for invalid user delichina from 1.12.251.79 port 40850 ssh2\n...",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-24T03:01:17+00:00",
              "reporterId": 31438,
              "reporterCountryCode": "FI",
              "reporterCountryName": "Finland",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            },
            {
              "comment": "Fail2Ban: Dovecot Attack 1.12.251.79 1769210664.0(JST)",
              "categories": [
                18,
                22
              ],
              "reportedAt": "2026-01-23T23:24:24+00:00",
              "reporterId": 164986,
              "reporterCountryCode": "JP",
              "reporterCountryName": "Japan",
              "categories_human_readable": [
                "Brute Force",
                "SSH"
              ]
            }
          ],
          "isPublic": true,
          "hostnames": [],
          "ipAddress": "1.12.251.79",
          "ipVersion": 4,
          "usageType": "Data Center/Web Hosting/Transit",
          "countryCode": "CN",
          "countryName": "China",
          "totalReports": 485,
          "isWhitelisted": false,
          "lastReportedAt": "2026-03-06T00:59:11+00:00",
          "numDistinctUsers": 78,
          "abuseConfidenceScore": 100
        },
        "permalink": "https://www.abuseipdb.com/check/1.12.251.79",
        "categories_found": {
          "SSH": 376,
          "Hacking": 6,
          "Phishing": 5,
          "Spoofing": 5,
          "Port Scan": 65,
          "Email Spam": 5,
          "Brute Force": 433,
          "Exploited Host": 14,
          "Web App Attack": 9,
          "FTP Brute-Force": 10
        }
      },
      "errors": [],
      "start_time": "2026-03-06T09:07:17.355180Z",
      "data_model": {
        "id": 5925,
        "analyzers_report": [
          25392
        ],
        "ietf_report": [],
        "evaluation": "malicious",
        "reliability": 10,
        "kill_chain_phase": null,
        "external_references": [
          "https://www.abuseipdb.com/check/1.12.251.79"
        ],
        "related_threats": [],
        "tags": [
          "port scan",
          "brute force",
          "ftp brute-force",
          "ssh",
          "phishing",
          "email spam",
          "spoofing",
          "web app attack",
          "exploited host",
          "hacking"
        ],
        "malware_family": null,
        "additional_info": {
          "description": "AbuseIPDB is a service where users can report malicious IP addresses attacking their infrastructure.This IP address has been categorized with some malicious categories",
          "distinct_users": 78
        },
        "date": "2026-03-06T09:07:18.075738Z",
        "asn": null,
        "asn_rank": null,
        "certificates": null,
        "org_name": null,
        "country_code": "cn",
        "registered_country_code": null,
        "isp": "tencent cloud computing (beijing) co., ltd.",
        "resolutions": []
      },
      "description": "check if an ip was reported on [AbuseIPDB](https://www.abuseipdb.com/)"
    }
  ],
  "connector_reports": [],
  "pivot_reports": [],
  "visualizer_reports": [
    {
      "name": "Reputation",
      "process_time": 0.07,
      "status": "SUCCESS",
      "end_time": "2026-03-06T09:07:25.790273Z",
      "parameters": {},
      "type": "visualizer",
      "id": 1704,
      "report": [
        {
          "elements": {
            "type": "horizontal_list",
            "values": [
              {
                "size": "auto",
                "type": "title",
                "title": {
                  "bold": false,
                  "icon": "virusTotal",
                  "link": "https://www.virustotal.com/gui/ip-address/1.12.251.79",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "VirusTotal",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "https://www.virustotal.com/gui/ip-address/1.12.251.79",
                  "description": ""
                },
                "value": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "Engine Hits: 5",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "Engine Hits: 5",
                  "description": ""
                },
                "disable": false,
                "alignment": "center"
              },
              {
                "size": "auto",
                "type": "title",
                "title": {
                  "bold": false,
                  "icon": "urlhaus",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "URLhaus",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "URLhaus",
                  "description": ""
                },
                "value": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "",
                  "description": ""
                },
                "disable": true,
                "alignment": "center"
              },
              {
                "size": "auto",
                "type": "title",
                "title": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "ThreatFox",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "ThreatFox",
                  "description": ""
                },
                "value": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "",
                  "description": ""
                },
                "disable": true,
                "alignment": "center"
              },
              {
                "size": "auto",
                "type": "title",
                "title": {
                  "bold": false,
                  "icon": "warning",
                  "link": "https://labs.inquest.net/repdb",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "InQuest",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "https://labs.inquest.net/repdb",
                  "description": ""
                },
                "value": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "found",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "found",
                  "description": ""
                },
                "disable": false,
                "alignment": "center"
              }
            ],
            "alignment": "around"
          },
          "level_size": "3",
          "level_position": 1
        },
        {
          "elements": {
            "type": "horizontal_list",
            "values": [
              {
                "name": {
                  "bold": false,
                  "icon": "info",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "info",
                  "value": "Crowdsec Classifications (0)",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "Crowdsec Classifications",
                  "description": ""
                },
                "size": "2",
                "type": "vertical_list",
                "values": [
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "no data available",
                    "italic": false,
                    "disable": true,
                    "alignment": "center",
                    "copy_text": "no data available",
                    "description": ""
                  }
                ],
                "disable": true,
                "alignment": "center",
                "start_open": true
              },
              {
                "name": {
                  "bold": false,
                  "icon": "alarm",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "danger",
                  "value": "AbuseIPDB Categories (10)",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "AbuseIPDB Categories",
                  "description": ""
                },
                "size": "2",
                "type": "vertical_list",
                "values": [
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "Brute Force",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "Brute Force",
                    "description": ""
                  },
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "FTP Brute-Force",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "FTP Brute-Force",
                    "description": ""
                  },
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "Email Spam",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "Email Spam",
                    "description": ""
                  },
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "Phishing",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "Phishing",
                    "description": ""
                  },
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "Web App Attack",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "Web App Attack",
                    "description": ""
                  },
                  {
                    "bold": true,
                    "icon": "",
                    "link": "http://localhost/jobs/2745/raw/analyzer",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "...",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "http://localhost/jobs/2745/raw/analyzer",
                    "description": "Inspect AbuseIPDB analyzer to view all the results."
                  }
                ],
                "disable": false,
                "alignment": "center",
                "start_open": true
              },
              {
                "name": {
                  "bold": false,
                  "icon": "alarm",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "danger",
                  "value": "Crowdsec Behaviors (2)",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "Crowdsec Behaviors",
                  "description": ""
                },
                "size": "2",
                "type": "vertical_list",
                "values": [
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "SSH Bruteforce",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "SSH Bruteforce",
                    "description": ""
                  },
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "Exploitation attempt",
                    "italic": false,
                    "disable": false,
                    "alignment": "center",
                    "copy_text": "Exploitation attempt",
                    "description": ""
                  }
                ],
                "disable": false,
                "alignment": "center",
                "start_open": true
              }
            ],
            "alignment": "around"
          },
          "level_size": "5",
          "level_position": 2
        },
        {
          "elements": {
            "type": "horizontal_list",
            "values": [
              {
                "size": "auto",
                "type": "title",
                "title": {
                  "bold": false,
                  "icon": "info",
                  "link": "https://www.abuseipdb.com/check/1.12.251.79",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "AbuseIPDB Meta",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "https://www.abuseipdb.com/check/1.12.251.79",
                  "description": ""
                },
                "value": {
                  "bold": false,
                  "icon": "",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "Tencent cloud computing (Beijing) Co., Ltd. (Data Center/Web Hosting/Transit)",
                  "italic": false,
                  "disable": false,
                  "alignment": "center",
                  "copy_text": "Tencent cloud computing (Beijing) Co., Ltd. (Data Center/Web Hosting/Transit)",
                  "description": ""
                },
                "disable": false,
                "alignment": "center"
              },
              {
                "name": {
                  "bold": false,
                  "icon": "fire",
                  "link": "",
                  "size": "auto",
                  "type": "base",
                  "color": "",
                  "value": "FireHol (0)",
                  "italic": false,
                  "disable": true,
                  "alignment": "center",
                  "copy_text": "FireHol",
                  "description": ""
                },
                "size": "auto",
                "type": "vertical_list",
                "values": [
                  {
                    "bold": false,
                    "icon": "",
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "color": "",
                    "value": "no data available",
                    "italic": false,
                    "disable": true,
                    "alignment": "center",
                    "copy_text": "no data available",
                    "description": ""
                  }
                ],
                "disable": true,
                "alignment": "center",
                "start_open": true
              },
              {
                "icon": "",
                "link": "",
                "size": "auto",
                "type": "bool",
                "color": "danger",
                "value": "Tor Exit Node",
                "italic": false,
                "disable": true,
                "copy_text": "Tor Exit Node",
                "description": ""
              },
              {
                "icon": "",
                "link": "",
                "size": "auto",
                "type": "bool",
                "color": "danger",
                "value": "Talos Reputation",
                "italic": false,
                "disable": true,
                "copy_text": "Talos Reputation",
                "description": ""
              }
            ],
            "alignment": "around"
          },
          "level_size": "6",
          "level_position": 3
        }
      ],
      "errors": [],
      "start_time": "2026-03-06T09:07:25.723495Z",
      "config": "IP_Reputation",
      "description": "Visualizer for the Playbook \"Popular_IP_Reputation_Services\""
    }
  ],
  "analyzable_id": 1557,
  "received_request_time": "2026-03-06T09:07:16.885196Z",
  "finished_analysis_time": "2026-03-06T09:07:25.896076Z",
  "process_time": 9.01,
  "warnings": [],
  "errors": []
}
""")

    # 2. Llamamos a la función principal
    try:
        print("[*] Generando STIX Bundle...")
        bundle_resultado = job_to_stix_bundle(datos_analisis)

        # 3. Guardamos el resultado en un archivo JSON para inspeccionarlo mejor
        with open("resultado_stix.json", "w", encoding="utf-8") as f:
            json.dump(bundle_resultado, f, indent=2, ensure_ascii=False)
        
        print("[✓] ¡Éxito! El bundle se ha guardado en 'resultado_stix.json'")
        
        # 4. También lo imprimimos por pantalla para verlo ahora mismo
        print("\n--- VISTA PREVIA DEL BUNDLE ---")
        # Imprimimos solo los tipos de objetos creados para no saturar la consola
        for obj in bundle_resultado['objects']:
            print(f"Objeto creado: {obj['type']} -> ID: {obj['id']}")

    except Exception as e:
        print(f"[X] Error: {e}")