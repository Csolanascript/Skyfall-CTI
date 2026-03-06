"""
Test script para el STIX converter de IP.
Ejecutar desde el directorio tests/ con el venv activo:
    source .venv/bin/activate
    python3 test_converter.py
"""
import sys
import json
import os

# Añadir el directorio del converter al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'intelowl-client'))

from stix_converter_ip import job_to_stix_bundle

# ── Payload de prueba: job result de IntelOwl para 1.12.251.79 ──────────────
datos_analisis = {
    "id": 2745,
    "observable_name": "1.12.251.79",
    "observable_classification": "ip",
    "file_name": "1.12.251.79",
    "is_sample": False,
    "analyzer_reports": [
        # ----------------------------------------------------------------- AbuseIPDB
        {
            "name": "AbuseIPDB",
            "status": "SUCCESS",
            "report": {
                "data": {
                    "isp": "Tencent cloud computing (Beijing) Co., Ltd.",
                    "isTor": False,
                    "domain": "tencent.com",
                    "reports": [
                        {
                            "comment": "PERMA offender. Observed 9025 times.",
                            "categories": [14, 18],
                            "reportedAt": "2026-03-06T00:59:11+00:00",
                            "reporterId": 259031,
                            "reporterCountryCode": "US",
                            "reporterCountryName": "United States of America",
                            "categories_human_readable": ["Port Scan", "Brute Force"]
                        },
                        {
                            "comment": "SSH brute force attacks",
                            "categories": [18, 22],
                            "reportedAt": "2026-02-03T07:19:48+00:00",
                            "reporterId": 258806,
                            "reporterCountryCode": "DE",
                            "reporterCountryName": "Germany",
                            "categories_human_readable": ["Brute Force", "SSH"]
                        },
                        {
                            "comment": "ThreatBook Intelligence: Zombie,IDC",
                            "categories": [5],
                            "reportedAt": "2026-02-05T00:03:29+00:00",
                            "reporterId": 56171,
                            "reporterCountryCode": "CN",
                            "reporterCountryName": "China",
                            "categories_human_readable": ["FTP Brute-Force"]
                        },
                        {
                            "comment": "Fail2Ban triggered for postfix-sasl",
                            "categories": [7, 11, 17],
                            "reportedAt": "2026-02-04T12:17:26+00:00",
                            "reporterId": 94865,
                            "reporterCountryCode": "AU",
                            "reporterCountryName": "Australia",
                            "categories_human_readable": ["Phishing", "Email Spam", "Spoofing"]
                        },
                        {
                            "comment": "Web app attack detected",
                            "categories": [18, 21],
                            "reportedAt": "2026-02-02T06:00:07+00:00",
                            "reporterId": 267320,
                            "reporterCountryCode": "CZ",
                            "reporterCountryName": "Czechia",
                            "categories_human_readable": ["Brute Force", "Web App Attack"]
                        }
                    ],
                    "isPublic": True,
                    "hostnames": [],
                    "ipAddress": "1.12.251.79",
                    "ipVersion": 4,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "countryCode": "CN",
                    "countryName": "China",
                    "totalReports": 485,
                    "isWhitelisted": False,
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
            "errors": []
        },
        # ----------------------------------------------------------------- ApiVoid
        {
            "name": "ApiVoid",
            "status": "SUCCESS",
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
                    "country_code": "CN",
                    "abuse_email": "tencent_noc@tencent.com",
                    "total_ipv4_ips": 12644608
                },
                "version": "IPv4",
                "anonymity": {
                    "is_tor": False,
                    "is_vpn": False,
                    "is_proxy": False,
                    "is_relay": False,
                    "is_hosting": True,
                    "is_webproxy": False,
                    "is_residential_proxy": False
                },
                "blacklists": {
                    "engines": {
                        "7": {"name": "BitNinja", "detected": True, "reference": "https://bitninja.com/", "elapsed_ms": 0},
                        "31": {"name": "IPsum", "detected": True, "reference": "https://github.com/stamparm/ipsum", "elapsed_ms": 0},
                        "61": {"name": "S5hbl", "detected": True, "reference": "https://www.usenix.org.uk/content/rbl.html", "elapsed_ms": 48}
                    },
                    "detections": 3,
                    "scan_time_ms": 281,
                    "engines_count": 79,
                    "detection_rate": "3%"
                },
                "elapsed_ms": 522,
                "risk_score": {"result": 70},
                "information": {
                    "asn": "AS45090",
                    "isp": "Tencent Cloud Computing (Beijing) Co. Ltd.",
                    "is_eu": False,
                    "is_bogon": False,
                    "latitude": 23.127361,
                    "city_name": "Guangzhou",
                    "longitude": 113.26457,
                    "region_name": "Guangdong",
                    "country_code": "CN",
                    "country_name": "China",
                    "cloud_provider": "Tencent Cloud",
                    "continent_code": "AS",
                    "continent_name": "Asia"
                }
            },
            "errors": []
        },
        # ----------------------------------------------------------------- VirusTotal
        {
            "name": "VirusTotal_v3_Get_Observable",
            "status": "SUCCESS",
            "report": {
                "data": {
                    "id": "1.12.251.79",
                    "type": "ip_address",
                    "attributes": {
                        "asn": 45090,
                        "country": "CN",
                        "network": "1.12.128.0/17",
                        "as_owner": "Shenzhen Tencent Computer Systems Company Limited",
                        "continent": "AS",
                        "reputation": 0,
                        "jarm": "3fd3fd0003fd3fd21c42d42d000000bdfc58c9a46434368cf60aa440385763",
                        "regional_internet_registry": "APNIC",
                        "last_analysis_stats": {
                            "timeout": 0,
                            "harmless": 58,
                            "malicious": 5,
                            "suspicious": 4,
                            "undetected": 27
                        },
                        "last_analysis_results": {
                            "Fortinet": {"method": "blacklist", "result": "malware", "category": "malicious", "engine_name": "Fortinet"},
                            "Cluster25": {"method": "blacklist", "result": "malicious", "category": "malicious", "engine_name": "Cluster25"},
                            "GreyNoise": {"method": "blacklist", "result": "malicious", "category": "malicious", "engine_name": "GreyNoise"},
                            "MalwareURL": {"method": "blacklist", "result": "malware", "category": "malicious", "engine_name": "MalwareURL"},
                            "Criminal IP": {"method": "blacklist", "result": "malicious", "category": "malicious", "engine_name": "Criminal IP"},
                            "AlphaSOC": {"method": "blacklist", "result": "suspicious", "category": "suspicious", "engine_name": "AlphaSOC"},
                            "SOCRadar": {"method": "blacklist", "result": "suspicious", "category": "suspicious", "engine_name": "SOCRadar"},
                            "ESET": {"method": "blacklist", "result": "clean", "category": "harmless", "engine_name": "ESET"}
                        },
                        "last_https_certificate": {
                            "issuer": {"C": "US", "O": "Let's Encrypt", "CN": "R12"},
                            "subject": {"CN": "tmavc.mavk.cn"},
                            "validity": {
                                "not_after": "2026-05-07 12:53:15",
                                "not_before": "2026-02-06 12:53:16"
                            },
                            "thumbprint": "9c48fa3cccd7705aa693c4f6923d343fb2d720ae",
                            "serial_number": "61766bc8742684b26fc0cc977ddd4aacc13"
                        },
                        "rdap": {
                            "name": "TencentCloud",
                            "country": "CN",
                            "status": ["active"]
                        },
                        "total_votes": {"harmless": 0, "malicious": 0}
                    },
                    "relationships": {
                        "resolutions": {
                            "data": [
                                {"id": "1.12.251.79rbsvcx.kxzu.cn", "type": "resolution"},
                                {"id": "1.12.251.79rmacvb.kxzo.cn", "type": "resolution"},
                                {"id": "1.12.251.79tmavc.mavk.cn", "type": "resolution"},
                                {"id": "1.12.251.79trnbnd.ktbv.cn", "type": "resolution"},
                                {"id": "1.12.251.79yyr.xxsq.cn", "type": "resolution"}
                            ]
                        }
                    }
                },
                "link": "https://www.virustotal.com/gui/ip-address/1.12.251.79"
            },
            "errors": []
        },
        # ----------------------------------------------------------------- Crowdsec
        {
            "name": "Crowdsec",
            "status": "SUCCESS",
            "report": {
                "ip": "1.12.251.79",
                "cves": [],
                "as_num": 45090,
                "scores": {
                    "overall": {"total": 5, "trust": 5, "threat": 4, "anomaly": 1, "aggressiveness": 5},
                    "last_day": {"total": 1, "trust": 2, "threat": 4, "anomaly": 1, "aggressiveness": 0},
                    "last_month": {"total": 4, "trust": 5, "threat": 4, "anomaly": 1, "aggressiveness": 3}
                },
                "as_name": "Shenzhen Tencent Computer Systems Company Limited",
                "history": {
                    "days_age": 27,
                    "full_age": 35,
                    "last_seen": "2026-03-06T02:00:00+00:00",
                    "first_seen": "2026-01-12T17:45:00+00:00"
                },
                "ip_range": "1.12.128.0/17",
                "location": {"city": "Guangzhou", "country": "CN", "latitude": 23.1181, "longitude": 113.2539},
                "behaviors": [
                    {"name": "ssh:bruteforce", "label": "SSH Bruteforce", "references": [], "description": "IP has been reported for performing brute force on ssh services."},
                    {"name": "generic:exploit", "label": "Exploitation attempt", "references": [], "description": "IP has been reported trying to exploit known vulnerability/CVE."}
                ],
                "confidence": "high",
                "references": [
                    {"name": "list:crowdsec_hosting_blocklist", "label": "Hosting Services Attackers", "references": [], "description": "Contains IPs attacking hosting providers."},
                    {"name": "list:crowdsec_bruteforce", "label": "Bruteforce Attackers", "references": [], "description": "Contains IPs mainly reported for Bruteforce."},
                    {"name": "list:crowdsec_healthcare_blocklist", "label": "Healthcare Attackers", "references": [], "description": "Contains IPs attacking healthcare organizations."}
                ],
                "reputation": "malicious",
                "attack_details": [
                    {"name": "crowdsecurity/ssh-slow-bf", "label": "SSH Slow Bruteforce", "references": [], "description": "Detect slow ssh bruteforce"},
                    {"name": "crowdsecurity/suricata-major-severity", "label": "Suricata Severity 1 Event", "references": [], "description": "Detect exploit attempts via emerging threat rules"},
                    {"name": "crowdsecurity/ssh-bf", "label": "SSH Bruteforce", "references": [], "description": "Detect ssh bruteforce"}
                ],
                "mitre_techniques": [
                    {"name": "T1110", "label": "Brute Force", "references": [], "description": "Adversaries may use brute force techniques."},
                    {"name": "T1190", "label": "Exploit Public-Facing Application", "references": [], "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host."},
                    {"name": "T1595", "label": "Active Scanning", "references": [], "description": "Adversaries may execute active reconnaissance scans."},
                    {"name": "T1589", "label": "Gather Victim Identity Information", "references": [], "description": "Adversaries may gather victim identity information."}
                ],
                "target_countries": {"AT": 2, "AU": 14, "DE": 34, "FI": 1, "FR": 21, "GB": 3, "NL": 3, "RU": 2, "UA": 6, "US": 7},
                "ip_range_score": 5,
                "background_noise": "medium",
                "background_noise_score": 7,
                "proxy_or_vpn": False,
                "link": "https://app.crowdsec.net/cti/1.12.251.79"
            },
            "errors": []
        },
        # ----------------------------------------------------------------- URLhaus (sin resultados)
        {
            "name": "URLhaus",
            "status": "SUCCESS",
            "report": {"query_status": "no_results"},
            "errors": []
        },
        # ----------------------------------------------------------------- ThreatFox (sin resultados)
        {
            "name": "ThreatFox",
            "status": "SUCCESS",
            "report": {"data": "Your search did not yield any results", "query_status": "no_result"},
            "errors": []
        },
        # ----------------------------------------------------------------- FireHol (sin resultados)
        {
            "name": "FireHol_IPList",
            "status": "SUCCESS",
            "report": {"firehol_level1.netset": False},
            "errors": []
        },
        # ----------------------------------------------------------------- TalosReputation (no encontrado)
        {
            "name": "TalosReputation",
            "status": "SUCCESS",
            "report": {"found": False},
            "errors": []
        }
    ]
}

# ── Ejecutar el converter ────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        print("[*] Generando STIX Bundle para 1.12.251.79 ...")
        bundle = job_to_stix_bundle(datos_analisis)

        # Guardar resultado
        out_path = os.path.join(os.path.dirname(__file__), "resultado_stix.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)

        print(f"[✓] Bundle guardado en: {out_path}\n")

        # Resumen por tipo de objeto
        from collections import Counter
        type_counts = Counter(obj["type"] for obj in bundle["objects"])
        print("--- OBJETOS CREADOS ---")
        for t, count in sorted(type_counts.items()):
            print(f"  {t:<25} x{count}")

        print(f"\n  TOTAL: {len(bundle['objects'])} objetos STIX")

        # Mostrar relaciones
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        if rels:
            print("\n--- RELACIONES ---")
            for r in rels:
                print(f"  {r.get('source_ref','?').split('--')[0]}"
                      f"  --[{r['relationship_type']}]-->"
                      f"  {r.get('target_ref','?').split('--')[0]}")

        # Mostrar confidence del Indicator
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        if indicators:
            ind = indicators[0]
            print(f"\n--- INDICATOR ---")
            print(f"  name       : {ind.get('name')}")
            print(f"  confidence : {ind.get('confidence')}")
            print(f"  types      : {ind.get('indicator_types')}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[X] Error: {e}")
