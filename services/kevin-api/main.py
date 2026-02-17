# ============================================================================
#  Skyfall-CTI · KEVin API
#  Este servicio ahora usa el proyecto real synfinner/KEVin.
#  El punto de entrada es kevin.py (Flask), NO este archivo.
#  Se conserva únicamente como referencia de la migración.
#
#  KEVin endpoints principales:
#    /kev                       → Todos los KEV
#    /kev/<CVE-ID>              → KEV por CVE
#    /kev/recent?days=7         → KEVs recientes
#    /kev/exists?cve=CVE-xxx    → Existencia en KEV
#    /vuln/<CVE-ID>             → Datos CISA+MITRE+NVD
#    /vuln/<CVE-ID>/nvd         → Solo NVD
#    /vuln/<CVE-ID>/mitre       → Solo MITRE
#    /vuln/published?days=7     → CVEs recientes en NVD
#    /get_metrics               → Métricas (total CVEs/KEVs)
#
#  Documentación: https://github.com/synfinner/KEVin
# ============================================================================
