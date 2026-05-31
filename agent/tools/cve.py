import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Mapeo de servicios comunes a su CPE vendor:product
CPE_MAP = {
    "nginx":      "nginx:nginx",
    "apache":     "apache:http_server",
    "openssh":    "openbsd:openssh",
    "ssh":        "openbsd:openssh",
    "mysql":      "mysql:mysql",
    "mariadb":    "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "redis":      "redis:redis",
    "mongodb":    "mongodb:mongodb",
    "ftp":        "vsftpd:vsftpd",
    "vsftpd":     "vsftpd:vsftpd",
    "smb":        "microsoft:windows",
    "rdp":        "microsoft:windows",
    "telnet":     "mit:kerberos",
    "upnp":       "portable_sdk_for_upnp_devices:portable_sdk_for_upnp_devices",
}

WEAK_SERVICES = {
    21:    ("FTP — transferencia sin cifrado, credenciales expuestas",          "MEDIUM"),
    23:    ("Telnet — protocolo sin cifrado, reemplazar por SSH",               "HIGH"),
    80:    ("HTTP — tráfico sin cifrado, considerar redirigir al puerto 443",   "MEDIUM"),
    139:   ("NetBIOS — puede exponer recursos de red",                          "MEDIUM"),
    445:   ("SMB — vector común de ataques (EternalBlue, WannaCry)",            "HIGH"),
    1433:  ("MSSQL — base de datos expuesta directamente",                      "MEDIUM"),
    1521:  ("Oracle DB — base de datos expuesta directamente",                  "MEDIUM"),
    3306:  ("MySQL — base de datos expuesta directamente",                      "MEDIUM"),
    3389:  ("RDP — escritorio remoto expuesto, riesgo de fuerza bruta",         "HIGH"),
    5900:  ("VNC — escritorio remoto sin cifrado",                              "HIGH"),
    6379:  ("Redis — sin autenticación por defecto",                            "HIGH"),
    27017: ("MongoDB — sin autenticación por defecto",                          "HIGH"),
}


def _build_cpe_name(service: str, version: str) -> str | None:
    """
    Construye un CPE 2.3 a partir del servicio y versión.
    Retorna None si el servicio no está en el mapa.
    """
    key = service.lower().strip()
    vendor_product = CPE_MAP.get(key)
    if not vendor_product:
        return None
    if version:
        return f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"
    return f"cpe:2.3:a:{vendor_product}:*:*:*:*:*:*:*:*"


def _parse_vulnerabilities(vulnerabilities: list) -> list:
    """
    Extrae los campos relevantes de cada CVE retornado por NVD.
    Prioriza CVSS v3.1 sobre v3.0 sobre v2.
    """
    cves = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})

        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "Sin descripción disponible"
        )

        metrics = cve.get("metrics", {})
        score, severity, vector = None, None, None

        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]
            cvss = data["cvssData"]
            score    = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            vector   = cvss.get("attackVector")
        elif "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0]
            cvss = data["cvssData"]
            score    = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            vector   = cvss.get("attackVector")
        elif "cvssMetricV2" in metrics:
            data = metrics["cvssMetricV2"][0]
            cvss = data["cvssData"]
            score    = cvss.get("baseScore")
            severity = data.get("baseSeverity")
            vector   = cvss.get("accessVector")

        published = cve.get("published", "")[:10]  # solo fecha YYYY-MM-DD

        cves.append({
            "id":          cve_id,
            "description": description[:400],
            "score":       score,
            "severity":    severity,
            "vector":      vector,
            "published":   published,
        })

    # Ordenar por score descendente para mostrar los más críticos primero
    cves.sort(key=lambda x: x["score"] or 0, reverse=True)
    return cves


def search_cves(service: str, version: str = "") -> dict:
    """
    Busca CVEs para un servicio y versión específica.
    Intenta primero con CPE exacto; si no hay resultados o el servicio
    no está mapeado, cae a keyword como fallback.
    """
    service = service.strip()
    version = version.strip()

    cpe_name = _build_cpe_name(service, version)
    used_method = "cpe" if cpe_name else "keyword"

    try:
        # --- Intento 1: búsqueda por CPE ---
        if cpe_name:
            params = {
                "cpeName":        cpe_name,
                "resultsPerPage": 5,
                "startIndex":     0,
            }
            response = requests.get(NVD_API_URL, params=params, timeout=10)

            if response.status_code == 200:
                data            = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if vulnerabilities:
                    return {
                        "service":     service,
                        "version":     version,
                        "cpe":         cpe_name,
                        "method":      used_method,
                        "total_cves":  data.get("totalResults", 0),
                        "cves":        _parse_vulnerabilities(vulnerabilities),
                    }

            # Si CPE no dio resultados, pasamos a fallback
            used_method = "keyword_fallback"

        # --- Intento 2: fallback por keyword (servicio + versión) ---
        keyword = f"{service} {version}".strip()
        params  = {
            "keywordSearch":  keyword,
            "resultsPerPage": 5,
            "startIndex":     0,
        }
        response = requests.get(NVD_API_URL, params=params, timeout=10)

        if response.status_code != 200:
            return {"error": f"Error al consultar NVD: {response.status_code}"}

        data            = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "service":    service,
                "version":    version,
                "method":     used_method,
                "total_cves": 0,
                "cves":       [],
                "message":    f"No se encontraron CVEs para {keyword}",
            }

        return {
            "service":    service,
            "version":    version,
            "method":     used_method,
            "total_cves": data.get("totalResults", 0),
            "cves":       _parse_vulnerabilities(vulnerabilities),
        }

    except requests.Timeout:
        return {"error": "Timeout al consultar NVD — intenta nuevamente"}
    except Exception as e:
        return {"error": str(e)}


def check_weak_config(ports: list) -> dict:
    """
    Detecta configuraciones débiles basándose en los puertos abiertos.
    Evita falsos positivos: si el puerto 80 está abierto pero el 443 también,
    la advertencia cambia a 'redirigir HTTP → HTTPS' en vez de 'no tiene HTTPS'.
    """
    warnings  = []
    open_ports = {p.get("port") for p in ports}

    for port_info in ports:
        port = port_info.get("port")
        if port not in WEAK_SERVICES:
            continue

        message, severity = WEAK_SERVICES[port]

        # Caso especial: puerto 80 con 443 activo
        if port == 80 and 443 in open_ports:
            message  = "HTTP activo junto a HTTPS — asegurarse de redirigir 80 → 443"
            severity = "LOW"

        warnings.append({
            "port":     port,
            "service":  port_info.get("service", ""),
            "warning":  message,
            "severity": severity,
        })

    # Ordenar: HIGH primero
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    warnings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return {
        "total_warnings": len(warnings),
        "warnings":       warnings,
        "is_secure":      len(warnings) == 0,
    }