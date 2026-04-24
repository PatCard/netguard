import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves(service: str, version: str = "") -> dict:
    """
    Busca CVEs conocidos para un servicio y versión específica.
    Usa la API gratuita del NVD (National Vulnerability Database).
    """
    try:
        keyword = f"{service} {version}".strip()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
            "startIndex": 0
        }

        response = requests.get(NVD_API_URL, params=params, timeout=10)

        if response.status_code != 200:
            return {"error": f"Error al consultar NVD: {response.status_code}"}

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "service": service,
                "version": version,
                "total_cves": 0,
                "cves": [],
                "message": f"No se encontraron CVEs para {keyword}"
            }

        cves = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "Sin descripción"
            )

            # Obtener score CVSS
            metrics = cve.get("metrics", {})
            score = None
            severity = None

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = metrics["cvssMetricV2"][0].get("baseSeverity")

            cves.append({
                "id": cve_id,
                "description": description[:300],
                "score": score,
                "severity": severity
            })

        return {
            "service": service,
            "version": version,
            "total_cves": data.get("totalResults", 0),
            "cves": cves
        }

    except Exception as e:
        return {"error": str(e)}


def check_weak_config(ports: list) -> dict:
    """
    Detecta configuraciones débiles basándose en los puertos abiertos.
    """
    warnings = []

    weak_services = {
        21:   "FTP — transferencia sin cifrado, credenciales expuestas",
        23:   "Telnet — protocolo sin cifrado, reemplazar por SSH",
        80:   "HTTP — tráfico sin cifrado, considerar HTTPS",
        139:  "NetBIOS — puede exponer recursos de red",
        445:  "SMB — vector común de ataques (EternalBlue, WannaCry)",
        1433: "MSSQL — base de datos expuesta directamente",
        1521: "Oracle DB — base de datos expuesta directamente",
        3306: "MySQL — base de datos expuesta directamente",
        3389: "RDP — escritorio remoto expuesto, riesgo de fuerza bruta",
        5900: "VNC — escritorio remoto sin cifrado",
        6379: "Redis — base de datos sin autenticación por defecto",
        27017: "MongoDB — base de datos sin autenticación por defecto"
    }

    for port_info in ports:
        port = port_info.get("port")
        if port in weak_services:
            warnings.append({
                "port": port,
                "service": port_info.get("service", ""),
                "warning": weak_services[port],
                "severity": "HIGH" if port in [23, 445, 3389, 6379, 27017] else "MEDIUM"
            })

    return {
        "total_warnings": len(warnings),
        "warnings": warnings,
        "is_secure": len(warnings) == 0
    }
