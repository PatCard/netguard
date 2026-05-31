from mcp.server.fastmcp import FastMCP
from tools.scanner import scan_active_hosts, scan_open_ports
from tools.cve import search_cves, check_weak_config
from tools.monitor import check_new_devices

mcp = FastMCP("NetGuard")


@mcp.tool()
def scan_network(network: str) -> dict:
    """
    Escanea todos los hosts activos en una red local usando ping sweep.
    Úsala cuando el usuario quiera descubrir qué dispositivos hay en la red,
    listar IPs activas, o como primer paso antes de auditar un host específico.

    Args:
        network: Red en formato CIDR. Ejemplo: 192.168.1.0/24
    """
    return scan_active_hosts(network)


@mcp.tool()
def scan_ports(host: str) -> dict:
    """
    Escanea los puertos abiertos de un host específico con detección de
    servicio, versión y sistema operativo. Retorna solo puertos en estado
    'open'. Úsala antes de buscar CVEs — necesitas el campo 'full_version'
    de cada puerto para hacer búsquedas precisas.

    Args:
        host: IP del host a escanear. Ejemplo: 192.168.1.1
    """
    return scan_open_ports(host)


@mcp.tool()
def find_cves(service: str, version: str = "") -> dict:
    """
    Busca vulnerabilidades CVE conocidas para un servicio y versión específica.
    IMPORTANTE: Llama esta tool una vez por cada servicio encontrado en
    scan_ports. Usa el campo 'service' como parámetro 'service' y el campo
    'full_version' como parámetro 'version'. Nunca uses términos genéricos
    como 'http' o 'ssh' sin versión — generará resultados irrelevantes.

    Ejemplos correctos:
        service='nginx',   version='1.18.0'
        service='openssh', version='OpenSSH 8.9p1'
        service='apache',  version='2.4.54'

    Ejemplos incorrectos:
        service='http',  version=''
        service='ssh',   version=''

    Args:
        service: Nombre del servicio detectado por Nmap. Ejemplo: nginx, openssh
        version: Versión completa del servicio (campo full_version de scan_ports)
    """
    return search_cves(service, version)


@mcp.tool()
def analyze_weak_config(ports: list) -> dict:
    """
    Detecta configuraciones débiles o peligrosas basándose en los puertos
    abiertos. Úsala siempre después de scan_ports, pasando directamente
    el campo 'ports' del resultado. Considera contexto: si el puerto 80
    y 443 están ambos abiertos, la advertencia es distinta a si solo está
    el 80.

    Args:
        ports: Lista completa de puertos retornada por scan_ports
    """
    return check_weak_config(ports)


@mcp.tool()
def audit_host(host: str) -> dict:
    """
    Auditoría completa de un host: escanea puertos, detecta configuraciones
    débiles y busca CVEs para cada servicio encontrado. Úsala cuando el
    usuario pida 'auditar', 'analizar', 'revisar seguridad' o 'escanear'
    un host específico. Es preferible a llamar scan_ports + find_cves por
    separado porque orquesta el flujo completo correctamente.

    Args:
        host: IP del host a auditar. Ejemplo: 192.168.1.1
    """
    # 1. Escanear puertos
    scan_result = scan_open_ports(host)
    if "error" in scan_result:
        return scan_result

    ports = scan_result.get("ports", [])

    # 2. Detectar configuraciones débiles
    weak_config = check_weak_config(ports)

    # 3. Buscar CVEs por cada servicio encontrado (sin duplicados)
    seen_services = set()
    cve_results   = []

    for port in ports:
        service      = port.get("service", "").lower()
        full_version = port.get("full_version", "")

        # Evitar buscar el mismo servicio+versión dos veces
        key = f"{service}:{full_version}"
        if not service or service in ("unknown", "") or key in seen_services:
            continue

        seen_services.add(key)
        cve_data = search_cves(service, full_version)
        if cve_data.get("total_cves", 0) > 0:
            cve_results.append(cve_data)

    return {
        "host":        host,
        "hostname":    scan_result.get("hostname", "unknown"),
        "os":          scan_result.get("os", {}),
        "total_ports": scan_result.get("total_ports", 0),
        "ports":       ports,
        "weak_config": weak_config,
        "cve_results": cve_results,
    }


@mcp.tool()
def monitor_network(network: str) -> dict:
    """
    Monitorea la red y detecta dispositivos nuevos que no estaban registrados
    en el escaneo anterior. Úsala cuando el usuario quiera saber si apareció
    algún dispositivo desconocido o para monitoreo continuo de la red.

    Args:
        network: Red en formato CIDR. Ejemplo: 192.168.1.0/24
    """
    return check_new_devices(network)


if __name__ == "__main__":
    mcp.run()