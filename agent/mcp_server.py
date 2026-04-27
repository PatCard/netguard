from mcp.server.fastmcp import FastMCP
from tools.scanner import scan_active_hosts, scan_open_ports
from tools.cve import search_cves, check_weak_config
from tools.monitor import check_new_devices

mcp = FastMCP("NetGuard")

@mcp.tool()
def scan_network(network: str) -> dict:
    """
    Escanea todos los hosts activos en una red local.
    
    Args:
        network: Red en formato CIDR. Ejemplo: 192.168.1.0/24
    """
    return scan_active_hosts(network)

@mcp.tool()
def scan_ports(host: str) -> dict:
    """
    Escanea los puertos abiertos de un host específico.
    
    Args:
        host: IP del host a escanear. Ejemplo: 192.168.1.1
    """
    return scan_open_ports(host)

@mcp.tool()
def find_cves(service: str, version: str = "") -> dict:
    """
    Busca vulnerabilidades CVE conocidas para un servicio y versión.
    
    Args:
        service: Nombre del servicio. Ejemplo: nginx, openssh, apache
        version: Versión del servicio. Ejemplo: 1.18.0
    """
    return search_cves(service, version)

@mcp.tool()
def analyze_weak_config(ports: list) -> dict:
    """
    Detecta configuraciones débiles o peligrosas en los puertos abiertos.
    
    Args:
        ports: Lista de puertos abiertos con su información
    """
    return check_weak_config(ports)

@mcp.tool()
def monitor_network(network: str) -> dict:
    """
    Monitorea la red y detecta dispositivos nuevos no registrados anteriormente.
    
    Args:
        network: Red en formato CIDR. Ejemplo: 192.168.1.0/24
    """
    return check_new_devices(network)

if __name__ == "__main__":
    mcp.run()
