import nmap
import os

def scan_active_hosts(network: str) -> dict:
    """
    Escanea hosts activos en una red.
    Ejemplo de network: '192.168.1.0/24'
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments="-sn")

        hosts = []
        for host in nm.all_hosts():
            hosts.append({
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state()
            })

        return {
            "network": network,
            "total_hosts": len(hosts),
            "hosts": hosts
        }

    except Exception as e:
        return {"error": str(e)}


def scan_open_ports(host: str) -> dict:
    """
    Escanea puertos abiertos de un host específico.
    Ejemplo de host: '192.168.1.1'
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments="-sV --top-ports 100")

        if host not in nm.all_hosts():
            return {"error": f"Host {host} no encontrado o inaccesible"}

        ports = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                ports.append({
                    "port": port,
                    "protocol": proto,
                    "state": port_info["state"],
                    "service": port_info["name"],
                    "version": port_info.get("version", ""),
                    "product": port_info.get("product", "")
                })

        return {
            "host": host,
            "hostname": nm[host].hostname(),
            "total_ports": len(ports),
            "ports": ports
        }

    except Exception as e:
        return {"error": str(e)}