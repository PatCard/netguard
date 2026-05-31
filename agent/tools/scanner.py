import nmap


def scan_active_hosts(network: str) -> dict:
    """
    Escanea hosts activos en una red usando ping sweep.
    Ejemplo de network: '192.168.1.0/24'
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments="-sn")

        hosts = []
        for host in nm.all_hosts():
            hosts.append({
                "ip":       host,
                "hostname": nm[host].hostname() or "unknown",
                "state":    nm[host].state(),
            })

        return {
            "network":     network,
            "total_hosts": len(hosts),
            "hosts":       hosts,
        }

    except Exception as e:
        return {"error": str(e)}


def scan_open_ports(host: str) -> dict:
    """
    Escanea puertos abiertos de un host con detección de versión y OS.
    Solo retorna puertos en estado 'open'.
    Ejemplo de host: '192.168.1.1'
    """
    try:
        nm = nmap.PortScanner()
        # -sV: detección de versión
        # -O: detección de OS (requiere root)
        # --top-ports 1000: cubre el estándar de seguridad
        # --open: solo puertos abiertos
        nm.scan(hosts=host, arguments="-sV -O --top-ports 1000 --open")

        if host not in nm.all_hosts():
            return {"error": f"Host {host} no encontrado o inaccesible"}

        host_data = nm[host]

        # --- Puertos abiertos ---
        ports = []
        for proto in host_data.all_protocols():
            for port, port_info in host_data[proto].items():
                if port_info["state"] != "open":
                    continue

                product = port_info.get("product", "").strip()
                version = port_info.get("version", "").strip()

                # full_version listo para pasarle a search_cves
                full_version = " ".join(filter(None, [product, version]))

                ports.append({
                    "port":         port,
                    "protocol":     proto,
                    "state":        port_info["state"],
                    "service":      port_info["name"],
                    "product":      product,
                    "version":      version,
                    "full_version": full_version or "unknown",
                })

        # --- Sistema operativo ---
        os_info = _extract_os(host_data)

        return {
            "host":        host,
            "hostname":    host_data.hostname() or "unknown",
            "total_ports": len(ports),
            "ports":       ports,
            "os":          os_info,
        }

    except Exception as e:
        return {"error": str(e)}


def _extract_os(host_data) -> dict:
    """
    Extrae la mejor coincidencia de OS detectado por Nmap.
    Retorna un dict con name, accuracy y family.
    """
    try:
        osmatch = host_data.get("osmatch", [])
        if not osmatch:
            return {"name": "unknown", "accuracy": 0, "family": "unknown"}

        # Nmap ordena por accuracy descendente, tomamos el primero
        best = osmatch[0]
        osclass = best.get("osclass", [{}])[0]

        return {
            "name":     best.get("name", "unknown"),
            "accuracy": int(best.get("accuracy", 0)),
            "family":   osclass.get("osfamily", "unknown"),
            "vendor":   osclass.get("vendor", "unknown"),
        }

    except Exception:
        return {"name": "unknown", "accuracy": 0, "family": "unknown"}