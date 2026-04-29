from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional
from tools.scanner import scan_active_hosts, scan_open_ports
from tools.cve import search_cves, check_weak_config
from tools.monitor import check_new_devices
import json

class NetworkAuditState(TypedDict):
    network: str
    hosts: List[dict]
    scan_results: List[dict]
    vulnerabilities: List[dict]
    weak_configs: List[dict]
    new_devices: List[dict]
    report: Optional[str]
    current_step: str
    errors: List[str]

def discover_hosts(state: NetworkAuditState) -> NetworkAuditState:
    print(f"[LangGraph] Descubriendo hosts en {state['network']}...")
    result = scan_active_hosts(state["network"])
    if "error" in result:
        state["errors"].append(f"Error descubriendo hosts: {result['error']}")
        state["hosts"] = []
    else:
        state["hosts"] = result.get("hosts", [])
    state["current_step"] = "discover_hosts"
    return state

def scan_hosts(state: NetworkAuditState) -> NetworkAuditState:
    print(f"[LangGraph] Escaneando puertos de {len(state['hosts'])} hosts...")
    scan_results = []
    # Limitamos a 3 hosts para que sea más rápido
    for host in state["hosts"][:3]:
        ip = host["ip"]
        result = scan_open_ports(ip)
        if "error" not in result:
            scan_results.append(result)
    state["scan_results"] = scan_results
    state["current_step"] = "scan_hosts"
    return state

def analyze_vulnerabilities(state: NetworkAuditState) -> NetworkAuditState:
    print(f"[LangGraph] Analizando vulnerabilidades...")
    vulnerabilities = []
    weak_configs = []

    for scan in state["scan_results"]:
        ports = scan.get("ports", [])
        host = scan.get("host", "")

        weak = check_weak_config(ports)
        if weak.get("warnings"):
            weak_configs.append({"host": host, "warnings": weak["warnings"]})

        # Solo buscamos CVEs para los primeros 2 puertos por host
        for port in ports[:2]:
            service = port.get("service", "")
            version = port.get("version", "")
            product = port.get("product", "")

            if service and service not in ["tcpwrapped", "unknown"]:
                search_term = product if product else service
                cve_result = search_cves(search_term, version)
                if cve_result.get("total_cves", 0) > 0:
                    vulnerabilities.append({
                        "host": host,
                        "port": port.get("port"),
                        "service": service,
                        "version": version,
                        "total_cves": cve_result["total_cves"],
                        "top_cves": cve_result["cves"][:3]
                    })

    state["vulnerabilities"] = vulnerabilities
    state["weak_configs"] = weak_configs
    state["current_step"] = "analyze_vulnerabilities"
    return state

def check_devices(state: NetworkAuditState) -> NetworkAuditState:
    print(f"[LangGraph] Verificando dispositivos nuevos...")
    result = check_new_devices(state["network"])
    if "error" not in result:
        state["new_devices"] = result.get("new_devices", [])
    else:
        state["new_devices"] = []
        state["errors"].append(f"Error verificando dispositivos: {result['error']}")
    state["current_step"] = "check_devices"
    return state

def generate_report(state: NetworkAuditState) -> NetworkAuditState:
    print(f"[LangGraph] Generando reporte...")
    total_hosts = len(state["hosts"])
    total_vulns = len(state["vulnerabilities"])
    total_weak = sum(len(w["warnings"]) for w in state["weak_configs"])
    total_new = len(state["new_devices"])

    report = f"""
## Reporte de Auditoría de Red — {state['network']}

### Resumen
- **Hosts activos:** {total_hosts}
- **Vulnerabilidades CVE encontradas:** {total_vulns} servicios afectados
- **Configuraciones débiles:** {total_weak}
- **Dispositivos nuevos:** {total_new}

### Hosts descubiertos
"""
    for host in state["hosts"]:
        report += f"- {host['ip']} ({host.get('hostname', 'sin hostname')})\n"

    if state["weak_configs"]:
        report += "\n### ⚠️ Configuraciones débiles\n"
        for wc in state["weak_configs"]:
            report += f"\n**{wc['host']}:**\n"
            for w in wc["warnings"]:
                report += f"- Puerto {w['port']}: {w['warning']} [{w['severity']}]\n"

    if state["vulnerabilities"]:
        report += "\n### 🔴 Vulnerabilidades CVE\n"
        for vuln in state["vulnerabilities"]:
            report += f"\n**{vuln['host']} — Puerto {vuln['port']} ({vuln['service']} {vuln['version']}):** {vuln['total_cves']} CVEs\n"
            for cve in vuln["top_cves"]:
                report += f"- {cve['id']} [{cve.get('severity', 'N/A')}] Score: {cve.get('score', 'N/A')}\n"

    if state["new_devices"]:
        report += "\n### 🆕 Dispositivos nuevos detectados\n"
        for device in state["new_devices"]:
            report += f"- {device['ip']} ({device.get('hostname', 'sin hostname')})\n"

    if state["errors"]:
        report += "\n### Errores durante el análisis\n"
        for error in state["errors"]:
            report += f"- {error}\n"

    state["report"] = report
    state["current_step"] = "generate_report"
    return state

def should_continue(state: NetworkAuditState) -> str:
    if not state["hosts"]:
        return END
    return "scan_hosts"

def build_audit_graph():
    graph = StateGraph(NetworkAuditState)
    graph.add_node("discover_hosts", discover_hosts)
    graph.add_node("scan_hosts", scan_hosts)
    graph.add_node("analyze_vulnerabilities", analyze_vulnerabilities)
    graph.add_node("check_devices", check_devices)
    graph.add_node("generate_report", generate_report)
    graph.set_entry_point("discover_hosts")
    graph.add_conditional_edges("discover_hosts", should_continue)
    graph.add_edge("scan_hosts", "analyze_vulnerabilities")
    graph.add_edge("analyze_vulnerabilities", "check_devices")
    graph.add_edge("check_devices", "generate_report")
    graph.add_edge("generate_report", END)
    return graph.compile()

audit_graph = build_audit_graph()

def run_full_audit(network: str) -> dict:
    initial_state = NetworkAuditState(
        network=network,
        hosts=[],
        scan_results=[],
        vulnerabilities=[],
        weak_configs=[],
        new_devices=[],
        report=None,
        current_step="start",
        errors=[]
    )
    final_state = audit_graph.invoke(initial_state)
    return final_state
