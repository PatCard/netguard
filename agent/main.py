from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from tools.scanner import scan_active_hosts, scan_open_ports
from tools.cve import search_cves, check_weak_config
from tools.monitor import check_new_devices
from tools.report import generate_pdf_report, calculate_security_score
import os
import json
import requests
import io

load_dotenv()

app = Flask(__name__)
CORS(app)

OPENROUTER_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://api.groq.com/openai/v1")
MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_active_hosts",
            "description": "Escanea todos los hosts activos en una red local.",
            "parameters": {
                "type": "object",
                "properties": {
                    "network": {
                        "type": "string",
                        "description": "Red en formato CIDR. Ejemplo: 192.168.1.0/24"
                    }
                },
                "required": ["network"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_open_ports",
            "description": "Escanea los puertos abiertos de un host específico.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "IP del host. Ejemplo: 192.168.1.1"
                    }
                },
                "required": ["host"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_cves",
            "description": "Busca vulnerabilidades CVE conocidas para un servicio y versión.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Nombre del servicio. Ejemplo: nginx, openssh, apache"
                    },
                    "version": {
                        "type": "string",
                        "description": "Versión del servicio. Ejemplo: 1.18.0"
                    }
                },
                "required": ["service"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_weak_config",
            "description": "Detecta configuraciones débiles en los puertos abiertos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ports": {
                        "type": "array",
                        "description": "Lista de puertos abiertos con su información",
                        "items": {
                            "type": "object"
                        }
                    }
                },
                "required": ["ports"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_new_devices",
            "description": "Escanea la red y detecta dispositivos nuevos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "network": {
                        "type": "string",
                        "description": "Red en formato CIDR. Ejemplo: 192.168.1.0/24"
                    }
                },
                "required": ["network"]
            }
        }
    }
]

def run_tool(tool_name: str, tool_input: dict) -> str:
    if tool_name == "scan_active_hosts":
        result = scan_active_hosts(tool_input["network"])
    elif tool_name == "scan_open_ports":
        result = scan_open_ports(tool_input["host"])
    elif tool_name == "search_cves":
        result = search_cves(tool_input["service"], tool_input.get("version", ""))
    elif tool_name == "check_weak_config":
        result = check_weak_config(tool_input["ports"])
    elif tool_name == "check_new_devices":
        result = check_new_devices(tool_input["network"])
    else:
        result = {"error": f"Herramienta {tool_name} no encontrada"}
    return json.dumps(result, ensure_ascii=False)

def call_llm(messages: list) -> dict:
    response = requests.post(
        f"{OPENROUTER_BASE_URL}/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": MODEL,
            "messages": messages,
            "tools": TOOLS,
            "tool_choice": "auto"
        }
    )
    return response.json()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netguard-agent", "model": MODEL})

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "message is required"}), 400

    messages = [
        {
            "role": "system",
            "content": """Eres NetGuard, un agente experto en seguridad de redes.
Tienes acceso a las siguientes herramientas:
- scan_active_hosts: escanea hosts activos en una red
- scan_open_ports: escanea puertos abiertos de un host
- search_cves: busca vulnerabilidades conocidas para un servicio
- check_weak_config: detecta configuraciones débiles en los puertos abiertos
- check_new_devices: detecta dispositivos nuevos en la red

Cuando el usuario pida analizar un host, debes:
1. Escanear sus puertos
2. Verificar configuraciones débiles
3. Buscar CVEs para los servicios encontrados
4. Dar un resumen claro con recomendaciones

Responde siempre en español y de forma clara y concisa."""
        }
    ] + history + [{"role": "user", "content": message}]

    try:
        response = call_llm(messages)

        while response.get("choices", [{}])[0].get("finish_reason") == "tool_calls":
            assistant_message = response["choices"][0]["message"]
            messages.append(assistant_message)

            for tool_call in assistant_message.get("tool_calls", []):
                tool_name = tool_call["function"]["name"]
                tool_input = json.loads(tool_call["function"]["arguments"])
                result = run_tool(tool_name, tool_input)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": result
                })

            response = call_llm(messages)

        final_response = response["choices"][0]["message"]["content"]

        return jsonify({
            "response": final_response,
            "history": messages[1:]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/audit", methods=["POST"])
def audit():
    data = request.get_json()
    network = data.get("network", "")

    if not network:
        return jsonify({"error": "network is required"}), 400

    try:
        from graph import run_full_audit
        result = run_full_audit(network)
        result["network"] = network

        # Calcular scores
        scores = calculate_security_score(
            result.get("vulnerabilities", []),
            result.get("weak_configs", []),
            result.get("hosts", [])
        )
        result["scores"] = scores

        return jsonify({
            "report": result["report"],
            "hosts": result["hosts"],
            "vulnerabilities": result["vulnerabilities"],
            "weak_configs": result["weak_configs"],
            "new_devices": result["new_devices"],
            "errors": result["errors"],
            "scores": scores,
            "network": network
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = request.get_json()

    if not data:
        return jsonify({"error": "audit data is required"}), 400

    try:
        pdf_bytes = generate_pdf_report(data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"netguard-report-{data.get('network','network').replace('/','-')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("AGENT_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
