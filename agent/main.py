
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from anthropic import Anthropic
from tools.scanner import scan_active_hosts, scan_open_ports
import os
import json

load_dotenv()

app = Flask(__name__)
CORS(app)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Definición de herramientas para el agente
TOOLS = [
    {
        "name": "scan_active_hosts",
        "description": "Escanea todos los hosts activos en una red local. Úsalo cuando el usuario quiera saber qué dispositivos hay en la red.",
        "input_schema": {
            "type": "object",
            "properties": {
                "network": {
                    "type": "string",
                    "description": "Red a escanear en formato CIDR. Ejemplo: 192.168.1.0/24"
                }
            },
            "required": ["network"]
        }
    },
    {
        "name": "scan_open_ports",
        "description": "Escanea los puertos abiertos de un host específico. Úsalo cuando el usuario quiera saber qué puertos o servicios tiene abiertos un dispositivo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "IP del host a escanear. Ejemplo: 192.168.1.1"
                }
            },
            "required": ["host"]
        }
    }
]

def run_tool(tool_name: str, tool_input: dict) -> str:
    """Ejecuta la herramienta correspondiente y retorna el resultado como string."""
    if tool_name == "scan_active_hosts":
        result = scan_active_hosts(tool_input["network"])
    elif tool_name == "scan_open_ports":
        result = scan_open_ports(tool_input["host"])
    else:
        result = {"error": f"Herramienta {tool_name} no encontrada"}

    return json.dumps(result, ensure_ascii=False)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netguard-agent"})

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "message is required"}), 400

    # Construimos el historial de mensajes
    messages = history + [{"role": "user", "content": message}]

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system="""Eres NetGuard, un agente experto en seguridad de redes. 
Puedes escanear redes locales, detectar hosts activos y analizar puertos abiertos.
Responde siempre en español y de forma clara y concisa.
Cuando el usuario pida escanear una red o un host, usa las herramientas disponibles.""",
            tools=TOOLS,
            messages=messages
        )

        # Ciclo ReAct: el agente puede usar herramientas
        while response.stop_reason == "tool_use":
            tool_uses = [block for block in response.content if block.type == "tool_use"]
            
            # Agregamos la respuesta del agente al historial
            messages.append({"role": "assistant", "content": response.content})

            # Ejecutamos cada herramienta y agregamos resultados
            tool_results = []
            for tool_use in tool_uses:
                result = run_tool(tool_use.name, tool_use.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": result
                })

            messages.append({"role": "user", "content": tool_results})

            # Nueva llamada al agente con los resultados
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system="""Eres NetGuard, un agente experto en seguridad de redes.
Puedes escanear redes locales, detectar hosts activos y analizar puertos abiertos.
Responde siempre en español y de forma clara y concisa.""",
                tools=TOOLS,
                messages=messages
            )

        # Extraemos el texto final
        final_response = next(
            (block.text for block in response.content if hasattr(block, "text")), ""
        )

        return jsonify({
            "response": final_response,
            "history": messages
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("AGENT_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")
