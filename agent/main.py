from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from tools.scanner import scan_active_hosts, scan_open_ports
import os
import json
import requests

load_dotenv()

app = Flask(__name__)
CORS(app)

OPENROUTER_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.getenv("LLM_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

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
    }
]

def run_tool(tool_name: str, tool_input: dict) -> str:
    if tool_name == "scan_active_hosts":
        result = scan_active_hosts(tool_input["network"])
    elif tool_name == "scan_open_ports":
        result = scan_open_ports(tool_input["host"])
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
Puedes escanear redes locales, detectar hosts activos y analizar puertos abiertos.
Responde siempre en español y de forma clara y concisa.
Cuando el usuario pida escanear una red o un host, usa las herramientas disponibles."""
        }
    ] + history + [{"role": "user", "content": message}]

    try:
        response = call_llm(messages)

        # Ciclo ReAct: ejecutar herramientas si el modelo las solicita
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
            "history": messages[1:]  # excluimos el system prompt
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("AGENT_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")