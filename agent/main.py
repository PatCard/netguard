from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netguard-agent"})

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")

    if not message:
        return jsonify({"error": "message is required"}), 400

    # Por ahora retorna eco — en el siguiente paso conectamos el agente IA
    return jsonify({"response": f"Agente recibió: {message}"})

if __name__ == "__main__":
    port = int(os.getenv("AGENT_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") == "development")