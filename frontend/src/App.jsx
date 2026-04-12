import { useState, useEffect, useRef } from "react"
import axios from "axios"

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000"

export default function App() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    axios.get(`${API_URL}/api/chat/history`)
      .then(res => setMessages(res.data))
      .catch(console.error)
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  const sendMessage = async () => {
    if (!input.trim() || loading) return

    const userMsg = { role: "user", content: input }
    setMessages(prev => [...prev, userMsg])
    setInput("")
    setLoading(true)

    try {
      const res = await axios.post(`${API_URL}/api/chat/send`, { message: input })
      setMessages(prev => [...prev, { role: "assistant", content: res.data.response }])
    } catch (err) {
      setMessages(prev => [...prev, { role: "assistant", content: "Error al conectar con el agente." }])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const clearHistory = async () => {
    await axios.delete(`${API_URL}/api/chat/clear`)
    setMessages([])
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", maxWidth: "800px", margin: "0 auto", padding: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h1 style={{ margin: 0, fontSize: "1.5rem" }}>🛡️ NetGuard</h1>
        <button onClick={clearHistory} style={{ padding: "0.4rem 0.8rem", cursor: "pointer" }}>
          Limpiar historial
        </button>
      </div>

      <div style={{ flex: 1, overflowY: "auto", border: "1px solid #ccc", borderRadius: "8px", padding: "1rem", marginBottom: "1rem" }}>
        {messages.length === 0 && (
          <p style={{ color: "#999", textAlign: "center" }}>Pregúntame sobre tu red. Ej: "escanea la red 192.168.1.0/24"</p>
        )}
        {messages.map((msg, i) => (
          <div key={i} style={{
            marginBottom: "1rem",
            textAlign: msg.role === "user" ? "right" : "left"
          }}>
            <span style={{
              display: "inline-block",
              padding: "0.6rem 1rem",
              borderRadius: "12px",
              maxWidth: "80%",
              background: msg.role === "user" ? "#0070f3" : "#f0f0f0",
              color: msg.role === "user" ? "white" : "black",
              whiteSpace: "pre-wrap"
            }}>
              {msg.content}
            </span>
          </div>
        ))}
        {loading && (
          <div style={{ textAlign: "left" }}>
            <span style={{ display: "inline-block", padding: "0.6rem 1rem", borderRadius: "12px", background: "#f0f0f0" }}>
              ⏳ Analizando...
            </span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div style={{ display: "flex", gap: "0.5rem" }}>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Escribe tu consulta... (Enter para enviar)"
          rows={2}
          style={{ flex: 1, padding: "0.6rem", borderRadius: "8px", border: "1px solid #ccc", resize: "none" }}
        />
        <button
          onClick={sendMessage}
          disabled={loading}
          style={{ padding: "0 1.5rem", borderRadius: "8px", background: "#0070f3", color: "white", border: "none", cursor: loading ? "not-allowed" : "pointer" }}
        >
          Enviar
        </button>
      </div>
    </div>
  )
}
