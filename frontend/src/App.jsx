import { useState, useEffect, useRef } from "react"
import axios from "axios"
import Markdown from "react-markdown"

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000"

function ScoreCircle({ score, grade }) {
  const color = score >= 75 ? "#22c55e" : score >= 50 ? "#eab308" : "#ef4444"
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{
        width: "80px", height: "80px", borderRadius: "50%",
        border: `6px solid ${color}`, display: "flex",
        flexDirection: "column", alignItems: "center",
        justifyContent: "center", margin: "0 auto"
      }}>
        <span style={{ fontSize: "1.3rem", fontWeight: "bold", color }}>{score}</span>
        <span style={{ fontSize: "0.7rem", color }}>{grade}</span>
      </div>
    </div>
  )
}

function HostCard({ host, weakConfigs, vulnerabilities, scores }) {
  const hasWeak = weakConfigs?.some(w => w.host === host.ip)
  const hasVuln = vulnerabilities?.some(v => v.host === host.ip)
  const hostScore = scores?.host_scores?.find(s => s.ip === host.ip)
  const status = hasVuln ? "critical" : hasWeak ? "warning" : "safe"
  const colors = {
    critical: { bg: "#fee2e2", border: "#ef4444", icon: "🔴" },
    warning:  { bg: "#fef9c3", border: "#eab308", icon: "⚠️" },
    safe:     { bg: "#dcfce7", border: "#22c55e", icon: "✅" }
  }
  const c = colors[status]
  return (
    <div style={{ border: `2px solid ${c.border}`, background: c.bg, borderRadius: "10px", padding: "0.8rem", minWidth: "160px", textAlign: "center" }}>
      <div style={{ fontSize: "1.5rem" }}>{c.icon}</div>
      <div style={{ fontWeight: "bold", fontSize: "0.9rem" }}>{host.ip}</div>
      {host.hostname && <div style={{ fontSize: "0.75rem", color: "#555" }}>{host.hostname}</div>}
      {hostScore && <div style={{ fontSize: "0.8rem", marginTop: "0.3rem", color: c.border }}>Score: {hostScore.score} ({hostScore.grade})</div>}
    </div>
  )
}

function ChatPanel({ history, onSend, loading }) {
  const [input, setInput] = useState("")
  const bottomRef = useRef(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }) }, [history])
  const handleSend = () => {
    if (!input.trim() || loading) return
    onSend(input)
    setInput("")
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ flex: 1, overflowY: "auto", padding: "1rem", background: "#f9f9f9", borderRadius: "8px", marginBottom: "0.5rem" }}>
        {history.length === 0 && <p style={{ color: "#999", textAlign: "center" }}>Ej: "analiza el host 192.168.1.1"</p>}
        {history.map((msg, i) => (
          <div key={i} style={{ marginBottom: "0.8rem", textAlign: msg.role === "user" ? "right" : "left" }}>
            <span style={{
              display: "inline-block", padding: "0.5rem 0.8rem", borderRadius: "10px", maxWidth: "85%",
              background: msg.role === "user" ? "#0070f3" : "#fff",
              color: msg.role === "user" ? "white" : "black",
              border: msg.role === "assistant" ? "1px solid #ddd" : "none",
              textAlign: "left", fontSize: "0.9rem"
            }}>
              {msg.role === "assistant" ? <Markdown>{msg.content}</Markdown> : msg.content}
            </span>
          </div>
        ))}
        {loading && (
          <div style={{ textAlign: "left" }}>
            <span style={{ display: "inline-block", padding: "0.5rem 0.8rem", borderRadius: "10px", background: "#fff", border: "1px solid #ddd" }}>⏳ Analizando...</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <div style={{ display: "flex", gap: "0.5rem" }}>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleSend()}
          placeholder="Escribe tu consulta..." style={{ flex: 1, padding: "0.6rem", borderRadius: "8px", border: "1px solid #ccc" }} />
        <button onClick={handleSend} disabled={loading}
          style={{ padding: "0.6rem 1.2rem", borderRadius: "8px", background: "#0070f3", color: "white", border: "none", cursor: "pointer" }}>
          Enviar
        </button>
      </div>
    </div>
  )
}

export default function App() {
  const [tab, setTab] = useState("dashboard")
  const [network, setNetwork] = useState("192.168.1.0/24")
  const [auditResult, setAuditResult] = useState(null)
  const [auditing, setAuditing] = useState(false)
  const [auditStatus, setAuditStatus] = useState("")
  const [downloading, setDownloading] = useState(false)
  const [chatHistory, setChatHistory] = useState([])
  const [chatLoading, setChatLoading] = useState(false)
  const pollRef = useRef(null)

  useEffect(() => {
    axios.get(`${API_URL}/api/chat/history`).then(res => setChatHistory(res.data)).catch(console.error)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const runAudit = async () => {
    setAuditing(true)
    setAuditResult(null)
    setAuditStatus("Iniciando auditoría...")

    try {
      const res = await axios.post(`${API_URL}/api/audit`, { network })
      const jobId = res.data.job_id

      const steps = [
        "Descubriendo hosts en la red...",
        "Escaneando puertos de cada host...",
        "Analizando vulnerabilidades CVE...",
        "Verificando dispositivos nuevos...",
        "Generando reporte..."
      ]
      let stepIdx = 0

      pollRef.current = setInterval(async () => {
        try {
          stepIdx = Math.min(stepIdx + 1, steps.length - 1)
          setAuditStatus(steps[stepIdx])

          const poll = await axios.get(`${API_URL}/api/audit/${jobId}`)

          if (poll.data.status === "completed") {
            clearInterval(pollRef.current)
            setAuditResult(poll.data.result)
            setAuditing(false)
            setAuditStatus("")
          } else if (poll.data.status === "failed") {
            clearInterval(pollRef.current)
            setAuditing(false)
            setAuditStatus("Error en la auditoría")
          }
        } catch (err) {
          console.error(err)
        }
      }, 8000)

    } catch (err) {
      console.error(err)
      setAuditing(false)
      setAuditStatus("Error al iniciar auditoría")
    }
  }

  const downloadPDF = async () => {
    if (!auditResult) return
    setDownloading(true)
    try {
      const res = await axios.post(`${API_URL}/api/report/pdf`, auditResult, { responseType: "blob" })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement("a")
      a.href = url
      a.download = `netguard-report-${network.replace("/", "-")}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (err) { console.error(err) }
    finally { setDownloading(false) }
  }

  const sendChat = async (message) => {
    setChatHistory(prev => [...prev, { role: "user", content: message }])
    setChatLoading(true)
    try {
      const res = await axios.post(`${API_URL}/api/chat/send`, { message })
      setChatHistory(prev => [...prev, { role: "assistant", content: res.data.response }])
    } catch { setChatHistory(prev => [...prev, { role: "assistant", content: "Error al conectar con el agente." }]) }
    finally { setChatLoading(false) }
  }

  const clearChat = async () => {
    await axios.delete(`${API_URL}/api/chat/clear`)
    setChatHistory([])
  }

  return (
    <div style={{ fontFamily: "sans-serif", height: "100vh", display: "flex", flexDirection: "column" }}>
      <div style={{ background: "#0f172a", color: "white", padding: "0.8rem 1.5rem", display: "flex", alignItems: "center", gap: "1rem" }}>
        <span style={{ fontSize: "1.3rem", fontWeight: "bold" }}>🛡️ NetGuard</span>
        <button onClick={() => setTab("dashboard")} style={{ background: tab === "dashboard" ? "#0070f3" : "transparent", color: "white", border: "1px solid #334", borderRadius: "6px", padding: "0.3rem 0.8rem", cursor: "pointer" }}>Dashboard</button>
        <button onClick={() => setTab("chat")} style={{ background: tab === "chat" ? "#0070f3" : "transparent", color: "white", border: "1px solid #334", borderRadius: "6px", padding: "0.3rem 0.8rem", cursor: "pointer" }}>Chat</button>
      </div>

      <div style={{ flex: 1, overflow: "hidden", padding: "1rem" }}>
        {tab === "dashboard" && (
          <div style={{ height: "100%", display: "flex", flexDirection: "column", gap: "1rem" }}>
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <input value={network} onChange={e => setNetwork(e.target.value)}
                style={{ padding: "0.5rem", borderRadius: "8px", border: "1px solid #ccc", width: "200px" }} />
              <button onClick={runAudit} disabled={auditing}
                style={{ padding: "0.5rem 1.2rem", borderRadius: "8px", background: "#0070f3", color: "white", border: "none", cursor: auditing ? "not-allowed" : "pointer" }}>
                {auditing ? "⏳ Auditando..." : "🔍 Auditar red"}
              </button>
              {auditResult && (
                <button onClick={downloadPDF} disabled={downloading}
                  style={{ padding: "0.5rem 1.2rem", borderRadius: "8px", background: "#22c55e", color: "white", border: "none", cursor: downloading ? "not-allowed" : "pointer" }}>
                  {downloading ? "⏳ Generando..." : "📄 Exportar PDF"}
                </button>
              )}
            </div>

            {auditing && auditStatus && (
              <div style={{ background: "#f0f9ff", border: "1px solid #0070f3", borderRadius: "8px", padding: "1rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span style={{ fontSize: "1.2rem" }}>⏳</span>
                <span style={{ color: "#0070f3" }}>{auditStatus}</span>
              </div>
            )}

            {!auditResult && !auditing && (
              <div style={{ textAlign: "center", color: "#999", marginTop: "3rem" }}>
                <p style={{ fontSize: "3rem" }}>🛡️</p>
                <p>Ingresa una red y presiona "Auditar red" para comenzar</p>
              </div>
            )}

            {auditResult && (
              <div style={{ flex: 1, overflowY: "auto" }}>
                <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem", flexWrap: "wrap", alignItems: "center" }}>
                  {auditResult.scores && (
                    <div style={{ background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "10px", padding: "0.8rem 1.2rem", textAlign: "center" }}>
                      <div style={{ fontSize: "0.8rem", color: "#666", marginBottom: "0.3rem" }}>Score Global</div>
                      <ScoreCircle score={auditResult.scores.global_score} grade={auditResult.scores.global_grade} />
                    </div>
                  )}
                  {[
                    { label: "Hosts activos", value: auditResult.hosts?.length, color: "#0070f3" },
                    { label: "Vulnerabilidades", value: auditResult.vulnerabilities?.length, color: "#ef4444" },
                    { label: "Config. débiles", value: auditResult.weak_configs?.reduce((a, w) => a + w.warnings.length, 0), color: "#eab308" },
                    { label: "Dispositivos nuevos", value: auditResult.new_devices?.length, color: "#22c55e" }
                  ].map((card, i) => (
                    <div key={i} style={{ background: card.color, color: "white", borderRadius: "10px", padding: "0.8rem 1.2rem", minWidth: "130px", textAlign: "center" }}>
                      <div style={{ fontSize: "1.8rem", fontWeight: "bold" }}>{card.value}</div>
                      <div style={{ fontSize: "0.8rem" }}>{card.label}</div>
                    </div>
                  ))}
                </div>

                <h3 style={{ margin: "0 0 0.5rem" }}>Mapa de red</h3>
                <div style={{ display: "flex", gap: "0.8rem", flexWrap: "wrap", marginBottom: "1rem" }}>
                  {auditResult.hosts?.map((host, i) => (
                    <HostCard key={i} host={host} weakConfigs={auditResult.weak_configs}
                      vulnerabilities={auditResult.vulnerabilities} scores={auditResult.scores} />
                  ))}
                </div>

                <h3 style={{ margin: "0 0 0.5rem" }}>Reporte</h3>
                <div style={{ background: "#f9f9f9", border: "1px solid #ddd", borderRadius: "8px", padding: "1rem" }}>
                  <Markdown>{auditResult.report}</Markdown>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === "chat" && (
          <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "0.5rem" }}>
              <button onClick={clearChat} style={{ padding: "0.3rem 0.8rem", cursor: "pointer", borderRadius: "6px", border: "1px solid #ccc" }}>Limpiar historial</button>
            </div>
            <div style={{ flex: 1, overflow: "hidden" }}>
              <ChatPanel history={chatHistory} onSend={sendChat} loading={chatLoading} />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
