# netguard

Agente conversacional web que monitorea una red local, detecta anomalías y analiza vulnerabilidades, todo consultable en lenguaje natural.

## Stack

| Capa | Tecnología |
|------|-----------|
| Frontend | React + Tailwind |
| Backend | Laravel (API REST) |
| Agente IA | Anthropic SDK + Python |
| Escaneo de red | Nmap + Scapy (Python) |
| Base de datos | MySQL |
| Contenedores | Docker Compose |
| MCP (Fase 4) | MCP Server con herramientas de red |

## Fases

- [x] **Fase 1** — Tool Use básico (chat + escaneo de red + historial)
- [ ] **Fase 2** — Patrones ReAct (CVEs + detección de configuraciones débiles)
- [ ] **Fase 3** — LangGraph (flujo autónomo + dashboard visual)
- [ ] **Fase 4** — MCP (MCP Server + integración Claude Desktop)
- [ ] **Fase 5** — Integrador (reporte PDF + score de seguridad)