# Fase 4 — MCP Server

## Funcionalidades completadas

- MCP Server con herramientas de red expuestas
- Compatible con Claude Desktop (Windows/Mac)
- Mismo código del agente reutilizado

## Herramientas expuestas

| Herramienta | Descripción |
|-------------|-------------|
| scan_network | Escanea hosts activos en una red |
| scan_ports | Escanea puertos de un host |
| find_cves | Busca CVEs por servicio/versión |
| analyze_weak_config | Detecta configuraciones débiles |
| monitor_network | Detecta dispositivos nuevos |

## Cómo conectar a Claude Desktop

Agregar en la configuración de Claude Desktop:

```json
{
  "mcpServers": {
    "netguard": {
      "command": "docker",
      "args": ["exec", "-i", "netguard_mcp", "python", "mcp_server.py"]
    }
  }
}
```
