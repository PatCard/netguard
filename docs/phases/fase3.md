# Fase 3 — LangGraph

## Funcionalidades completadas

- Flujo autónomo de auditoría completa de red
- Dashboard visual con mapa de hosts
- Tarjetas de estado por host (seguro/warning/crítico)
- Reporte markdown renderizado
- Resumen ejecutivo con métricas

## Flujo LangGraph

discover_hosts -> scan_hosts -> analyze_vulnerabilities -> check_devices -> generate_report

## Componentes

| Componente | Descripción |
|------------|-------------|
| graph.py | Flujo LangGraph de auditoría |
| /audit endpoint | API REST que ejecuta el flujo |
| Dashboard React | Visualización del reporte |
