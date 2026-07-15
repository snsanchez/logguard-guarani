<div align="center">
  <a href="https://snsanchez.github.io/logguard-guarani/" target="_blank">
    <img src="https://github.com/snsanchez/logguard-guarani/blob/main/docs/img/lgg_logo_nobg.png" alt="LogGuard Logo" width="20%" />
  </a>

  <h1>LogGuard Guaraní</h1>
</div>

Analizador defensivo de logs Apache orientado a la detección de anomalías, clasificación de amenazas web y asistencia automática de análisis mediante un agente SOC.

El proyecto fue desarrollado como prueba de concepto para entornos universitarios utilizando logs del ecosistema SIU Guaraní, con un enfoque modular, explicable y offline-first.

# Características principales

## Pipeline de análisis

LogGuard implementa un pipeline completo:

```
Apache Logs
    |
Parser
    |
Analysis Event
    |
Heuristics + Scoring
    |
Attack Classification
    |
Machine Learning
    |
Risk Mapping
    |
Threat Intelligence Enrichment
    |
SOC Agent
    |
Report
```

## Detección y clasificación

El motor analiza:

- URLs y parámetros HTTP
- User-Agent
- códigos de respuesta HTTP
- patrones de ataque conocidos
- comportamiento anómalo por IP

Tipos de amenazas:

- SQL Injection
- Path Traversal
- Scanner / Reconocimiento
- Error Abuse
- Actividad desconocida

# Machine Learning

LogGuard incorpora un modelo SVM para clasificación complementaria.

El modelo utiliza características extraídas del evento:

- score de riesgo
- status HTTP
- tamaño de respuesta
- longitud de URL
- método HTTP

El modelo retorna:

- predicción
- nivel de confianza

El ML no reemplaza las reglas de detección, sino que aporta una señal adicional explicable.

# Threat Intelligence

Los eventos son enriquecidos utilizando una base de conocimiento local:

- MITRE ATT&CK
- NVD CVE Database
- CISA Known Exploited Vulnerabilities (KEV)

La base puede actualizarse mediante:

```bash
python3 src/logguard_guarani.py \
--actualizar-conocimiento \
--online
```

# SOC Agent

La versión 3 incorpora un agente SOC encargado de analizar eventos de alto riesgo.

El agente recibe eventos enriquecidos con:

- evidencia de detección
- nivel de riesgo
- contexto MITRE
- CVEs relacionados
- vulnerabilidades explotadas conocidas

Su objetivo es generar análisis estructurados y recomendaciones.

# Instalación

Requisitos:

- Python 3.11+
- Dependencias definidas en requirements.txt

Instalación:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

# Uso

Análisis básico:

```bash
python3 src/logguard_guarani.py access.log
```

Mostrar solamente eventos relevantes:

```bash
python3 src/logguard_guarani.py access.log --solo-anomalos
```

Ejecutar clasificación ML:

```bash
python3 src/logguard_guarani.py access.log --razonar
```

Exportar eventos enriquecidos:

```bash
python3 src/logguard_guarani.py access.log \
--razonar \
--exportar-json outputs/eventos.jsonl
```

# Docker

Construcción:

```bash
docker build \
-t san2s/logguard-guarani:3.0.0 \
-f docker/Dockerfile .
```

Ejecución:

```bash
docker run --rm \
-v /ruta/logs:/data \
san2s/logguard-guarani:3.0.0 \
/data/access.log --solo-anomalos
```

# Arquitectura futura

LogGuard forma parte de una arquitectura mayor:

```
Collectors
    |
LogGuard Core
    |
Correlation Engine
    |
SOC Agent
    |
Dashboard / TUI
```

El objetivo futuro es integrar múltiples fuentes:

- Apache logs
- logs de sistema
- infraestructura de red
- servicios institucionales

# Seguridad

Este repositorio no contiene logs reales ni información institucional sensible.

Los datos utilizados durante el desarrollo fueron excluidos del repositorio por motivos de privacidad y seguridad.
