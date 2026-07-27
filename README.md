<div align="center">
  <a href="https://snsanchez.github.io/logguard-guarani/" target="_blank">
    <img src="https://github.com/snsanchez/logguard-guarani/blob/main/docs/img/lgg_logo_nobg.png" alt="LogGuard Logo" width="20%" />
  </a>

  <h1>LogGuard Guaraní</h1>

  <p>
    <strong>Analizador defensivo de logs Apache</strong> con detección heurística, Machine Learning,
    Threat Intelligence y un agente SOC.
  </p>

  <p>
    <img alt="License" src="https://img.shields.io/badge/license-GPLv3-blue">
    <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue">
    <img alt="Docker" src="https://img.shields.io/badge/docker-ready-2496ED">
    <img alt="Docs" src="https://img.shields.io/badge/docs-GitHub%20Pages-success">
    <img alt="Status" src="https://img.shields.io/badge/status-proof--of--concept-yellow">
  </p>

  <p>
    📖 <a href="https://snsanchez.github.io/logguard-guarani/"><strong>Documentación completa</strong></a>
    &nbsp;·&nbsp;
    📄 <a href="https://github.com/snsanchez/logguard-guarani/blob/main/docs/paper/LogGuard%20Guarani%20-%20Short%20Paper.pdf">Short paper (PDF)</a>
    &nbsp;·&nbsp;
    🐛 <a href="https://github.com/snsanchez/logguard-guarani/issues">Reportar un problema</a>
  </p>
</div>

---

Analizador defensivo de logs Apache orientado a la detección de anomalías, clasificación de amenazas web y asistencia automática de análisis mediante un agente SOC.

El proyecto fue desarrollado como prueba de concepto para entornos universitarios utilizando logs del ecosistema SIU Guaraní, con un enfoque modular, explicable y offline-first.

## Tabla de contenidos

- [Características principales](#características-principales)
  - [Pipeline de análisis](#pipeline-de-análisis)
  - [Detección y clasificación](#detección-y-clasificación)
  - [Machine Learning](#machine-learning)
  - [Threat Intelligence](#threat-intelligence)
  - [SOC Agent](#soc-agent)
- [Vista previa](#vista-previa)
- [Instalación](#instalación)
- [Uso](#uso)
- [Docker](#docker)
- [Arquitectura futura](#arquitectura-futura)
- [Cómo citar](#cómo-citar)
- [Autores](#autores)
- [Contribuciones](#contribuciones)
- [Seguridad](#seguridad)
- [Licencia](#licencia)

## Características principales

### Pipeline de análisis

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

> Para el detalle completo de cada etapa, modelos de datos y la separación entre el pipeline de detección (determinístico) y el de razonamiento (agente SOC), ver la [documentación de arquitectura](https://snsanchez.github.io/logguard-guarani/#architecture-overview).

### Detección y clasificación

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

### Machine Learning

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

### Threat Intelligence

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

Durante el análisis normal **no se realizan consultas online** — toda la inteligencia se consulta offline contra esta base local.

### SOC Agent

La versión 3 incorpora un agente SOC (implementado con Google ADK) encargado de analizar eventos de alto riesgo.

El agente recibe eventos enriquecidos con:

- evidencia de detección
- nivel de riesgo
- contexto MITRE
- CVEs relacionados
- vulnerabilidades explotadas conocidas

Su objetivo es generar análisis estructurados y recomendaciones — **nunca detecta ataques ni reemplaza las heurísticas**, solo interpreta lo que el pipeline determinístico ya produjo.

## Vista previa

Resumen de eventos agrupado por IP de origen:

<p align="center">
  <img src="docs/img/analisis.png" alt="Resumen de análisis de LogGuard Guaraní agrupado por IP" width="85%">
</p>

Fragmento de un reporte generado por el agente SOC:

<p align="center">
  <img src="docs/img/reporte_SOC.png" alt="Reporte SOC generado por LogGuard Guaraní" width="85%">
</p>

## Instalación

Requisitos:

- Python 3.11+
- Dependencias definidas en `requirements.txt`

Instalación:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Uso

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

> Referencia completa de flags y ejemplos adicionales: [Referencia CLI](https://snsanchez.github.io/logguard-guarani/#cli).

## Docker

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

## Arquitectura futura

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

## Cómo citar

Si utilizás LogGuard Guaraní en un trabajo académico o de investigación, podés citar el short paper asociado al proyecto:

> Sánchez, S. N., García, N., Castro, N. (2026). *LogGuard Guaraní: Plataforma Inteligente para el Análisis Defensivo de Logs Apache mediante un Agente SOC e Inteligencia de Amenazas*. Universidad Nacional de Río Negro — Laboratorio de Informática Aplicada (LIA).

El artículo completo, con metodología, resultados y referencias, está disponible en la [sección Short Paper de la documentación](https://snsanchez.github.io/logguard-guarani/#paper).

## Autores

Desarrollado en el **Laboratorio de Informática Aplicada (LIA)**, Universidad Nacional de Río Negro — Sede Atlántica, Viedma.

- Santiago Nicolás Sánchez
- Nicolás García
- Nicolás Castro

## Contribuciones

¿Encontraste un bug o tenés una idea para mejorar el proyecto? Los [issues](https://github.com/snsanchez/logguard-guarani/issues) y pull requests son bienvenidos. Si vas a proponer un cambio grande, abrí primero un issue para discutirlo.

## Seguridad

Este repositorio no contiene logs reales ni información institucional sensible.

Los datos utilizados durante el desarrollo fueron excluidos del repositorio por motivos de privacidad y seguridad.

## Licencia

Distribuido bajo licencia **GPL v3**. Ver [`LICENSE`](LICENSE) para más información.
