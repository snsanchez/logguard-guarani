<div align="center">
  <a href="https://snsanchez.github.io/logguard-guarani/" target="_blank">
    <img src="https://github.com/snsanchez/logguard-guarani/blob/main/docs/img/lgg_logo_nobg.png" alt="Logguard Logo" width="20%" />
  </a>
  <h1>LogGuard Guaraní</h1>
  <br>
</div>

Analizador de logs Apache orientado a la detección de anomalías, actividad sospechosa y posibles ataques sobre implementaciones del sistema SIU Guaraní.

Desarrollado como prueba de concepto para el análisis contextual de logs HTTP en entornos universitarios, utilizando un enfoque rule-based sin dependencias externas.

## Características

- Parseo de logs Apache (Combined Log Format)
- Clasificación contextual de requests:
    - `NORMAL`
    - `OBSERVAR`
    - `SOSPECHOSO`
    - `ANOMALO`
- Detección de amenazas web comunes:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Remote Code Execution / Local File Inclusion (RCE/LFI)
    - Path Traversal (../, %2e%2e)
    - Escaneo automatizado de rutas
    - Reconocimiento de recursos
    - Requests a webshells conocidas
    - User-Agents asociados a scanners y herramientas ofensivas
- Análisis contextual multi-señal:
    - URL y parámetros
    - User-Agent
    - Código HTTP
    - IP de origen
    - Frecuencia de errores por IP
- Reducción de falsos positivos mediante conocimiento del dominio:
    - Flujos SSO/SAML
    - Bots legítimos
    - Rutas propias del SIU Guaraní
    - Servicios internos
    - Requests automáticos del navegador
- Sistema de score de riesgo por request
- Clasificación automática del tipo de ataque detectado
- Rankings Top IPs:
    - mayor volumen de requests
    - mayor cantidad de anomalías
    - mayor cantidad de errores HTTP
- Exportación de resultados a CSV
- Salida visual en consola con colores y categorías

---
## Metodología
LogGuard Guaraní implementa un enfoque rule-based con análisis contextual.

A diferencia de herramientas genéricas de análisis de logs, el sistema incorpora conocimiento específico del ecosistema SIU Guaraní y del comportamiento normal esperado en servidores Apache universitarios. Esto permite reducir significativamente el ruido y mejorar la precisión de las detecciones.

El motor de análisis evalúa señales provenientes de:
- rutas HTTP
- parámetros sospechosos
- patrones de ataque conocidos
- comportamiento por IP
- códigos de estado HTTP
- herramientas automatizadas de scanning

---

## Requisitos

- Python 3.8+
No requiere dependencias externas.

---

## Uso

Ejecución básica:
```bash
python3 logguard_guarani.py access.log
```

Mostrar únicamente los registros sospechosos y anómalos:

```bash
python3 logguard_guarani.py access.log --solo-anomalos
```

Exportar resultados a un archivo CSV:

```bash
python3 logguard_guarani.py access.log --exportar salida.csv
```

📊 Ejemplo de salida
```bash
✖ ANOMALO   [11:32] 119.8.159.33  201 [80] SCANNER
POST /guarani/3.21/rest/v2/cobros-unrn/bloqueo

→ User-Agent asociado a herramienta automatizada
→ Frecuencia anómala de requests
```
---
## Tipos de ataques
- `INJECTION`
- `PATH_TRAVERSAL`
- `SCANNER`
- `ERROR_ABUSE`
- `DESCONOCIDO`

---
## Funciones implementadas
Etapa 1 — Completada
- Score de riesgo
- Clasificación de tipo de ataque
- Top IPs
- Exportación CSV
- Análisis contextual avanzado
- Reducción de falsos positivos

---
## Trabajo Futuro
Etapa 2
- Correlación temporal
- Memoria por IP
- Detección de bursts
- Secuencias sospechosas

Etapa 3
- Baseline de comportamiento
- Correlación de señales
- Detección de ataques low-and-slow

Etapa 4
- Dashboard de visualización
- Pipeline modular
- Timeline de eventos
- Integración con arquitectura centralizada basada en rsyslog
---
## ⚠️ Seguridad
Este repositorio no incluye logs reales ni información sensible.

Los datos utilizados durante el desarrollo fueron anonimizados y excluidos del repositorio por motivos de privacidad y seguridad institucional.

---
Referencias
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP SQL Injection](https://owasp.org/www-project-sql-injection/)
- [Apache HTTP Server Log Files](https://httpd.apache.org/docs/current/logs.html)
- [rsyslog Documentation](https://www.rsyslog.com/doc/)
- [SIU Guaraní](https://www.siugaraní.unrn.edu.ar/)

---
## Arquitectura futura
El proyecto forma parte de una arquitectura más amplia denominada LogGuard Ecosystem, orientada a la centralización y análisis de eventos de seguridad provenientes de múltiples fuentes:
- Apache access logs
- logs de sistema (journal)
- infraestructura de red
- servicios institucionales

La arquitectura futura contempla integración con:
- rsyslog
- modelos de clasificación
- correlación de eventos
- automatización de respuestas de seguridad

---
## Docker

Construir imagen:

```bash
docker build -t san2s/logguard-guarani:1.0 -f docker/Dockerfile .
```

Ejecutar:

```bash
docker run --rm \
  -v /ruta/logs:/data \
  san2s/logguard-guarani:1.0 \
  /data/access.log --solo-anomalos
```

Imagen oficial:
docker pull san2s/logguard-guarani:1.0

