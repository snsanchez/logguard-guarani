> Sample SOC report generated from `examples/apache_demo.log`.

# CRITICAL Risk Event (GET /../../../../etc/passwd)

## Analysis Metadata

- Severity: **CRITICAL**
- Confidence: **LOW**
- Generated at: `2026-07-29T02:54:15.308075+00:00`

## Executive Summary

Se detectó un intento de inyección de ruta (Path Traversal) dirigido a /../../../../etc/passwd. Aunque el servidor respondió con un error 404, la naturaleza del intento de acceso a un archivo sensible del sistema es altamente sospechosa y se correlaciona con vulnerabilidades conocidas de inyección de comandos.

## Event Overview

Un cliente con la dirección IP 198.51.100.99 realizó una solicitud HTTP GET al servidor. La solicitud apuntaba a la ruta /../../../../etc/passwd, un patrón comúnmente utilizado en ataques de Path Traversal para intentar acceder al archivo de contraseñas del sistema operativo. El servidor respondió con un código de estado 404 (No Encontrado), lo que indica que el archivo solicitado no estaba disponible en esa ubicación o el servidor está configurado para no revelar dicha información. Sin embargo, la heurística de 'Patrón de inyección detectado en URL' se activó, señalando la naturaleza maliciosa del intento.

## Evidence

### Intento de Inyección de Ruta (Path Traversal)

La solicitud HTTP GET contenía la ruta '/../../../../etc/passwd', un patrón típico para intentar acceder a archivos sensibles del sistema operativo.

- Source: `HTTP Request Log`
- Severity: `HIGH`

### Respuesta del Servidor

El servidor respondió con un código de estado 404 (Not Found), lo que indica que el recurso solicitado no se encontró.

- Source: `HTTP Response Log`
- Severity: `LOW`

### Heurística de Detección

Se activó la heurística 'Patrón de inyección detectado en URL', indicando que la URL de la solicitud coincide con patrones conocidos de inyección.

- Source: `LogGuard Heuristics`
- Severity: `HIGH`

### Nivel de Riesgo

El evento fue clasificado con un nivel de riesgo 'CRITICAL' y una puntuación de 100.0.

- Source: `LogGuard Risk Analysis`
- Severity: `CRITICAL`

## Recommendations

### Aplicar actualizaciones de seguridad

Actualizar versiones de software vulnerables asociadas con CVE detectados.

- Priority: `HIGH`
- Category: `Patching`

### Preservar evidencia

Conserve logs relevantes para futuros análisis forenses.

- Priority: `HIGH`
- Category: `Forensics`

## Analyst Notes

No additional notes.
