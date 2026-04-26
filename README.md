# 🛡️ LogGuard Guaraní

Analizador de logs Apache orientado a detectar anomalías y posibles ataques en el sistema SIU Guaraní.

## 🚀 Características

- Parseo de logs Apache (access.log)
- Clasificación de requests:
  - NORMAL
  - OBSERVAR
  - SOSPECHOSO
  - ANÓMALO
- Detección de:
  - Inyecciones (SQLi, XSS, RCE)
  - Path traversal (`../`)
  - User-Agents de scanners (sqlmap, curl, etc.)
  - URLs sospechosas (longitud, patrones raros)
- Análisis por IP:
  - múltiples 404 → posible scanning
  - múltiples 403 → enumeración de recursos
- Exportación a CSV

---

## 📦 Requisitos

- Python 3.8+

No requiere dependencias externas.

---

## 🧪 Uso

```bash
python3 logguard_guarani.py <archivo_log>
```

Opciones
```bash
--solo-anomalos     # muestra solo SOSPECHOSO y ANOMALO
--exportar salida.csv
```

Ejemplo
```bash
python3 logguard_guarani.py access.log --solo-anomalos
```

📊 Ejemplo de salida
```bash
✖ ANOMALO   [08:01] 192.168.1.10  404 GET /../../etc/passwd
→ Path traversal detectado
```

---
## ⚠️ Seguridad
Este proyecto NO incluye logs reales por razones de privacidad y seguridad.

🧠 Contexto

Desarrollado como prueba de concepto para análisis de seguridad en logs del sistema SIU Guaraní (UNRN).

📌 Futuro
detección de patrones temporales
correlación de eventos
dashboard o visualización
