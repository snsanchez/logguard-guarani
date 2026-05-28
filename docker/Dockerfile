# ─────────────────────────────────────────────────────────────────
# LogGuard Guaraní — Dockerfile
# Imagen mínima: solo Python stdlib, sin dependencias externas.
#
# Build:
#   docker build -t logguard-guarani:1.0 .
#
# Run (montando logs desde el host):
#   docker run --rm -v /ruta/a/logs:/data logguard-guarani:1.0 \
#       /data/access.log --solo-anomalos
# ─────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# ─────────────────────────────────────────────
# Metadata OCI
# ─────────────────────────────────────────────
LABEL org.opencontainers.image.title="LogGuard Guaraní"
LABEL org.opencontainers.image.description="Analizador defensivo de logs Apache para SIU Guaraní"
LABEL org.opencontainers.image.version="1.0"
LABEL org.opencontainers.image.authors="Santiago Sánchez"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/snsanchez/logguard-guarani"

# ─────────────────────────────────────────────
# Usuario no-root por seguridad
# ─────────────────────────────────────────────
RUN useradd --create-home --shell /bin/bash logguard

# ─────────────────────────────────────────────
# Directorio de trabajo
# ─────────────────────────────────────────────
WORKDIR /app

# ─────────────────────────────────────────────
# Copiar source
# ─────────────────────────────────────────────
COPY src/logguard_guarani.py .

# Ownership correcta
RUN chown -R logguard:logguard /app

# Ejecutar como usuario restringido
USER logguard

# Punto de montaje esperado para logs
VOLUME ["/data"]

# Entrypoint principal
ENTRYPOINT ["python3", "/app/logguard_guarani.py"]
