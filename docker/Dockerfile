# ─────────────────────────────────────────────────────────────────
# LogGuard Guaraní — Dockerfile
#
# Build:
#   docker build -t logguard-guarani:1.0 .
#
# Run (montando logs desde el host):
#   docker run --rm -v /ruta/a/logs:/data logguard-guarani:1.0 \
#       /data/access.log --solo-anomalos
# ─────────────────────────────────────────────────────────────────

FROM python:3.11-slim

LABEL org.opencontainers.image.title="LogGuard Guaraní"
LABEL org.opencontainers.image.description="Analizador defensivo de logs Apache para SIU Guaraní"
LABEL org.opencontainers.image.version="4.0"
LABEL org.opencontainers.image.authors="Santiago Sánchez"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/snsanchez/logguard-guarani"

# Python
ENV PYTHONPATH="/app:/app/src"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --shell /bin/bash logguard

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY soc_agent/ soc_agent/
COPY knowledge/ knowledge/
COPY examples/ examples/

COPY README.md .
COPY LICENSE .

RUN chown -R logguard:logguard /app

USER logguard

VOLUME ["/data"]

ENTRYPOINT ["python3", "-m", "src.logguard_guarani"]
