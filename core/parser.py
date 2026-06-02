import re
from urllib.parse import unquote

# ─────────────────────────────────────────────
# REGEX PARA PARSEAR EL LOG
# Formato: IP - usuario [fecha] "METODO URL PROTO" status bytes "referer" "UA"
# ─────────────────────────────────────────────
LOG_REGEX = re.compile(
    r"(?P<ip>\S+)\s+"  # IP
    r"\S+\s+"  # ident (siempre -)
    r"(?P<usuario>\S+)\s+"  # usuario autenticado o -
    r"\[(?P<fecha>[^\]]+)\]\s+"  # [fecha]
    r'"(?P<request>[^"]+)"\s+'  # "METODO URL PROTO"
    r"(?P<status>\d{3})\s+"  # código de status
    r"(?P<bytes>\S+)\s+"  # bytes
    r'"(?P<referer>[^"]*)"\s+'  # "referer"
    r'"(?P<ua>[^"]*)"'  # "user-agent"
)


# ─────────────────────────────────────────────
# PARSER DE UNA LÍNEA
# ─────────────────────────────────────────────
def parsear_linea(linea):
    m = LOG_REGEX.match(linea.strip())

    if not m:
        return None

    request = m.group("request")
    partes = request.split(" ")

    metodo = partes[0] if len(partes) >= 1 else ""
    url = partes[1] if len(partes) >= 2 else ""
    proto = partes[2] if len(partes) >= 3 else ""

    bytes_raw = m.group("bytes")
    bytes_val = int(bytes_raw) if bytes_raw.isdigit() else 0

    return {
        "ip": m.group("ip"),
        "usuario": m.group("usuario"),
        "fecha": m.group("fecha"),
        "metodo": metodo,
        "url": url,
        "url_dec": unquote(url),  # URL decodificada para análisis
        "proto": proto,
        "status": int(m.group("status")),
        "bytes": bytes_val,
        "referer": m.group("referer"),
        "ua": m.group("ua"),
        "linea": linea.strip(),
    }
