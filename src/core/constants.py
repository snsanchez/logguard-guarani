# ─────────────────────────────────────────────
# CONOCIMIENTO DEL DOMINIO: SIU GUARANÍ
# ─────────────────────────────────────────────

# Prefijos de rutas conocidas y legítimas del SIU Guaraní
RUTAS_LEGITIMAS = [
    "/guarani/3.21/aplicacion.php",
    "/guarani/3.21/rest/v2/",
    "/guarani/3.21/css/",
    "/guarani/3.21/js/",
    "/guarani/3.21/skins/",
    "/guarani/3.21/jquery",
    "/guarani/3.21/?acs",  # SSO SAML assertion consumer
    "/guarani/3.21/",
    "/guarani_pers/3.21/css/",
    "/toba_3.3/",  # Framework TOBA
    "/favicon.ico",  # Automático del browser — siempre ignorar
]

# Versiones antiguas del SIU (ya no deberían usarse)
VERSIONES_VIEJAS = [
    "/guarani/3.17/",
    "/guarani/3.18/",
    "/guarani/3.19/",
    "/guarani/3.20/",
]

# User-Agents conocidos y legítimos en este entorno
USER_AGENTS_CONOCIDOS = [
    "Mozilla/5.0",  # Browsers normales
    "Java/",  # Servicio interno (SPA, integraciones)
    "Apache/",  # Internal dummy connection de Apache
    "GuzzleHttp/",  # Cliente HTTP PHP (integraciones internas)
]

# IPs internas de la red UNRN (ajustar según la realidad)
REDES_INTERNAS = [
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "::1",
    "127.",
]

SCANNER_UA = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "burpsuite",
    "python-requests",
    "curl/",
    "wget/",
    "go-http-client",
    "libwww-perl",
]
