from urllib.parse import unquote

from core.constants import (
    REDES_INTERNAS,
    RUTAS_LEGITIMAS,
    SCANNER_UA,
    USER_AGENTS_CONOCIDOS,
    VERSIONES_VIEJAS,
)


# ─────────────────────────────────────────────
# FUNCIONES DE CONTEXTO
# ─────────────────────────────────────────────
def es_red_interna(ip):
    return any(ip.startswith(r) for r in REDES_INTERNAS)


def es_ruta_legitima(url):
    path = url.split("?")[0]
    return any(path.startswith(r) for r in RUTAS_LEGITIMAS)


def es_version_vieja(url):
    return any(url.startswith(v) for v in VERSIONES_VIEJAS)


def es_ua_conocido(ua):
    return any(ua.startswith(k) for k in USER_AGENTS_CONOCIDOS)


def es_internal_dummy(req):
    """Internal dummy connection de Apache — completamente ignorar."""
    return "Apache/" in req.get("ua", "")


def es_flujo_sso(req):
    """Redirects 302 parte del flujo SAML/SSO son normales."""
    return req["status"] == 302 and (
        "?acs" in req["url"] or req["url"] in ["/", "/guarani/3.21/"]
    )


def longitud_url_sospechosa(url):
    """URLs muy largas pueden ser intentos de inyección, pero en Guaraní
    hay filtros legítimos que generan URLs largas."""
    url_dec = unquote(url)
    # Umbral: más de 400 caracteres Y no parece un filtro normal de Guaraní
    if len(url_dec) > 400:
        # URLs con parámetros de filtro conocidos del Guaraní son normales
        parametros_guarani = ["filtrado-ce", "cascadas", "tsd=", "ts=", "ai=", "ah="]
        if any(p in url_dec for p in parametros_guarani):
            return False  # largo pero legítimo
        return True
    return False


def detectar_path_traversal(url):
    url_dec = unquote(url).lower()
    patrones = ["../", "..\\", "%2e%2e", "....//"]
    return any(p in url_dec for p in patrones)


def detectar_inyeccion(url):
    url_dec = unquote(url).lower()

    patrones = [
        "select ",
        "union ",
        "insert ",
        "drop ",
        "delete ",  # SQLi
        "<script",
        "javascript:",
        "onerror=",
        "onload=",  # XSS
        "/etc/passwd",
        "/proc/self",
        "cmd=",
        "exec(",  # RCE/LFI
    ]
    return any(p in url_dec for p in patrones)


def detectar_scanner(ua):
    """User-agents típicos de scanners y bots maliciosos."""
    ua = ua.lower()
    return any(s in ua for s in SCANNER_UA)
