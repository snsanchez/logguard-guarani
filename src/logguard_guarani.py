#!/usr/bin/env python3
"""
23/04/26
LogGuard Guaraní — Analizador de logs Apache para SIU Guaraní (UNRN)
Analiza los request a la API del SIU para detectar anomalias.

Uso:
    python3 logguard_guarani.py <archivo_de_log>
    python3 logguard_guarani.py <archivo_de_log> --solo-anomalos
    python3 logguard_guarani.py <archivo_de_log> --exportar reporte.csv

    Ejemplo: python3 logguard_guarani.py Log\ Reales\ UNRN/logs_apache_2026-04-19/gestiong3.unrn.edu.ar-access.log.1
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote


# ─────────────────────────────────────────────
# COLORES PARA CONSOLA
# ─────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    GREY = "\033[90m"
    WHITE = "\033[97m"


def colorear(texto, color):
    return f"{color}{texto}{C.RESET}"


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

# Patrón de internal dummy connection de Apache — siempre ignorar
APACHE_INTERNAL_UA = "Apache/"

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
    url_dec = unquote(url)
    patrones = ["../", "..\\", "%2e%2e", "....//"]
    return any(p in url_dec.lower() for p in patrones)


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
    ua_lower = ua.lower()
    scanners = [
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
    return any(s in ua_lower for s in scanners)


# ─────────────────────────────────────────────
# MOTOR DE ANÁLISIS PRINCIPAL
# ─────────────────────────────────────────────
def analizar_request(req, contexto_ip):
    """
    Retorna (etiqueta, razones[]) donde etiqueta es:
      IGNORAR    — ruido interno, no mostrar
      NORMAL     — request esperado
      OBSERVAR   — algo a tener en cuenta, no crítico
      SOSPECHOSO — requiere revisión
      ANOMALO    — alerta alta prioridad
    """
    razones = []

    # ── IGNORAR ─────────────────────────────────────────
    if es_internal_dummy(req):
        return "IGNORAR", ["Internal dummy connection de Apache"]

    if req["url"] == "/favicon.ico":
        return "IGNORAR", ["favicon.ico — automático del browser"]

    # 200 con ruta legítima = normal directo
    if req["status"] == 200 and es_ruta_legitima(req["url"]):
        return "NORMAL", ["200 en ruta conocida del SIU Guaraní"]

    # SSO/SAML redirects normales
    if es_flujo_sso(req):
        return "NORMAL", ["302 parte del flujo SSO/SAML normal"]

    # 304 Not Modified = caché, normal
    if req["status"] == 304:
        return "NORMAL", ["304 Not Modified — caché del browser"]

    # ── ANÁLISIS DE AMENAZAS (mayor prioridad primero) ──
    if detectar_inyeccion(req["url"]):
        razones.append("⚠️  Patrón de inyección detectado en URL (SQLi/XSS/RCE)")
        return "ANOMALO", razones

    if detectar_path_traversal(req["url"]):
        razones.append("⚠️  Path traversal detectado (../ o equivalente)")
        return "ANOMALO", razones

    if detectar_scanner(req["ua"]):
        razones.append(
            f"⚠️  User-Agent de scanner/herramienta de ataque: {req['ua'][:60]}"
        )
        return "ANOMALO", razones

    # ── ANÁLISIS DE STATUS ───────────────────────────────
    if req["status"] == 403:
        # 403 desde servicio interno conocido son normales (ej: integración SPA)
        if es_red_interna(req["ip"]) and req["usuario"] != "-":
            razones.append(
                f"403 desde servicio interno (IP: {req['ip']}, usuario: {req['usuario']})"
            )
            return "OBSERVAR", razones
        else:
            razones.append(f"403 Forbidden desde IP externa: {req['ip']}")
            return "SOSPECHOSO", razones

    if req["status"] == 404:
        if es_version_vieja(req["url"]):
            razones.append(
                f"404 en versión antigua del Guaraní ({req['url'][:50]}...) — sesión vieja o bookmark"
            )
            return "OBSERVAR", razones
        if req["url"] in ["/guarani/", "/guarani", "/"]:
            razones.append("404 en raíz — usuario navegando sin sesión")
            return "OBSERVAR", razones
        if longitud_url_sospechosa(req["url"]):
            razones.append(
                f"404 en URL sospechosamente larga ({len(req['url'])} chars)"
            )
            return "SOSPECHOSO", razones
        # 404 genérico
        razones.append(f"404 en ruta desconocida: {req['url'][:80]}")
        return "OBSERVAR", razones

    if req["status"] >= 500:
        razones.append(f"Error de servidor {req['status']} — posible bug o ataque")
        return "SOSPECHOSO", razones

    # ── CHECKS ADICIONALES ───────────────────────────────
    if not es_ua_conocido(req["ua"]) and req["ua"] != "-":
        razones.append(f"User-Agent desconocido: {req['ua'][:80]}")
        return "SOSPECHOSO", razones

    if longitud_url_sospechosa(req["url"]):
        razones.append(
            f"URL inusualmente larga ({len(req['url'])} chars) sin parámetros conocidos"
        )
        return "SOSPECHOSO", razones

    # 200 en ruta no catalogada
    if req["status"] == 200:
        razones.append(f"200 en ruta no catalogada: {req['url'][:80]}")
        return "OBSERVAR", razones

    # Resto
    razones.append(f"Status {req['status']} en {req['url'][:60]}")
    return "OBSERVAR", razones


# ─────────────────────────────────────────────
# DETECCIÓN DE PATRONES POR IP (post-proceso)
# ─────────────────────────────────────────────
def analizar_patrones_ip(registros):
    """
    Detecta comportamiento anómalo a nivel de IP:
    - Muchos 404 seguidos (reconocimiento/scanning)
    - Muchos 403 seguidos (fuerza bruta de paths)
    """
    alertas_ip = defaultdict(list)
    errores_por_ip = defaultdict(list)

    for r in registros:
        if r["status"] in [403, 404]:
            errores_por_ip[r["ip"]].append(r)

    for ip, reqs in errores_por_ip.items():
        if es_internal_dummy(reqs[0]):
            continue
        count_404 = sum(1 for r in reqs if r["status"] == 404)
        count_403 = sum(1 for r in reqs if r["status"] == 403)

        if count_404 >= 5:
            alertas_ip[ip].append(
                f"🔍 {count_404} errores 404 desde esta IP — posible reconocimiento/scanning"
            )
        if count_403 >= 3 and not es_red_interna(ip):
            alertas_ip[ip].append(
                f"🚫 {count_403} errores 403 desde IP externa — posible enumeración de paths"
            )

    return alertas_ip


# ─────────────────────────────────────────────
# FORMATO DE SALIDA EN CONSOLA
# ─────────────────────────────────────────────
ETIQUETA_CONFIG = {
    "IGNORAR": (C.GREY, "·"),
    "NORMAL": (C.GREEN, "✓"),
    "OBSERVAR": (C.CYAN, "ℹ"),
    "SOSPECHOSO": (C.YELLOW, "⚠"),
    "ANOMALO": (C.RED, "✖"),
}


def imprimir_header():
    print()
    print(colorear("=" * 72, C.BOLD))
    print(
        colorear(
            "  LogGuard Guaraní — Analizador de Logs Apache (UNRN)", C.BOLD + C.WHITE
        )
    )
    print(colorear("=" * 72, C.BOLD))
    print()


def imprimir_resultado(req, etiqueta, razones, num):
    color, icono = ETIQUETA_CONFIG.get(etiqueta, (C.WHITE, "?"))

    fecha_corta = req["fecha"].split(":")[0][1:]  # "19/Apr/2026"
    hora = ":".join(req["fecha"].split(":")[1:3])  # "08:01"

    linea_req = f"{req['metodo']} {req['url'][:55]}"
    if len(req["url"]) > 55:
        linea_req += "…"

    print(
        f"  {colorear(icono, color)} "
        f"{colorear(etiqueta.ljust(10), color + C.BOLD)} "
        f"{colorear(f'[{hora}]', C.GREY)} "
        f"{colorear(req['ip'].ljust(15), C.WHITE)} "
        f"{colorear(str(req['status']), color)} "
        f"{linea_req}"
    )
    for razon in razones:
        print(f"    {colorear('→', C.GREY)} {colorear(razon, color)}")


def imprimir_resumen(stats, alertas_ip):
    print()
    print(colorear("─" * 72, C.BOLD))
    print(colorear("  RESUMEN", C.BOLD + C.WHITE))
    print(colorear("─" * 72, C.BOLD))

    total = sum(stats.values())
    for etiqueta in ["ANOMALO", "SOSPECHOSO", "OBSERVAR", "NORMAL", "IGNORAR"]:
        count = stats.get(etiqueta, 0)
        if count == 0:
            continue
        color, icono = ETIQUETA_CONFIG[etiqueta]
        pct = count / total * 100 if total > 0 else 0
        barra = "█" * int(pct / 3)
        print(
            f"  {colorear(icono, color)} {colorear(etiqueta.ljust(10), color + C.BOLD)} "
            f"{colorear(str(count).rjust(5), C.WHITE)} requests  "
            f"{colorear(barra, color)} {pct:.1f}%"
        )

    print()

    if alertas_ip:
        print(colorear("  ALERTAS POR COMPORTAMIENTO DE IP:", C.BOLD + C.YELLOW))
        print()
        for ip, alertas in alertas_ip.items():
            print(f"  {colorear('►', C.YELLOW)} IP: {colorear(ip, C.WHITE)}")
            for a in alertas:
                print(f"      {a}")
        print()

    print(colorear("─" * 72, C.BOLD))
    print()


# ─────────────────────────────────────────────
# EXPORTAR A CSV
# ─────────────────────────────────────────────
def exportar_csv(resultados, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "fecha",
                "ip",
                "usuario",
                "metodo",
                "url",
                "status",
                "bytes",
                "ua",
                "etiqueta",
                "razones",
            ],
        )
        writer.writeheader()
        for req, etiqueta, razones in resultados:
            writer.writerow(
                {
                    "fecha": req["fecha"],
                    "ip": req["ip"],
                    "usuario": req["usuario"],
                    "metodo": req["metodo"],
                    "url": req["url"],
                    "status": req["status"],
                    "bytes": req["bytes"],
                    "ua": req["ua"],
                    "etiqueta": etiqueta,
                    "razones": " | ".join(razones),
                }
            )
    print(colorear(f"  ✓ Reporte exportado a: {path}", C.GREEN))


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="LogGuard Guaraní — Analiza logs Apache del SIU Guaraní UNRN"
    )
    parser.add_argument("archivo", help="Archivo de log Apache a analizar")
    parser.add_argument(
        "--solo-anomalos",
        action="store_true",
        help="Mostrar sólo SOSPECHOSO y ANOMALO (omite NORMAL y OBSERVAR)",
    )
    parser.add_argument(
        "--exportar", metavar="ARCHIVO.CSV", help="Exportar todos los resultados a CSV"
    )
    args = parser.parse_args()

    # ── Leer y parsear ──────────────────────────────────
    try:
        with open(args.archivo, encoding="utf-8", errors="replace") as f:
            lineas = f.readlines()
    except FileNotFoundError:
        print(colorear(f"  ✖ Archivo no encontrado: {args.archivo}", C.RED))
        sys.exit(1)

    registros = []
    for i, linea in enumerate(lineas, 1):
        r = parsear_linea(linea)
        if r:
            registros.append(r)
        elif linea.strip():
            print(colorear(f"  ! Línea {i} no pudo parsearse: {linea[:60]}", C.GREY))

    imprimir_header()
    print(f"  Archivo:   {colorear(args.archivo, C.CYAN)}")
    print(f"  Líneas:    {colorear(str(len(lineas)), C.WHITE)}")
    print(f"  Parseadas: {colorear(str(len(registros)), C.WHITE)}")
    print()
    print(colorear("─" * 72, C.BOLD))

    # ── Analizar cada request ────────────────────────────
    stats = defaultdict(int)
    resultados = []

    for req in registros:
        etiqueta, razones = analizar_request(req, contexto_ip=None)
        stats[etiqueta] += 1
        resultados.append((req, etiqueta, razones))

        if etiqueta == "IGNORAR":
            continue
        if args.solo_anomalos and etiqueta in ["NORMAL", "OBSERVAR"]:
            continue

        imprimir_resultado(req, etiqueta, razones, 0)

    # ── Patrones por IP ──────────────────────────────────
    alertas_ip = analizar_patrones_ip(registros)

    # ── Resumen ──────────────────────────────────────────
    imprimir_resumen(stats, alertas_ip)

    # ── Exportar CSV ─────────────────────────────────────
    if args.exportar:
        exportar_csv(resultados, args.exportar)


if __name__ == "__main__":
    main()
