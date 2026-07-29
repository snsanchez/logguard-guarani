import argparse
import asyncio
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # raíz del proyecto

from core.attack_classifier import clasificar_tipo_ataque
from core.enrichment.knowledge_enricher import enrich_event
from core.enrichment.risk_mapper import build_enriched_event
from core.events import AnalysisEvent
from core.exporter import exportar_jsonl
from core.heuristics import (
    detectar_inyeccion,
    detectar_path_traversal,
    detectar_scanner,
    es_flujo_sso,
    es_internal_dummy,
    es_red_interna,
    es_ruta_legitima,
    es_ua_conocido,
    es_version_vieja,
    longitud_url_sospechosa,
)
from core.parser import parsear_linea
from core.scoring import calcular_score
from ml.infer import clasificar_evento
from soc_agent.agent import SOCAgent
from soc_agent.models import AnalysisContext
from soc_agent.models.evidence import RiskLevel


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


TIPOS_ATAQUE = [
    "INJECTION",
    "PATH_TRAVERSAL",
    "SCANNER",
    "ERROR_ABUSE",
    "DESCONOCIDO",
]


def imprimir_top_ips(registros, resultados, n=5):

    total_por_ip = defaultdict(int)
    anomalos_por_ip = defaultdict(int)
    errores_por_ip = defaultdict(int)

    for req in registros:
        total_por_ip[req["ip"]] += 1
        if req["status"] in (403, 404):
            errores_por_ip[req["ip"]] += 1

    # evento es un dict que ya contiene todo (ip, etiqueta, etc.)
    for evento in resultados:
        if evento["etiqueta"] in ("ANOMALO", "SOSPECHOSO"):
            anomalos_por_ip[evento["ip"]] += 1

    def ranking(d, titulo, color_val):
        items = sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]
        if not items:
            return
        print(colorear(f"  {titulo}", C.BOLD + C.WHITE))
        for i, (ip, val) in enumerate(items, 1):
            barra = "█" * min(val, 30)
            print(
                f"{colorear(str(i).rjust(2), C.GREY)}. "
                f"{colorear(ip.ljust(16), C.WHITE)} "
                f"{colorear(str(val).rjust(5), color_val)} "
                f"{colorear(barra, color_val)}"
            )
        print()

    print(colorear("  TOP IPs:", C.BOLD + C.WHITE))
    print()
    ranking(total_por_ip, "Por volumen total de requests:", C.CYAN)
    ranking(anomalos_por_ip, "Por requests ANOMALO/SOSPECHOSO:", C.RED)
    ranking(errores_por_ip, "Por errores HTTP (403 + 404):", C.YELLOW)


def analizar_request(req):
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

    # ── NORMAL ─────────────────────────────────────────
    if req["status"] == 200 and es_ruta_legitima(req["url"]):
        return "NORMAL", ["200 - Ruta legítima"]

    if es_flujo_sso(req):
        return "NORMAL", ["302 parte del flujo SSO/SAML normal"]

    if req["status"] == 304:
        return "NORMAL", ["304 Not Modified — caché del browser"]

    # ── ANÁLISIS DE AMENAZAS (mayor prioridad primero) ──
    if detectar_inyeccion(req["url"]):
        razones.append("⚠️  Patrón de inyección detectado en URL")
        return "ANOMALO", razones

    if detectar_path_traversal(req["url"]):
        razones.append("⚠️  Path traversal detectado")
        return "ANOMALO", razones

    if detectar_scanner(req["ua"]):
        razones.append(
            f"⚠️  User-Agent de scanner/herramienta de ataque: {req['ua'][:60]}"
        )
        return "ANOMALO", razones

    # ── STATUS ───────────────────────────────
    if req["status"] == 403:
        if es_red_interna(req["ip"]):
            razones.append("403 interno")
            return "OBSERVAR", razones

        razones.append("403 externo")
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

    # ── UA ───────────────────────────────
    if not es_ua_conocido(req["ua"]) and req["ua"] != "-":
        razones.append(f"User-Agent desconocido: {req['ua'][:80]}")
        return "SOSPECHOSO", razones

    return "OBSERVAR", ["Actividad no catalogada"]


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


def imprimir_resultado(req, etiqueta, razones, num, score=0, tipo_ataque=None):
    color, icono = ETIQUETA_CONFIG.get(etiqueta, (C.WHITE, "?"))
    hora = ":".join(req["fecha"].split(":")[1:3])  # "08:01"

    linea_req = f"{req['metodo']} {req['url'][:55]}"
    if len(req["url"]) > 55:
        linea_req += "…"

    score_str = colorear(
        f"[{score:>3}]", C.RED if score >= 40 else C.YELLOW if score >= 15 else C.GREY
    )
    tipo_str = colorear(f" {tipo_ataque}", C.MAGENTA) if tipo_ataque else ""

    print(
        f"  {colorear(icono, color)} "
        f"{colorear(etiqueta.ljust(10), color + C.BOLD)} "
        f"{colorear(f'[{hora}]', C.GREY)} "
        f"{colorear(req['ip'].ljust(15), C.WHITE)} "
        f"{colorear(str(req['status']), color)} "
        f"{score_str}{tipo_str} "
        f"{linea_req}"
    )
    for razon in razones:
        print(f"    {colorear('→', C.GREY)} {colorear(razon, color)}")


def imprimir_resumen(stats, alertas_ip, registros=None, resultados=None):
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

    if registros and resultados:
        imprimir_top_ips(registros, resultados)

    print(colorear("─" * 72, C.BOLD))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="LogGuard Guaraní — Analizador defensivo de logs Apache SIU Guaraní"
    )

    parser.add_argument("archivo", nargs="?", help="Archivo de log Apache a analizar")

    parser.add_argument(
        "--solo-anomalos",
        action="store_true",
        help="Mostrar sólo SOSPECHOSO y ANOMALO (omite NORMAL y OBSERVAR)",
    )

    parser.add_argument(
        "--exportar-json",
        metavar="ARCHIVO.JSONL",
        help="Exportar eventos enriquecidos a archivo JSONL",
    )

    parser.add_argument(
        "--razonar",
        action="store_true",
        help="Ejecuta clasificación SVM sobre eventos SOSPECHOSO y ANOMALO",
    )

    parser.add_argument(
        "--actualizar-conocimiento",
        action="store_true",
        help="Verifica y actualiza la base de conocimiento local",
    )

    parser.add_argument(
        "--online",
        action="store_true",
        help="Fuerza sincronizacion consultando fuentes externa requiriendo wifi (CVE/MITRE/KEV)",
    )

    args = parser.parse_args()

    if args.actualizar_conocimiento:
        from core.knowledge import update_knowledge

        exit(update_knowledge(force_online=args.online))

    if args.archivo is None:
        parser.error("Debe indicar un archivo de log para analizar")

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
    eventos = []
    soc_events = []

    for req in registros:
        etiqueta, razones = analizar_request(req)

        score = calcular_score(req["url"], req["ua"], req["status"])

        tipo_ataque = clasificar_tipo_ataque(
            req["url"], req["ua"], req["status"], etiqueta
        )

        evento = {
            "ip": req["ip"],
            "usuario": req["usuario"],
            "fecha": req["fecha"],
            "metodo": req["metodo"],
            "url": req["url"],
            "status": req["status"],
            "bytes": req["bytes"],
            "ua": req["ua"],
            "etiqueta": etiqueta,
            "tipo_ataque": tipo_ataque,
            "score": score,
            "razones": razones,
        }

        # ── ML ───────────────────────────────
        if args.razonar and etiqueta in ("SOSPECHOSO", "ANOMALO"):
            resultado_ml = clasificar_evento(evento)

            evento["ml_prediction"] = resultado_ml["prediction"]
            evento["ml_confidence"] = resultado_ml["confidence"]

        # --------------------------
        # Construcción del EnrichedEvent

        analysis_event = AnalysisEvent(**evento)

        enriched = build_enriched_event(analysis_event)

        enriched = enrich_event(analysis_event, enriched)

        eventos.append(evento)

        stats[etiqueta] += 1

        # ── FILTRO CONSOLA ───────────────────
        if args.solo_anomalos and etiqueta not in ("SOSPECHOSO", "ANOMALO"):
            continue

        imprimir_resultado(
            req, etiqueta, razones, 0, score=score, tipo_ataque=tipo_ataque
        )

        # ── OUTPUT ML ────────────────────────
        if "ml_prediction" in evento:
            print(
                f"   → ML prediction: "
                f"{evento['ml_prediction']} "
                f"(confianza={evento['ml_confidence']})"
            )

        if enriched.evidence.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            soc_events.append(enriched)

    # ─────────────────────────────────────────
    # EXPORTAR
    if args.exportar_json:
        exportar_jsonl(
            eventos,
            args.exportar_json,
        )
        print()
        print(f"Eventos exportados a: {args.exportar_json}")

    # ── Patrones por IP ──────────────────────────────────
    alertas_ip = analizar_patrones_ip(registros)
    # ── Resumen ──────────────────────────────────────────
    imprimir_resumen(stats, alertas_ip, registros=registros, resultados=eventos)

    # --- ! Solo se genera un reporte para el evento con mas riesgo detectado en el log
    if soc_events:
        most_relevant = max(
            soc_events,
            key=lambda e: e.evidence.score,
        )
        context = AnalysisContext(
            event=most_relevant,
        )
        report = asyncio.run(SOCAgent().analyze(context))

        print()
        print("Reporte SOC generado:")
        print(report.title)


if __name__ == "__main__":
    main()
