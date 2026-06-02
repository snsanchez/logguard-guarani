from core.heuristics import (
    detectar_inyeccion,
    detectar_path_traversal,
    detectar_scanner,
    es_ua_conocido,
)


# ─────────────────────────────────────────────
# SCORE DE RIESGO
# Cada regla suma puntos independientemente.
# El score NO reemplaza la etiqueta — es información adicional.
# ─────────────────────────────────────────────
def calcular_score(url, ua, status):
    score = 0

    # ── Señales de URL ──────────────────────────────────
    if detectar_inyeccion(url):
        score += 50

    if detectar_path_traversal(url):
        score += 40

    # ── Señales de User-Agent ────────────────────────────
    if detectar_scanner(ua):
        score += 30

    elif not es_ua_conocido(ua) and ua not in ("-", ""):
        score += 10

    # ── Señales de status HTTP ───────────────────────────
    if status == 403:
        score += 15

    elif status == 404:
        score += 10

    elif status >= 500:
        score += 20

    return score
