from core.heuristics import (
    detectar_inyeccion,
    detectar_path_traversal,
    detectar_scanner,
)


def clasificar_tipo_ataque(url, ua, status, etiqueta):

    if etiqueta in ("IGNORAR", "NORMAL", "OBSERVAR"):
        return None

    if detectar_inyeccion(url):
        return "INJECTION"
    if detectar_path_traversal(url):
        return "PATH_TRAVERSAL"
    if detectar_scanner(ua):
        return "SCANNER"
    if status in (403, 404):
        return "ERROR_ABUSE"

    return "DESCONOCIDO"
