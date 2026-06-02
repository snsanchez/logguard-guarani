# Interfaz entre logguard y el modelo de machine learning

import numpy as np

FEATURE_VERSION = 1

METODO_COD = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "HEAD": 4,
    "OPTIONS": 5,
    "PATCH": 6,
}

TIPO_ATAQUE_COD = {
    None: 0,
    "DESCONOCIDO": 1,
    "ERROR_ABUSE": 2,
    "SCANNER": 3,
    "PATH_TRAVERSAL": 4,
    "INJECTION": 5,
}


def extraer_features(evento):

    return np.array(
        [
            float(evento.get("score", 0)),
            float(evento.get("status", 0)),
            float(evento.get("bytes", 0)),
            float(len(evento.get("url", ""))),
            float(METODO_COD.get(evento.get("metodo"), 0)),
            float(TIPO_ATAQUE_COD.get(evento.get("tipo_ataque"), 0)),
        ],
        dtype=np.float32,
    )


FEATURE_NAMES = [
    "score",
    "status",
    "bytes",
    "url_length",
    "metodo_cod",
    "tipo_ataque_cod",
]
