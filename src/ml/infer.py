from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.features import FEATURE_NAMES, extraer_features

# para que no se carguen los modelos automaticando solo al importar infer
modelo = None
scaler = None


def cargar_modelos():
    global modelo, scaler

    if modelo is None or scaler is None:
        base = Path(__file__).parent / "models"
        # Ruta absoluta relativa a este archivo (src/ml/infer.py → src/ml/models/)

        modelo_path = base / "svm_model.pkl"
        scaler_path = base / "scaler.pkl"

        if not modelo_path.exists():
            raise FileNotFoundError(f"Modelo no encontrado: {modelo_path}")

        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler no encontrado: {scaler_path}")

        modelo = joblib.load(modelo_path)
        scaler = joblib.load(scaler_path)


def clasificar_evento(evento):
    cargar_modelos()
    x = extraer_features(evento)
    # para que sklearn reciba un dataframe y no un array
    x = pd.DataFrame([x], columns=FEATURE_NAMES)
    x = scaler.transform(x)

    pred = modelo.predict(x)[0]
    prob = modelo.predict_proba(x)[0]

    confianza = float(np.max(prob))

    return {
        "prediction": pred,
        "confidence": round(confianza, 4),
    }
