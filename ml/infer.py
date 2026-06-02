import joblib
import numpy as np

from ml.features import extraer_features

# Cargar el modelo y el escalador entrenados
modelo = joblib.load("ml/models/svm_model.pkl")
scaler = joblib.load("ml/models/scaler.pkl")


def clasificar_evento(evento):

    x = extraer_features(evento)

    x = scaler.transform([x])

    pred = modelo.predict(x)[0]

    prob = modelo.predict_proba(x)[0]

    confianza = float(np.max(prob))

    return {
        "prediction": int(pred),
        "confidence": round(confianza, 4),
    }
