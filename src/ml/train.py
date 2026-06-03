from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

BASE_DIR = Path(__file__).parent

# Cargar el dataset generado previamente
df = pd.read_csv("datasets/dataset.csv")

# ─────────────────────────────────────────────
# PREPARACIÓN DE LOS DATOS
# ─────────────────────────────────────────────
# Separar las características (X) y la etiqueta (y)
X = df.drop("label", axis=1)
y = df["label"]

# Escalar las características para que todas tengan igual peso en el modelo
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Dividir los datos en conjuntos de entrenamiento (70%) y prueba (30%)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.3,
    random_state=42,
)

# ─────────────────────────────────────────────
# ENTRENAMIENTO DEL MODELO
# ─────────────────────────────────────────────
# Support Vector Machine con kernel RBF (no lineal)
modelo = SVC(
    kernel="rbf",
    probability=True,
    random_state=42,
)

# Entrenar el modelo con los datos de entrenamiento
modelo.fit(X_train, y_train)

# Realizar predicciones sobre el conjunto de prueba
pred = modelo.predict(X_test)
print(classification_report(y_test, pred))

# Guardar el modelo entrenado

joblib.dump(modelo, BASE_DIR / "models" / "svm_model.pkl")
joblib.dump(scaler, BASE_DIR / "models" / "scaler.pkl")

print("Modelo entrenado.")
