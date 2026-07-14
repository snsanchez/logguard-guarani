from pydantic import BaseModel


class AnalysisEvent(BaseModel):
    ip: str

    usuario: str

    fecha: str

    metodo: str

    url: str

    status: int

    bytes: int

    ua: str

    etiqueta: str

    tipo_ataque: str | None

    score: float

    razones: list[str]

    ml_prediction: str | None = None

    ml_confidence: float = 0.0
