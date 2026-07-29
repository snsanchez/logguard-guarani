from __future__ import annotations

from core.events import AnalysisEvent
from soc_agent.models import (
    EnrichedEvent,
    EventEvidence,
    KnowledgeContext,
    MLPrediction,
    RiskLevel,
)


def _risk_level(score: float) -> RiskLevel:

    if score >= 90:
        return RiskLevel.CRITICAL

    if score >= 75:
        return RiskLevel.HIGH

    if score >= 40:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def _ml_prediction(prediction: str | None) -> MLPrediction:

    if prediction is None:
        return MLPrediction.UNKNOWN

    mapping = {
        "NORMAL": MLPrediction.NORMAL,
        "OBSERVAR": MLPrediction.OBSERVE,
        "SOSPECHOSO": MLPrediction.SUSPICIOUS,
        "ANOMALO": MLPrediction.ANOMALOUS,
    }

    return mapping.get(prediction.upper(), MLPrediction.UNKNOWN)


def build_enriched_event(
    event: AnalysisEvent,
) -> EnrichedEvent:

    score = min(event.score, 100.0)
    return EnrichedEvent(
        timestamp=event.fecha,
        source_ip=event.ip,
        method=event.metodo,
        path=event.url,
        status_code=event.status,
        user_agent=event.ua,
        evidence=EventEvidence(
            heuristics=event.razones,
            score=score,
            risk_level=_risk_level(score),
            ml_prediction=_ml_prediction(event.ml_prediction),
            ml_confidence=event.ml_confidence,
        ),
        knowledge=KnowledgeContext(),
    )
