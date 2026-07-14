"""
Factory functions for building SOC models from LogGuard pipeline results.
"""

from __future__ import annotations

from .models import (
    EnrichedEvent,
    EventEvidence,
    KnowledgeContext,
    MLPrediction,
    RiskLevel,
)


def build_event(
    *,
    timestamp: str,
    source_ip: str,
    method: str,
    path: str,
    status_code: int,
    user_agent: str,
    heuristics: list[str],
    score: float,
    risk_level: RiskLevel,
    ml_prediction: MLPrediction,
    ml_confidence: float,
    knowledge: KnowledgeContext | None = None,
) -> EnrichedEvent:

    return EnrichedEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        method=method,
        path=path,
        status_code=status_code,
        user_agent=user_agent,
        evidence=EventEvidence(
            heuristics=heuristics,
            score=score,
            risk_level=risk_level,
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
        ),
        knowledge=knowledge or KnowledgeContext(),
    )
