"""
Simplified representation of an enriched event intended for SOC analysis.
This model acts as an abstraction layer between the internal LogGuard event
representation and the SOC Agent.
The agent does not need the complete EnrichedEvent object.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import BaseModel
from .evidence import MLPrediction, RiskLevel


@dataclass(slots=True)
class EventSummary(BaseModel):
    timestamp: str

    source_ip: str

    request_method: str

    request_path: str

    status_code: int

    risk_level: RiskLevel

    risk_score: float

    ml_prediction: MLPrediction

    ml_confidence: float

    heuristics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "status_code": self.status_code,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "ml_prediction": self.ml_prediction.value,
            "ml_confidence": self.ml_confidence,
            "heuristics": self.heuristics,
        }

    @property
    def is_suspicious(self) -> bool:
        return self.ml_prediction in (
            MLPrediction.SUSPICIOUS,
            MLPrediction.ANOMALOUS,
        )

    @property
    def has_multiple_indicators(self) -> bool:
        return len(self.heuristics) > 1
