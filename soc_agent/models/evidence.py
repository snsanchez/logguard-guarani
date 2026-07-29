"""
Evidence models produced by the LogGuard analysis pipeline.
These classes represent the evidence collected BEFORE the SOC Agent starts
its reasoning process.
The SOC Agent never computes new evidence.
It only interprets the evidence already produced.
"""

from __future__ import annotations

from dataclasses import asdict
from enum import Enum, StrEnum

from pydantic import BaseModel, Field, model_validator

# ============================================================================
# Event Evidence
# ============================================================================


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MLPrediction(StrEnum):
    NORMAL = "NORMAL"
    OBSERVE = "OBSERVAR"
    SUSPICIOUS = "SOSPECHOSO"
    ANOMALOUS = "ANOMALO"
    UNKNOWN = "UNKNOWN"


class EventEvidence(BaseModel):
    """
    This information comes from:
    - Heuristics
    - Risk scoring
    - ML
    """

    heuristics: list[str]

    score: float = Field(ge=0.0, le=100.0)

    risk_level: RiskLevel

    ml_prediction: MLPrediction

    ml_confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_evidence(self):

        if self.score >= 75 and self.risk_level not in (
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ):
            raise ValueError("High score requires HIGH risk level.")

        return self

    @property
    def is_high_risk(self) -> bool:
        return self.score >= 75

    @property
    def is_medium_risk(self) -> bool:
        return 50 <= self.score < 75

    @property
    def is_low_risk(self) -> bool:
        return self.score < 50

    @property
    def heuristic_count(self) -> int:
        return len(self.heuristics)


class EvidenceItem(BaseModel):
    title: str = Field(description="Short title identifying the evidence.")

    description: str = Field(description="Detailed explanation of the evidence.")

    source: str = Field(description="Origin of the evidence.")

    severity: RiskLevel = Field(description="Severity associated with the evidence.")

    def to_dict(self):
        return asdict(self)
