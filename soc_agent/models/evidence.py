"""
Evidence models produced by the LogGuard analysis pipeline.
These classes represent the evidence collected BEFORE the SOC Agent starts
its reasoning process.
The SOC Agent never computes new evidence.
It only interprets the evidence already produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from soc_agent.models.base import BaseModel

# ============================================================================
# Event Evidence
# ============================================================================


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MLPrediction(Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(slots=True)
class EventEvidence(BaseModel):
    """
    This information comes from:
    - Heuristics
    - Risk scoring
    - ML
    """

    heuristics: list[str]

    score: float

    risk_level: RiskLevel

    ml_prediction: MLPrediction

    ml_confidence: float

    def __post_init__(self) -> None:

        if not 0.0 <= self.score <= 100.0:
            raise ValueError("Risk score must be between 0 and 100.")

        if not 0.0 <= self.ml_confidence <= 1.0:
            raise ValueError("ML confidence must be between 0 and 1.")

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


@dataclass(slots=True)
class EvidenceItem(BaseModel):
    """
    Single piece of evidence shown in the SOC report.

    Unlike EventEvidence, this object is human-oriented.
    """

    title: str

    description: str

    source: str

    severity: RiskLevel
