"""
analysis.py

Core domain models used during SOC analysis.

EnrichedEvent represents the input received from the detection pipeline.

AnalysisContext represents the mutable state while the SOC Agent executes
its analysis workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import BaseModel
from .evidence import EventEvidence
from .knowledge import KnowledgeContext
from .recommendation import Recommendation
from .report import SOCReport
from .stage import AnalysisStage


@dataclass(slots=True)
class EnrichedEvent(BaseModel):
    """
    Complete event information provided to the SOC Agent.

    This object is generated before the agent starts reasoning.

    The agent must never modify this object.
    """

    timestamp: str

    source_ip: str

    destination: str

    method: str

    path: str

    status_code: int

    user_agent: str

    evidence: EventEvidence

    knowledge: KnowledgeContext = field(default_factory=KnowledgeContext)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "evidence": self.evidence.to_dict(),
            "knowledge": self.knowledge.to_dict(),
        }

    @property
    def is_high_risk(self) -> bool:
        """
        Indicates if this event requires SOC analysis.
        """

        return self.evidence.is_high_risk


@dataclass(slots=True)
class AnalysisContext(BaseModel):
    """
    Mutable context shared between SOC Agent tools.

    Each tool enriches this object instead of returning raw dictionaries.
    """

    event: EnrichedEvent

    stage: AnalysisStage = AnalysisStage.CREATED

    recommendations: list[Recommendation] = field(default_factory=list)

    report: SOCReport | None = None

    def advance(
        self,
        stage: AnalysisStage,
    ) -> None:
        """
        Updates the current analysis stage.
        """

        self.stage = stage

    def add_recommendation(
        self,
        recommendation: Recommendation,
    ) -> None:
        """
        Adds a defensive recommendation.
        """

        self.recommendations.append(recommendation)

    def set_report(
        self,
        report: SOCReport,
    ) -> None:
        """
        Stores the final generated report.
        """

        self.report = report

        self.stage = AnalysisStage.REPORT_READY

    @property
    def has_report(self) -> bool:
        return self.report is not None

    @property
    def knowledge(self) -> KnowledgeContext:
        """
        Shortcut access to event knowledge.
        """

        return self.event.knowledge

    @property
    def severity(self):
        """
        Shortcut access to event risk level.

        Keeps tools independent from the internal event structure.
        """

        return self.event.evidence.risk_level
