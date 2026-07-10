"""
Transforms an AgentAnalysis into the final SOCReport.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..confidence import ConfidenceCalculator
from ..models.agent_analysis import AgentAnalysis
from ..models.analysis import AnalysisContext
from ..models.evidence import EvidenceItem
from ..models.report import (
    ReportSeverity,
    SOCReport,
)


class ReportBuilder:
    def build(
        self,
        context: AnalysisContext,
        analysis: AgentAnalysis,
    ) -> SOCReport:

        report = SOCReport(
            title=self._build_title(context),
            executive_summary=analysis.executive_summary,
            event_overview=analysis.event_overview,
            severity=self._severity(context),
            confidence=ConfidenceCalculator.calculate(context),
            evidence=(
                analysis.evidence
                if analysis.evidence
                else self._default_evidence(context)
            ),
            recommendations=context.recommendations,
            analyst_notes=analysis.analyst_notes,
            generated_at=datetime.now(UTC).isoformat(),
        )

        context.set_report(report)

        return report

    def _build_title(
        self,
        context: AnalysisContext,
    ) -> str:

        event = context.event

        return (
            f"{event.evidence.risk_level.value} Risk Event "
            f"({event.method} {event.path})"
        )

    def _severity(
        self,
        context: AnalysisContext,
    ) -> ReportSeverity:

        return ReportSeverity(context.event.evidence.risk_level.value)

    def _default_evidence(
        self,
        context: AnalysisContext,
    ) -> list[EvidenceItem]:

        event = context.event

        return [
            EvidenceItem(
                title="LogGuard Detection",
                description=(
                    f"Event classified as "
                    f"{event.evidence.ml_prediction.value} "
                    f"with score {event.evidence.score:.1f}."
                ),
                source="LogGuard",
                severity=event.evidence.risk_level,
            )
        ]
