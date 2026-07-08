"""
Transforms an AgentAnalysis into the final SOCReport.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..confidence import ConfidenceCalculator
from ..models.agent_analysis import AgentAnalysis
from ..models.analysis import AnalysisContext
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
            evidence=analysis.evidence,
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
