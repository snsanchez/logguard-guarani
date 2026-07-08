from __future__ import annotations

from ..models.analysis import AnalysisContext
from ..models.report import ReportConfidence


class ConfidenceCalculator:
    @staticmethod
    def calculate(
        context: AnalysisContext,
    ) -> ReportConfidence:

        evidence = context.event.evidence

        score = 0

        if evidence.ml_confidence >= 0.90:
            score += 2
        elif evidence.ml_confidence >= 0.75:
            score += 1

        score += min(len(evidence.heuristics), 3)

        if context.knowledge.mitre:
            score += 1

        if context.knowledge.cves:
            score += 1

        if context.knowledge.kev:
            score += 2

        if score >= 7:
            return ReportConfidence.HIGH

        if score >= 4:
            return ReportConfidence.MEDIUM

        return ReportConfidence.LOW
