from __future__ import annotations

from .models.analysis import AnalysisContext
from .models.recommendation import (
    Recommendation,
    RecommendationCategory,
    RecommendationPriority,
)


class RecommendationEngine:
    def generate(
        self,
        context: AnalysisContext,
    ) -> list[Recommendation]:

        recommendations: list[Recommendation] = []

        event = context.event
        knowledge = context.knowledge

        heuristics = set(event.evidence.heuristics)

        if "SQL Injection Pattern" in heuristics:
            recommendations.append(
                Recommendation(
                    title="Review SQL Injection Protection",
                    description=(
                        "Review input validation and parameterized queries "
                        "for the affected application."
                    ),
                    priority=RecommendationPriority.CRITICAL,
                    category=RecommendationCategory.HARDENING,
                    reference="OWASP A03 Injection",
                )
            )

        if "Suspicious User-Agent" in heuristics:
            recommendations.append(
                Recommendation(
                    title="Investigate Source IP",
                    description=(
                        "Correlate the source IP with previous events and "
                        "consider temporary blocking if malicious."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.MONITORING,
                )
            )

        if knowledge.has_cves:
            recommendations.append(
                Recommendation(
                    title="Apply Security Updates",
                    description=(
                        "Update vulnerable software versions associated "
                        "with detected CVEs."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.PATCHING,
                )
            )

        if knowledge.has_kev:
            recommendations.append(
                Recommendation(
                    title="Prioritize KEV Remediation",
                    description=(
                        "CISA lists this vulnerability as actively exploited. "
                        "Prioritize remediation."
                    ),
                    priority=RecommendationPriority.CRITICAL,
                    category=RecommendationCategory.PATCHING,
                )
            )

        if event.is_high_risk:
            recommendations.append(
                Recommendation(
                    title="Preserve Evidence",
                    description=(
                        "Preserve relevant logs for future forensic analysis."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.FORENSICS,
                )
            )

        return recommendations
