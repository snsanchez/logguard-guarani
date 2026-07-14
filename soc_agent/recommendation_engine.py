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
                    title="Revisar protección contra inyección SQL",
                    description=(
                        "Revisar la validación de entradas y el uso de consultas "
                        "parametrizadas en la aplicación afectada."
                    ),
                    priority=RecommendationPriority.CRITICAL,
                    category=RecommendationCategory.HARDENING,
                    reference="OWASP A03 Injection",
                )
            )

        if "User-Agent Sospechoso" in heuristics:
            recommendations.append(
                Recommendation(
                    title="Investigar dirección IP",
                    description=(
                        "Correlacionar la IP de origen con eventos anteriores y "
                        "considere el bloqueo temporal si es malicioso."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.MONITORING,
                )
            )

        if knowledge.has_cves:
            recommendations.append(
                Recommendation(
                    title="Aplicar actualizaciones de seguridad",
                    description=(
                        "Actualizar versiones de software vulnerables asociadas "
                        "con CVE detectados."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.PATCHING,
                )
            )

        if knowledge.has_kev:
            recommendations.append(
                Recommendation(
                    title="Priorizar la remediación de KEV",
                    description=(
                        "CISA enumera esta vulnerabilidad como explotada activamente "
                        "priorizar la remediación."
                    ),
                    priority=RecommendationPriority.CRITICAL,
                    category=RecommendationCategory.PATCHING,
                )
            )

        if event.is_high_risk:
            recommendations.append(
                Recommendation(
                    title="Preservar evidencia",
                    description=(
                        "Conserve logs relevantes para futuros análisis forenses."
                    ),
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.FORENSICS,
                )
            )

        return recommendations
