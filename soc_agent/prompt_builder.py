"""
Serializes LogGuard domain objects into the textual context consumed by
the SOC Agent.
"""

from __future__ import annotations

from .models.event_summary import EventSummary
from .models.knowledge import KnowledgeContext


class ContextSerializer:
    @staticmethod
    def serialize(
        event: EventSummary,
        knowledge: KnowledgeContext,
    ) -> str:

        lines: list[str] = []

        # ==============================================================
        # Event
        # ==============================================================

        lines.append("# Security Event")
        lines.append("")

        lines.append(f"Timestamp: {event.timestamp}")
        lines.append(f"Source IP: {event.source_ip}")
        lines.append(f"HTTP Method: {event.request_method}")
        lines.append(f"Path: {event.request_path}")
        lines.append(f"Status Code: {event.status_code}")

        lines.append("")

        lines.append(f"Risk Level: {event.risk_level.value}")
        lines.append(f"Risk Score: {event.risk_score:.1f}")

        lines.append(f"ML Prediction: {event.ml_prediction.value}")

        lines.append(f"ML Confidence: {event.ml_confidence:.2%}")

        lines.append("")

        lines.append("Triggered Heuristics:")

        if event.heuristics:
            for heuristic in event.heuristics:
                lines.append(f"- {heuristic}")
        else:
            lines.append("- None")

        lines.append("")

        # ==============================================================
        # MITRE
        # ==============================================================

        lines.append("# MITRE ATT&CK")

        if knowledge.mitre:
            for technique in knowledge.mitre:
                lines.append(f"- {technique.technique_id}: {technique.name}")

                if technique.tactic:
                    lines.append(f"  Tactic: {technique.tactic}")

        else:
            lines.append("- None")

        lines.append("")

        # ==============================================================
        # CVEs
        # ==============================================================

        lines.append("# CVEs")

        if knowledge.cves:
            for cve in knowledge.cves:
                lines.append(f"- {cve.cve_id}")

                if cve.cvss_score is not None:
                    lines.append(f"  CVSS: {cve.cvss_score}")

                if cve.description:
                    lines.append(f"  Summary: {cve.description}")

        else:
            lines.append("- None")

        lines.append("")

        # ==============================================================
        # KEV
        # ==============================================================

        lines.append("# CISA Known Exploited Vulnerabilities")

        if knowledge.kev:
            for kev in knowledge.kev:
                lines.append(f"- {kev.cve_id}")

                if kev.vendor:
                    lines.append(f"  Vendor: {kev.vendor}")

                if kev.product:
                    lines.append(f"  Product: {kev.product}")

        else:
            lines.append("- None")

        return "\n".join(lines)


@staticmethod
def serialize_dict(
    event: EventSummary,
    knowledge: KnowledgeContext,
) -> dict:

    return {
        "event": event.to_dict(),
        "knowledge": knowledge.to_dict(),
    }
