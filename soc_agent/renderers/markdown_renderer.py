from __future__ import annotations

from pathlib import Path

from ..models.report import SOCReport


def render_markdown(
    report: SOCReport,
    output_path: str | Path | None = None,
) -> str:

    markdown = _build_markdown(report)

    if output_path is not None:
        path = Path(output_path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            markdown,
            encoding="utf-8",
        )

    return markdown


def _build_markdown(
    report: SOCReport,
) -> str:
    lines = []

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    lines.append(f"# {report.title}")

    lines.append("")

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    lines.append("## Analysis Metadata")

    lines.append("")

    lines.append(f"- Severity: **{report.severity.value}**")

    lines.append(f"- Confidence: **{report.confidence.value}**")

    if report.generated_at:
        lines.append(f"- Generated at: `{report.generated_at}`")

    lines.append("")

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    lines.append("## Executive Summary")

    lines.append("")

    lines.append(report.executive_summary)

    lines.append("")

    # ------------------------------------------------------------------
    # Event Overview
    # ------------------------------------------------------------------

    lines.append("## Event Overview")

    lines.append("")

    lines.append(report.event_overview)

    lines.append("")

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    lines.append("## Evidence")

    lines.append("")

    if report.evidence:
        for evidence in report.evidence:
            lines.append(f"### {evidence.title}")

            lines.append("")

            lines.append(evidence.description)

            lines.append("")

            lines.append(f"- Source: `{evidence.source}`")

            lines.append(f"- Severity: `{evidence.severity.value}`")

            lines.append("")

    else:
        lines.append("No evidence available.")

        lines.append("")

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

    lines.append("## Recommendations")

    lines.append("")

    if report.recommendations:
        for recommendation in report.recommendations:
            lines.append(f"### {recommendation.title}")

            lines.append("")

            lines.append(recommendation.description)

            lines.append("")

            lines.append(f"- Priority: `{recommendation.priority.value}`")

            lines.append(f"- Category: `{recommendation.category.value}`")

            if recommendation.reference:
                lines.append(f"- Reference: `{recommendation.reference}`")

            lines.append("")

    # ------------------------------------------------------------------
    # Analyst Notes
    # ------------------------------------------------------------------

    else:
        lines.append("No recommendations generated.")

        lines.append("")

    lines.append("## Analyst Notes")

    lines.append("")

    lines.append(
        report.analyst_notes if report.analyst_notes else "No additional notes."
    )

    return "\n".join(lines)
