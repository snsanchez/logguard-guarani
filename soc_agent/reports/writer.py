from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..models.report import SOCReport
from ..renderers.markdown_renderer import render_markdown


class ReportWriter:
    def __init__(
        self,
        output_dir: Path | None = None,
    ) -> None:

        self.output_dir = output_dir or (Path(__file__).parent)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save_markdown(
        self,
        report: SOCReport,
    ) -> Path:

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

        filename = f"{timestamp}_{report.severity.value.lower()}.md"

        path = self.output_dir / filename

        path.write_text(
            render_markdown(report),
            encoding="utf-8",
        )

        return path
