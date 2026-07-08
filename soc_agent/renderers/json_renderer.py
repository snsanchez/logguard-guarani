"""
Use example:

from soc.renderers.json_renderer import render_json


json_report = render_json(
    report,
    "reports/event_001.json"
)
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models.report import SOCReport


def render_json(
    report: SOCReport,
    output_path: str | Path | None = None,
    indent: int = 4,
) -> str:

    json_content = json.dumps(
        report.to_dict(),
        indent=indent,
        ensure_ascii=False,
    )

    if output_path is not None:
        path = Path(output_path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json_content,
            encoding="utf-8",
        )

    return json_content
