"""
Transforms an internal EnrichedEvent into a simplified EventSummary.
This tool does not analyze the event.
It only prepares the information required by the SOC Agent.
"""

from __future__ import annotations

from ..models.analysis import EnrichedEvent
from ..models.event_summary import EventSummary


def event_reader(
    event: EnrichedEvent,
) -> EventSummary:

    return EventSummary(
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        request_method=event.method,
        request_path=event.path,
        status_code=event.status_code,
        risk_level=event.evidence.risk_level,
        risk_score=event.evidence.score,
        ml_prediction=event.evidence.ml_prediction,
        ml_confidence=event.evidence.ml_confidence,
        heuristics=event.evidence.heuristics.copy(),
    )
