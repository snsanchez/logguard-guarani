"""
Responsible for deciding when an enriched event
must be analyzed by the SOC Agent.
"""

from __future__ import annotations

from soc_agent.agent import SOCAgent
from soc_agent.models import AnalysisContext, EnrichedEvent


class SOCOrchestrator:
    def __init__(
        self,
        threshold: float = 75.0,
    ) -> None:

        self.threshold = threshold
        self.agent = SOCAgent()

    def should_analyze(
        self,
        event: EnrichedEvent,
    ) -> bool:

        return event.evidence.score >= self.threshold

    async def process(
        self,
        event: EnrichedEvent,
    ):
        if not self.should_analyze(event):
            return None
        context = AnalysisContext(
            event=event,
        )
        report = await self.agent.analyze(
            context,
        )
        return report
