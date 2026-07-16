"""
Simple end-to-end test for the SOC Agent.

EnrichedEvent

↓

AnalysisContext

↓

SOCAgent.analyze()

↓

imprimir markdown

↓

imprimir json

"""

from __future__ import annotations

import asyncio

from soc_agent.agent import SOCAgent
from soc_agent.models import (
    AnalysisContext,
    CVEInfo,
    EnrichedEvent,
    EventEvidence,
    KEVEntry,
    KnowledgeContext,
    MitreTechnique,
    MLPrediction,
    RiskLevel,
)
from soc_agent.renderers.markdown_renderer import render_markdown


async def main():

    event = EnrichedEvent(
        timestamp="2026-07-10T18:00:00Z",
        source_ip="192.168.1.25",
        method="GET",
        path="/guarani3/rest/login",
        status_code=200,
        user_agent="sqlmap/1.8",
        evidence=EventEvidence(
            heuristics=[
                "Suspicious User-Agent",
                "SQL Injection Pattern",
            ],
            score=91.5,
            risk_level=RiskLevel.HIGH,
            ml_prediction=MLPrediction.ANOMALOUS,
            ml_confidence=0.97,
        ),
        knowledge=KnowledgeContext(
            mitre=[
                MitreTechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                    description="Attackers exploit public applications.",
                )
            ],
            cves=[
                CVEInfo(
                    cve_id="CVE-2024-0001",
                    description="Example CVE",
                    cvss_score=9.8,
                    severity="CRITICAL",
                )
            ],
            kev=[
                KEVEntry(
                    cve_id="CVE-2024-0001",
                    vendor="Apache",
                    product="HTTP Server",
                    vulnerability_name="Example Vulnerability",
                    date_added="2024-03-01",
                )
            ],
        ),
    )

    context = AnalysisContext(
        event=event,
    )

    agent = SOCAgent()

    report = await agent.analyze(context)

    markdown = render_markdown(report)

    print("=" * 80)
    print(markdown)
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
