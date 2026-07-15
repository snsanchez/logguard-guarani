from __future__ import annotations

from soc_agent.models import (
    EnrichedEvent,
    KnowledgeContext,
)

from ..events import AnalysisEvent
from .cve_lookup import lookup_cves
from .kev_lookup import lookup_kev
from .mitre_lookup import lookup_mitre


def enrich_event(analysis: AnalysisEvent, event: EnrichedEvent) -> EnrichedEvent:

    attack = analysis.tipo_ataque

    mitre = lookup_mitre(attack)
    cves = lookup_cves(attack, analysis.url)

    kev = lookup_kev(cves)

    event.knowledge = KnowledgeContext(
        mitre=mitre,
        cves=cves,
        kev=kev,
    )
    return event
