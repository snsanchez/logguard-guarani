"""
Returns the knowledge already associated with an event.
The SOC Agent never queries the Knowledge Base directly.
Knowledge enrichment has already been performed by the LogGuard pipeline.
"""

from __future__ import annotations

from ..models.analysis import AnalysisContext
from ..models.knowledge import KnowledgeContext


def knowledge_lookup(
    context: AnalysisContext,
) -> KnowledgeContext:
    """
    Returns
    -------
    KnowledgeContext
        MITRE ATT&CK techniques, CVEs and CISA KEV entries previously
        associated with the event.
    """

    return context.knowledge
