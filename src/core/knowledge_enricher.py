from __future__ import annotations

from soc_agent.models import KnowledgeContext


class KnowledgeEnricher:
    def enrich(
        self,
        event: dict,
    ) -> KnowledgeContext:

        context = KnowledgeContext()

        #
        # Acá reutilizaremos el código que ya existe
        # para consultar MITRE / CVE / KEV.
        #
        # Por ahora devolvemos el contexto vacío.
        #

        return context
