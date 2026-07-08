@dataclass(slots=True)
class KnowledgeContext:
    mitre: list[dict]

    cves: list[dict]

    kev: list[dict]
