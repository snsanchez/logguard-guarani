from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import KEVEntry

DATABASE = Path("knowledge/cves/kev_lookup.json")


def lookup_kev(cve_ids: list[str]) -> list[KEVEntry]:

    if not DATABASE.exists():
        return []

    with open(DATABASE, encoding="utf-8") as f:
        database = json.load(f)

    results = []

    for cve in cve_ids:
        if cve in database:
            results.append(KEVEntry(**database[cve]))

    return results
