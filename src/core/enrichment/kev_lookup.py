from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import KEVEntry

DATABASE = Path("knowledge") / "cves" / "kev.json"


def lookup_kev(
    cves,
) -> list[KEVEntry]:

    with open(DATABASE, encoding="utf-8") as f:
        kev = json.load(f)

    ids = {c.cve_id for c in cves}

    return [KEVEntry(**item) for item in kev if item["cve_id"] in ids]
