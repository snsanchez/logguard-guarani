from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import CVEInfo

DATABASE = Path("knowledge") / "cves" / "cve_lookup.json"


def lookup_cves(attack_type: str | None) -> list[CVEInfo]:

    if attack_type is None:
        return []

    if not DATABASE.exists():
        return []

    with open(DATABASE, encoding="utf-8") as f:
        database = json.load(f)

    entries = database.get(attack_type, [])

    return [CVEInfo(**entry) for entry in entries]
