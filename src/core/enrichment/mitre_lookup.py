from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import MitreTechnique

DATABASE = Path("knowledge/mitre/attack_mapping.json")


def lookup_mitre(attack_type: str | None) -> list[MitreTechnique]:

    if attack_type is None:
        return []

    if not DATABASE.exists():
        return []

    with open(DATABASE, encoding="utf-8") as f:
        database = json.load(f)

    item = database.get(attack_type)

    if item is None:
        return []

    return [
        MitreTechnique(
            technique_id=item["technique"],
            name=item["name"],
            tactic=item.get("tactic", ""),
            description=item.get("description", ""),
        )
    ]
