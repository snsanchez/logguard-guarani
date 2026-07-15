from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import MitreTechnique

DATABASE = Path("knowledge") / "mitre" / "attack_mapping.json"


def lookup_mitre(
    attack_type: str | None,
) -> list[MitreTechnique]:

    if attack_type is None:
        return []

    with open(DATABASE, encoding="utf-8") as f:
        data = json.load(f)

    result = data.get(attack_type, [])

    return [MitreTechnique(**item) for item in result]
