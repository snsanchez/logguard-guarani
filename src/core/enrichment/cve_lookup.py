from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import CVEInfo

DATABASE = Path("knowledge") / "cves" / "recent.json"


def lookup_cves(
    attack_type: str | None,
    path: str,
) -> list[CVEInfo]:

    with open(DATABASE, encoding="utf-8") as f:
        data = json.load(f)

    matches = []

    for cve in data:
        if attack_type == "INJECTION":
            if "sql" in cve["description"].lower():
                matches.append(CVEInfo(**cve))

        elif attack_type == "PATH_TRAVERSAL":
            if "path traversal" in cve["description"].lower():
                matches.append(CVEInfo(**cve))

        elif attack_type == "SCANNER":
            if "apache" in cve["description"].lower():
                matches.append(CVEInfo(**cve))

    return matches
