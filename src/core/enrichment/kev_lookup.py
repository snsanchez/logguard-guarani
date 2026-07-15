from __future__ import annotations

import json
from pathlib import Path

from soc_agent.models import CVEInfo, KEVEntry

DATABASE = Path("knowledge") / "cves" / "kev.json"


def lookup_kev(cves: list[CVEInfo]) -> list[KEVEntry]:

    if not cves:
        return []

    if not DATABASE.exists():
        return []

    try:
        with open(DATABASE, encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError:
        return []

    database = {entry["cve_id"]: entry for entry in data.get("vulnerabilities", [])}

    matches = []

    for cve in cves:
        entry = database.get(cve.cve_id)
        if entry:
            matches.append(
                KEVEntry(
                    cve_id=entry["cve_id"],
                    vendor=entry.get("vendor", ""),
                    product=entry.get("product", ""),
                    vulnerability_name=entry.get("vulnerability_name", ""),
                    date_added=entry.get("date_added", ""),
                    ransomware_use=(
                        entry.get("ransomware_use") is True
                        or entry.get("ransomware_use") == "Known"
                        or entry.get("ransomware_use") == "Yes"
                    ),
                )
            )

    return matches
