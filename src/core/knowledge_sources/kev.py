from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .base import KnowledgeUpdater
from .paths import KEV_CACHE_FILE

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KEVUpdater(KnowledgeUpdater):
    name = "CISA KEV"
    target_file = KEV_CACHE_FILE

    def fetch(self) -> Any:
        return self._http_get_json(CISA_KEV_URL)

    def validate(self, data: Any) -> bool:
        return isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list)

    def save(self, data: Any) -> int:

        vulnerabilities = data["vulnerabilities"]

        simplified = []

        lookup = {}

        for entry in vulnerabilities:
            record = {
                "cve_id": entry.get("cveID"),
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "date_added": entry.get("dateAdded"),
            }

            simplified.append(record)

            lookup[record["cve_id"]] = record

        payload = {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "count": len(simplified),
            "vulnerabilities": simplified,
        }

        self.target_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.target_file, "w", encoding="utf-8") as f:
            json.dump(
                payload,
                f,
                indent=2,
                ensure_ascii=False,
            )

        lookup_file = self.target_file.parent / "kev_lookup.json"

        with open(lookup_file, "w", encoding="utf-8") as f:
            json.dump(
                lookup,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return len(simplified)
