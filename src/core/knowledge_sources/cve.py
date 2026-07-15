"""
Synchronizes a local cache of recently modified CVEs from the NVD
(National Vulnerability Database) REST API.

NOTE: NVD applies aggressive rate limiting to unauthenticated requests.
For production use, request an NVD API key and send it via the
'apiKey' header -- see https://nvd.nist.gov/developers/request-an-api-key
This implementation works without a key but may be throttled.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import KnowledgeUpdater
from .paths import CVE_CACHE_FILE

# Window of recently-modified CVEs to pull on each sync. Kept small to
# avoid NVD rate limits; increase if you have an API key configured.
LOOKBACK_DAYS = 7

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEUpdater(KnowledgeUpdater):
    name = "Cache de CVEs (NVD)"
    target_file = CVE_CACHE_FILE

    def fetch(self) -> Any:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=LOOKBACK_DAYS)
        url = (
            f"{NVD_API_URL}"
            f"?lastModStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&lastModEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        )
        return self._http_get_json(url)

    def validate(self, data: Any) -> bool:
        return isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list)

    def save(self, data: Any) -> int:

        vulnerabilities = data["vulnerabilities"]

        simplified = []

        lookup = {
            "INJECTION": [],
            "PATH_TRAVERSAL": [],
            "SCANNER": [],
        }

        for entry in vulnerabilities:
            cve = entry.get("cve", {})

            descriptions = cve.get("descriptions", [])

            description = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                "",
            )

            severity = self._extract_severity(cve.get("metrics", {}))

            record = {
                "cve_id": cve.get("id"),
                "description": description,
                "cvss_score": None,
                "severity": severity,
            }

            simplified.append(record)

            desc = description.lower()

            if "sql" in desc or "injection" in desc:
                lookup["INJECTION"].append(record)

            if "path traversal" in desc:
                lookup["PATH_TRAVERSAL"].append(record)

            if (
                "apache" in desc
                or "http server" in desc
                or "nginx" in desc
                or "scanner" in desc
            ):
                lookup["SCANNER"].append(record)

        payload = {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "count": len(simplified),
            "cves": simplified,
        }

        self.target_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.target_file, "w", encoding="utf-8") as f:
            json.dump(
                payload,
                f,
                indent=2,
                ensure_ascii=False,
            )

        lookup_file = self.target_file.parent / "cve_lookup.json"

        with open(lookup_file, "w", encoding="utf-8") as f:
            json.dump(
                lookup,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return len(simplified)

    @staticmethod
    def _extract_severity(metrics: dict) -> str:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                return entries[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        return "UNKNOWN"

    @staticmethod
    def _extract_cvss(metrics: dict) -> float:

        for key in (
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            if metrics.get(key):
                return metrics[key][0]["cvssData"]["baseScore"]

        return 0.0
