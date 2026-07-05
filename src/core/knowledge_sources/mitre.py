from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .base import KnowledgeUpdater
from .paths import MITRE_MAPPINGS_FILE

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


class MitreAttackUpdater(KnowledgeUpdater):
    name = "MITRE ATT&CK"
    target_file = MITRE_MAPPINGS_FILE

    def fetch(self) -> Any:
        return self._http_get_json(MITRE_ATTACK_URL)

    def validate(self, data: Any) -> bool:
        return (
            isinstance(data, dict)
            and data.get("type") == "bundle"
            and isinstance(data.get("objects"), list)
            and len(data["objects"]) > 0
        )

    def save(self, data: Any) -> int:
        techniques = []
        for obj in data["objects"]:
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue

            external_id = self._extract_attack_id(obj)
            if not external_id:
                continue

            tactics = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            techniques.append(
                {
                    "id": external_id,
                    "name": obj.get("name", ""),
                    "tactics": tactics,
                }
            )

        payload = {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "count": len(techniques),
            "techniques": techniques,
        }

        self.target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.target_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        return len(techniques)

    @staticmethod
    def _extract_attack_id(obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None
