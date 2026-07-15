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
            if obj.get("type") != "attack-pattern":
                continue

            if obj.get("revoked"):
                continue

            attack_id = self._extract_attack_id(obj)

            if attack_id is None:
                continue

            techniques.append(
                {
                    "id": attack_id,
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "tactics": [
                        phase.get("phase_name")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ],
                }
            )

        payload = {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "count": len(techniques),
            "techniques": techniques,
        }

        self.target_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.target_file, "w", encoding="utf-8") as f:
            json.dump(
                payload,
                f,
                indent=2,
                ensure_ascii=False,
            )

        mapping = {}

        for tech in techniques:
            name = tech["name"].lower()

            if "sql" in name:
                mapping["INJECTION"] = {
                    "technique": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactics"][0] if tech["tactics"] else "",
                    "description": tech["description"],
                }

            elif "path traversal" in name:
                mapping["PATH_TRAVERSAL"] = {
                    "technique": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactics"][0] if tech["tactics"] else "",
                    "description": tech["description"],
                }

            elif "scan" in name:
                mapping["SCANNER"] = {
                    "technique": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactics"][0] if tech["tactics"] else "",
                    "description": tech["description"],
                }

        # Fallbacks conocidos para no depender del nombre exacto del ATT&CK
        mapping.setdefault(
            "INJECTION",
            {
                "technique": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Attackers exploit vulnerabilities in internet-facing applications.",
            },
        )

        mapping.setdefault(
            "PATH_TRAVERSAL",
            {
                "technique": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Attackers exploit vulnerabilities in internet-facing applications.",
            },
        )

        mapping.setdefault(
            "SCANNER",
            {
                "technique": "T1595",
                "name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": "Attackers actively scan public services before exploitation.",
            },
        )

        mapping_file = self.target_file.parent / "attack_mapping.json"

        with open(mapping_file, "w", encoding="utf-8") as f:
            json.dump(
                mapping,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return len(techniques)

    @staticmethod
    def _extract_attack_id(obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None
