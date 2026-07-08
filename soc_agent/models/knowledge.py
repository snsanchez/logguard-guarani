"""
Domain models representing threat intelligence consumed by the SOC Agent.
These models intentionally abstract the original MITRE ATT&CK, NVD CVE and
CISA KEV formats. The Knowledge Updater is responsible for translating the
official feeds into these lightweight models.
The SOC Agent should never depend on vendor-specific JSON schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from soc_agent.models.base import BaseModel


@dataclass(slots=True)
class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str
    url: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "MitreTechnique":
        """Create a MitreTechnique from a dictionary."""
        return cls(
            technique_id=data["technique_id"],
            name=data["name"],
            tactic=data["tactic"],
            description=data["description"],
            url=data.get("url"),
        )

    @property
    def short_name(self) -> str:
        return f"{self.technique_id} - {self.name}"


@dataclass(slots=True)
class CVEInfo(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "CVEInfo":
        return cls(
            cve_id=data["cve_id"],
            description=data["description"],
            cvss_score=data.get("cvss_score"),
            severity=data.get("severity"),
            published=data.get("published"),
            modified=data.get("modified"),
            references=data.get("references", []),
        )

    @property
    def has_cvss(self) -> bool:
        return self.cvss_score is not None

    @property
    def is_critical(self) -> bool:
        return self.cvss_score is not None and self.cvss_score >= 9.0


# CISA Known Exploited Vulnerabilities
@dataclass(slots=True)
class KEVEntry(BaseModel):
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    ransomware_use: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "KEVEntry":
        return cls(
            cve_id=data["cve_id"],
            vendor=data["vendor"],
            product=data["product"],
            vulnerability_name=data["vulnerability_name"],
            date_added=data["date_added"],
            required_action=data.get("required_action"),
            due_date=data.get("due_date"),
            ransomware_use=data.get("ransomware_use", False),
        )

    @property
    def is_ransomware_related(self) -> bool:
        return self.ransomware_use


# Aggregated Threat Intelligence
@dataclass(slots=True)
class KnowledgeContext:
    """
    Aggregates all threat intelligence associated with an event.
    This object is attached to EnrichedEvent and progressively consumed by the
    SOC Agent tools.
    """

    mitre: list[MitreTechnique] = field(default_factory=list)
    cves: list[CVEInfo] = field(default_factory=list)
    kev: list[KEVEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mitre": [t.to_dict() for t in self.mitre],
            "cves": [c.to_dict() for c in self.cves],
            "kev": [k.to_dict() for k in self.kev],
        }

    @property
    def has_mitre(self) -> bool:
        return bool(self.mitre)

    @property
    def has_cves(self) -> bool:
        return bool(self.cves)

    @property
    def has_kev(self) -> bool:
        return bool(self.kev)

    @property
    def highest_cvss(self) -> Optional[float]:
        scores = [c.cvss_score for c in self.cves if c.cvss_score is not None]

        if not scores:
            return None

        return max(scores)

    @property
    def critical_cves(self) -> list[CVEInfo]:
        return [cve for cve in self.cves if cve.is_critical]

    @property
    def kev_count(self) -> int:
        return len(self.kev)

    @property
    def mitre_count(self) -> int:
        return len(self.mitre)

    @property
    def cve_count(self) -> int:
        return len(self.cves)

    def summary(self) -> dict:
        """
        Returns a compact summary used by the Report Builder.
        """
        return {
            "mitre_count": self.mitre_count,
            "cve_count": self.cve_count,
            "kev_count": self.kev_count,
            "highest_cvss": self.highest_cvss,
            "critical_cves": len(self.critical_cves),
        }
