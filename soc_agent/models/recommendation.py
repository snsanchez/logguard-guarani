"""
Recommendation models used by the SOC Agent.
Recommendations are deterministic defensive actions generated from the
evidence already produced by LogGuard.

The LLM does not invent recommendations; it only explains them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional


class RecommendationPriority(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendationCategory(Enum):
    PATCHING = "Patching"

    MONITORING = "Monitoring"

    HARDENING = "Hardening"

    LOG_REVIEW = "Log Review"

    ACCESS_CONTROL = "Access Control"

    NETWORK = "Network"

    FORENSICS = "Forensics"

    CONFIGURATION = "Configuration"

    GENERAL = "General"


@dataclass(slots=True)
class Recommendation:
    """
    These recommendations should come from deterministic rules
    (for example, based on MITRE techniques or CVEs), not from the LLM.
    """

    title: str

    description: str

    priority: RecommendationPriority

    category: RecommendationCategory

    reference: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["priority"] = self.priority.value
        return data

    @property
    def is_critical(self) -> bool:
        return self.priority is RecommendationPriority.CRITICAL

    @property
    def is_high_priority(self) -> bool:
        return self.priority in (
            RecommendationPriority.HIGH,
            RecommendationPriority.CRITICAL,
        )

    @property
    def short_description(self) -> str:
        """
        Returns a compact representation useful for summaries.
        """
        return f"{self.title} ({self.priority.value})"
