"""
Defines the lifecycle stages of a SOC analysis.
This is used to track the progression of an event through the SOC Agent
pipeline.
"""

from enum import Enum


class AnalysisStage(Enum):
    CREATED = "CREATED"

    KNOWLEDGE_ENRICHED = "KNOWLEDGE_ENRICHED"

    ANALYZING = "ANALYZING"

    REPORT_READY = "REPORT_READY"

    FAILED = "FAILED"
