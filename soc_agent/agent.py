from __future__ import annotations

from pathlib import Path

from google.adk.agents import Agent

from .tools import (
    event_reader,
    knowledge_lookup,
)

PROMPT_PATH = Path(__file__).parent / "prompts" / "system_prompt.md"


def load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def create_soc_agent() -> Agent:
    return Agent(
        name="logguard_soc_agent",
        model="gemini-2.5-flash",
        instruction=load_system_prompt(),
        tools=[
            event_reader,
            knowledge_lookup,
        ],
    )
