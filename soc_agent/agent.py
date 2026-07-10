from __future__ import annotations

import uuid
from pathlib import Path

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .builders import ReportBuilder
from .models.agent_analysis import AgentAnalysis
from .models.analysis import AnalysisContext
from .prompt_builder import ContextSerializer
from .tools import event_reader, knowledge_lookup


class SOCAgent:
    def __init__(
        self,
        model: str = "gemini-2.5-flash",
    ) -> None:

        self._builder = ReportBuilder()

        self._agent = Agent(
            name="logguard_soc_agent",
            model=model,
            instruction=self._load_system_prompt(),
            output_schema=AgentAnalysis,
        )

        self._session_service = InMemorySessionService()

        self._runner = Runner(
            agent=self._agent,
            app_name="logguard",
            session_service=self._session_service,
        )

    @staticmethod
    def _load_system_prompt() -> str:

        path = Path(__file__).parent / "prompts" / "system_prompt.md"

        return path.read_text(encoding="utf-8")

    def build_prompt(
        self,
        context: AnalysisContext,
    ) -> str:

        event = event_reader(context.event)

        knowledge = knowledge_lookup(context)

        return ContextSerializer.serialize(
            event,
            knowledge,
        )

    async def analyze(
        self,
        context: AnalysisContext,
    ):

        prompt = self.build_prompt(context)

        analysis = await self._run_llm(prompt)

        return self._builder.build(
            context=context,
            analysis=analysis,
        )

    async def _run_llm(
        self,
        prompt: str,
    ) -> AgentAnalysis:
        user_id = "logguard"

        session_id = str(uuid.uuid4())

        await self._session_service.create_session(
            app_name="logguard",
            user_id=user_id,
            session_id=session_id,
        )

        message = types.Content(
            role="user",
            parts=[types.Part(text=prompt)],
        )

        async for event in self._runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=message,
        ):
            if event.is_final_response():
                if event.content is None or not event.content.parts:
                    raise RuntimeError("SOC Agent final response had no content")
                output = event.content.parts[0].text
                if output is None:
                    raise RuntimeError("SOC Agent final response had no text")
                return AgentAnalysis.model_validate_json(output)
        raise RuntimeError("SOC Agent did not produce a final response")
