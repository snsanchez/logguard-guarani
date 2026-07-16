from __future__ import annotations

import os
import uuid
from pathlib import Path

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .builders import ReportBuilder
from .models.agent_analysis import AgentAnalysis
from .models.analysis import AnalysisContext
from .prompt_builder import ContextSerializer
from .recommendation_engine import RecommendationEngine
from .reports.writer import ReportWriter
from .tools import event_reader

load_dotenv()

MODEL_NAME = os.getenv(
    "GEMINI_MODEL",
    "gemini-2.5-flash-lite",
)

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    raise RuntimeError("GOOGLE_API_KEY no está configurada.")


class SOCAgent:
    def __init__(
        self,
        model: str = MODEL_NAME,
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

        self._recommendations = RecommendationEngine()

        self._writer = ReportWriter()

    @staticmethod
    def _load_system_prompt() -> str:

        path = Path(__file__).parent / "prompts" / "system_prompt.md"

        return path.read_text(encoding="utf-8")

    def build_prompt(
        self,
        context: AnalysisContext,
    ) -> str:

        return ContextSerializer.serialize(
            event_reader(context.event),
            context.event.knowledge,
        )

    async def analyze(
        self,
        context: AnalysisContext,
    ):
        for recommendation in self._recommendations.generate(context):
            context.add_recommendation(recommendation)

        prompt = self.build_prompt(context)

        analysis = await self._run_llm(prompt)

        report = self._builder.build(
            context=context,
            analysis=analysis,
        )

        self._writer.save_markdown(report)

        return report

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

                output = output.strip()
                if output.startswith("```"):
                    output = output.removeprefix("```json")
                    output = output.removeprefix("```")
                    output = output.removesuffix("```")
                    output = output.strip()

                return AgentAnalysis.model_validate_json(output)
        raise RuntimeError("SOC Agent did not produce a final response")
