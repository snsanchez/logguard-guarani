"""
- Invocar la CLI oficial de LogGuard.
- Administrar el proceso de análisis.
- Exponer una API simple para la interfaz Textual.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen

from config import TUIConfig

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_ENTRYPOINT = PROJECT_ROOT / "src" / "logguard_guarani.py"
SOC_REPORTS_DIR = PROJECT_ROOT / "soc_agent" / "reports"
EVENTS_FILE = PROJECT_ROOT / "outputs" / "eventos.jsonl"


@dataclass(slots=True)
class RunningProcess:
    process: Popen[str]
    command: list[str]
    started_at: datetime
    description: str


class LogGuardController:
    def __init__(
        self,
        config: TUIConfig,
    ) -> None:

        self.config = config
        self._current_process: RunningProcess | None = None

    @property
    def busy(self) -> bool:
        return self._current_process is not None

    @property
    def current_process(self) -> RunningProcess | None:
        return self._current_process

    def process_finished(
        self,
        process: RunningProcess,
    ) -> None:
        # evita un bug si a futuro implemento dos procesos a la vez
        if self._current_process is process:
            self._current_process = None

    # Internal
    def _start_process(
        self,
        command: list[str],
        description: str,
    ) -> RunningProcess:

        if self.busy:
            raise RuntimeError("Ya existe un proceso ejecutándose.")

        process = Popen(
            command,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            bufsize=1,
        )

        running = RunningProcess(
            process=process,
            command=command,
            started_at=datetime.now(),
            description=description,
        )

        self._current_process = running
        return running

    # Public API
    def run_analysis(
        self,
        logfile: Path,
        *,
        reasoning: bool = False,
        only_anomalies: bool = False,
    ) -> RunningProcess:

        command = [
            sys.executable,
            str(CLI_ENTRYPOINT),
            str(logfile),
        ]

        if reasoning:
            command.append("--razonar")

        if only_anomalies:
            command.append("--solo-anomalos")

        return self._start_process(
            command,
            "Análisis de logs",
        )

    def run_update_knowledge(
        self,
        *,
        online: bool = False,
    ) -> RunningProcess:

        command = [
            sys.executable,
            str(CLI_ENTRYPOINT),
            "--actualizar-conocimiento",
        ]

        if online:
            command.append("--online")

        return self._start_process(
            command,
            "Actualización de base de conocimiento",
        )

    # Reports
    def latest_soc_report(self) -> Path | None:
        reports = sorted(
            SOC_REPORTS_DIR.glob("*.md"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not reports:
            return None

        return reports[0]

    def list_log_files(
        self,
    ) -> list[Path]:

        if self.config.logs_directory is None:
            return []

        if not self.config.logs_directory.exists():
            return []

        extensions = {
            ".log",
            ".1",
            ".2",
            ".3",
            ".4",
            ".5",
        }

        files = []

        for file in self.config.logs_directory.rglob("*"):
            if file.is_file() and any(file.name.endswith(ext) for ext in extensions):
                files.append(file)

        return sorted(files)

    def status(self) -> dict:
        return {
            "logs_directory": self.config.logs_directory,
            "log_count": len(self.list_log_files()),
            "latest_report": self.latest_soc_report(),
            "knowledge_directory": PROJECT_ROOT / "knowledge",
        }

    def events_file(self):

        if EVENTS_FILE.exists():
            return EVENTS_FILE
        return None
