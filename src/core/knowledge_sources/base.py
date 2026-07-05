"""
To add a new source:
    1. Create core/knowledge_sources/<source>.py
    2. Implement a class inheriting KnowledgeUpdater with fetch(),
       validate(data) and save(data)
    3. Register an instance of it in core/knowledge.py's
       UPDATER_PIPELINE list
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_USER_AGENT = "LogGuardGuarani/2.0 (+educational-log-analyzer)"


class Status(Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class Result:
    source: str
    status: Status
    message: str


class KnowledgeUpdater(ABC):
    """
    fetch()    -> retrieves raw data from the external source
    validate() -> returns True if the fetched data is well-formed
    save()     -> persists the data locally and returns the number
                  of records written (used for reporting)

    run() ties these together and never raises: any failure at any
    stage is converted into a Result with Status.FAIL, so one broken
    source cannot abort synchronization of the others.
    """

    name: str
    target_file: Path

    @abstractmethod
    def fetch(self) -> Any: ...

    @abstractmethod
    def validate(self, data: Any) -> bool: ...

    @abstractmethod
    def save(self, data: Any) -> int: ...

    def _http_get_json(self, url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Any:
        """Shared helper for the common case of fetching a JSON endpoint."""
        import json

        request = Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
        return json.loads(raw)

    # cache awareness opcional
    def run(self, force: bool = False) -> Result:
        try:
            # Cache skip (if file exists and is fresh)
            if not force and hasattr(self, "target_file"):
                from .cache_policy import is_cache_fresh

                if is_cache_fresh(self.target_file):
                    return Result(
                        self.name,
                        Status.OK,
                        "Cache vigente (skip sync)",
                    )

            data = self.fetch()

        except Exception as exc:
            return Result(self.name, Status.FAIL, f"Error al descargar datos: {exc}")

        try:
            if not self.validate(data):
                return Result(self.name, Status.FAIL, "Validación fallida")
        except Exception as exc:
            return Result(self.name, Status.FAIL, f"Error validando: {exc}")

        try:
            count = self.save(data)
        except Exception as exc:
            return Result(self.name, Status.FAIL, f"Error guardando: {exc}")

        return Result(self.name, Status.OK, f"OK ({count} registros)")
