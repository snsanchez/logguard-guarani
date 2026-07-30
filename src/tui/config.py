from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator

APP_NAME = "logguard_guarani"
CONFIG_DIR = Path.home() / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = PROJECT_ROOT / "examples"


class TUIConfig(BaseModel):
    version: int = Field(default=1)
    logs_directory: Path | None = None

    @field_validator("logs_directory")
    @classmethod
    def validate_logs_directory(cls, value):
        if value is None:
            return value
        return value.expanduser().resolve()

    @property
    def effective_logs_directory(self) -> Path:
        return self.logs_directory or DEFAULT_LOG_DIR


class ConfigManager:
    def __init__(
        self,
        config_path: Path = CONFIG_FILE,
    ) -> None:

        self._config_path = config_path

        self._config = TUIConfig()

    @property
    def config(self) -> TUIConfig:
        return self._config

    def load(self) -> TUIConfig:

        CONFIG_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not self._config_path.exists():
            self.save()
            return self._config

        try:
            data = json.loads(
                self._config_path.read_text(
                    encoding="utf-8",
                )
            )

            self._config = TUIConfig.model_validate(data)

        except (
            json.JSONDecodeError,
            ValidationError,
            OSError,
        ):
            self._config = TUIConfig()

            self.save()

        return self._config

    def save(self) -> None:
        CONFIG_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._config_path.write_text(
            self._config.model_dump_json(
                indent=4,
            ),
            encoding="utf-8",
        )

    def reset(self) -> None:
        self._config = TUIConfig()
        self.save()
