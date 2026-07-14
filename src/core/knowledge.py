"""
Public entry point: update_knowledge().

Orchestrates five stages:
    1. verify_knowledge_base()   - local structure/integrity checks
    2-3. synchronize_sources()   - fetch + validate dynamic sources
                                    (each source validates its own data
                                    inside its run(), see
                                    knowledge_sources/base.py)
    4. update_metadata()         - record sync results in metadata.json
    5. print_full_report()       - colored, detailed report


Extensibility:
    To add a new dynamic source (e.g. OWASP):
        1. Create core/knowledge_sources/owasp.py implementing
           KnowledgeUpdater (fetch/validate/save).
        2. Add an instance of it to UPDATER_PIPELINE below.
    update_knowledge() itself never needs to change.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, List

from core.knowledge_sources.base import Result, Status
from core.knowledge_sources.cve import CVEUpdater
from core.knowledge_sources.kev import KEVUpdater
from core.knowledge_sources.mitre import MitreAttackUpdater
from core.knowledge_sources.paths import (
    KNOWLEDGE_DIR,
    METADATA_FILE,
    PLAYBOOKS_DIR,
    REFERENCES_DIR,
    REQUIRED_METADATA_KEYS,
    REQUIRED_SUBDIRS,
)


class Colors:
    OK = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


_STATUS_LABEL = {Status.OK: "OK", Status.WARN: "ADVERTENCIA", Status.FAIL: "ERROR"}
_STATUS_COLOR = {
    Status.OK: Colors.OK,
    Status.WARN: Colors.WARN,
    Status.FAIL: Colors.FAIL,
}


def check_knowledge_directory() -> Result:
    if KNOWLEDGE_DIR.is_dir():
        return Result(
            "Directorio de conocimiento", Status.OK, f"Encontrado en {KNOWLEDGE_DIR}"
        )
    return Result(
        "Directorio de conocimiento", Status.FAIL, f"No existe: {KNOWLEDGE_DIR}"
    )


def check_subdirectories() -> Result:
    missing = [d.name for d in REQUIRED_SUBDIRS if not d.is_dir()]
    if not missing:
        return Result(
            "Subdirectorios requeridos", Status.OK, "Todos los subdirectorios presentes"
        )
    return Result(
        "Subdirectorios requeridos", Status.WARN, f"Faltan: {', '.join(missing)}"
    )


def check_metadata_file() -> Result:
    if not METADATA_FILE.is_file():
        return Result(
            "metadata.json", Status.FAIL, "No se encontró el archivo metadata.json"
        )
    try:
        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        return Result("metadata.json", Status.FAIL, f"JSON inválido: {exc}")

    missing_keys = [k for k in REQUIRED_METADATA_KEYS if k not in data]
    if missing_keys:
        return Result(
            "metadata.json", Status.WARN, f"Faltan claves: {', '.join(missing_keys)}"
        )
    return Result("metadata.json", Status.OK, "Válido y completo")


def check_playbooks() -> Result:
    """Read-only check. Playbooks are static, Git-managed docs and are
    NEVER written to by this module."""
    if not PLAYBOOKS_DIR.is_dir():
        return Result(
            "Playbooks", Status.FAIL, f"Directorio no encontrado: {PLAYBOOKS_DIR}"
        )
    playbooks = list(PLAYBOOKS_DIR.glob("*.*"))
    if not playbooks:
        return Result(
            "Playbooks", Status.WARN, "El directorio existe pero no contiene playbooks"
        )
    return Result("Playbooks", Status.OK, f"{len(playbooks)} playbook(s) encontrado(s)")


def check_references() -> Result:
    if not REFERENCES_DIR.is_dir():
        return Result(
            "Referencias", Status.FAIL, f"Directorio no encontrado: {REFERENCES_DIR}"
        )
    references = list(REFERENCES_DIR.glob("*.*"))
    if not references:
        return Result(
            "Referencias",
            Status.WARN,
            "El directorio existe pero no contiene archivos de referencia",
        )
    return Result(
        "Referencias",
        Status.OK,
        f"{len(references)} archivo(s) de referencia encontrado(s)",
    )


CHECK_PIPELINE: List[Callable[[], Result]] = [
    check_knowledge_directory,
    check_subdirectories,
    check_metadata_file,
    check_playbooks,
    check_references,
]


def verify_knowledge_base() -> List[Result]:
    """Stage 1: local, read-only verification."""
    return [check() for check in CHECK_PIPELINE]


UPDATER_PIPELINE = [
    CVEUpdater(),
    MitreAttackUpdater(),
    KEVUpdater(),
]


def synchronize_sources() -> List[Result]:
    """Stage 2-3: fetch, validate and persist each dynamic source.
    A failure in one updater does not stop the others (see
    KnowledgeUpdater.run() in knowledge_sources/base.py)."""
    return [updater.run() for updater in UPDATER_PIPELINE]


def update_metadata(sync_results: List[Result]) -> Result:
    """Records the outcome of this synchronization run in metadata.json,
    preserving any other existing keys."""
    if METADATA_FILE.is_file():
        try:
            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except json.JSONDecodeError:
            metadata = {}
    else:
        metadata = {}

    metadata.setdefault("version", "1.0.0")
    metadata["last_updated"] = datetime.now(timezone.utc).isoformat()
    metadata.setdefault("sources", {})

    for result in sync_results:
        metadata["sources"][result.source] = {
            "last_synced": datetime.now(timezone.utc).isoformat(),
            "status": result.status.value,
            "message": result.message,
        }

    try:
        METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
    except OSError as exc:
        return Result(
            "metadata.json", Status.FAIL, f"No se pudo escribir metadata.json: {exc}"
        )

    return Result(
        "metadata.json",
        Status.OK,
        "Actualizado con los resultados de la sincronización",
    )


def _print_section(title: str, results: List[Result]) -> None:
    print(f"{Colors.BOLD}{title}{Colors.RESET}")
    for result in results:
        color = _STATUS_COLOR[result.status]
        label = _STATUS_LABEL[result.status]
        print(f"  [{color}{label:^11}{Colors.RESET}] {result.source}: {result.message}")
    print()


def print_full_report(
    verification_results: List[Result],
    sync_results: List[Result],
    metadata_result: Result,
) -> None:
    print(
        f"\n{Colors.BOLD}== Actualización de la base de conocimiento =={Colors.RESET}\n"
    )
    _print_section("1. Verificación local", verification_results)
    _print_section(
        "2-3. Sincronización de fuentes externas (datos dinámicos)", sync_results
    )
    _print_section("4. Actualización de metadata", [metadata_result])
    print(
        f"{Colors.DIM}Nota: los playbooks son documentación estática y no se sincronizan.{Colors.RESET}\n"
    )


def update_knowledge(force_online: bool = False) -> int:
    verification_results = verify_knowledge_base()
    sync_results = []
    if force_online:
        sync_results = [updater.run(force=True) for updater in UPDATER_PIPELINE]
    else:
        sync_results = [updater.run(force=False) for updater in UPDATER_PIPELINE]

    metadata_result = update_metadata(sync_results)

    print_full_report(verification_results, sync_results, metadata_result)

    all_results = verification_results + sync_results + [metadata_result]

    if any(r.status == Status.FAIL for r in all_results):
        return 1
    if any(r.status == Status.WARN for r in all_results):
        return 2
    return 0
