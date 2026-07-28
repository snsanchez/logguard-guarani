from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class CommandCategory(str, Enum):
    CONFIGURATION = "Configuración"
    KNOWLEDGE = "Base de conocimiento"
    ANALYSIS = "Análisis"
    EXPORT = "Exportación"
    AUTOMATION = "Automatización"
    SYSTEM = "Sistema"


class CommandID(str, Enum):
    # Identificadores internos. Nunca deben mostrarse al usuario.

    LOG_DIRECTORY = "log_directory"

    UPDATE_KNOWLEDGE = "update_knowledge"

    UPDATE_KNOWLEDGE_ONLINE = "update_knowledge_online"

    ANALYZE = "analyze"

    EXPORT_EVENTS = "export_events"

    OPEN_LAST_REPORT = "open_last_report"

    CRON_HELP = "cron_help"

    INFO = "info"

    API = "api"

    STATUS = "status"

    CLEAR_CONSOLE = "clear_console"

    EXIT = "exit"


class MenuCommand(BaseModel):
    id: CommandID
    category: CommandCategory
    title: str
    description: str


MENU_COMMANDS: list[MenuCommand] = [
    # CONFIGURACIÓN
    MenuCommand(
        id=CommandID.LOG_DIRECTORY,
        category=CommandCategory.CONFIGURATION,
        title="Configurar carpeta de logs",
        description="Configurar el directorio donde buscar archivos de log.",
    ),
    # BASE DE CONOCIMIENTO
    MenuCommand(
        id=CommandID.UPDATE_KNOWLEDGE,
        category=CommandCategory.KNOWLEDGE,
        title="Actualizar (local)",
        description="Verificar y actualizar la base de conocimiento local.",
    ),
    MenuCommand(
        id=CommandID.UPDATE_KNOWLEDGE_ONLINE,
        category=CommandCategory.KNOWLEDGE,
        title="Actualizar (online)",
        description="Sincronizar MITRE, CVEs y KEV desde las fuentes oficiales.",
    ),
    # ANÁLISIS
    MenuCommand(
        id=CommandID.ANALYZE,
        category=CommandCategory.ANALYSIS,
        title="Analizar archivo",
        description="Ejecutar el pipeline completo de LogGuard.",
    ),
    # EXPORTACIÓN
    MenuCommand(
        id=CommandID.OPEN_LAST_REPORT,
        category=CommandCategory.EXPORT,
        title="Abrir último SOC Report",
        description="Mostrar el informe Markdown más reciente.",
    ),
    # AUTOMATIZACIÓN
    MenuCommand(
        id=CommandID.CRON_HELP,
        category=CommandCategory.AUTOMATION,
        title="Programar análisis",
        description="Mostrar un ejemplo para automatizar análisis periódicos.",
    ),
    MenuCommand(
        id=CommandID.INFO,
        category=CommandCategory.SYSTEM,
        title="Info de LogGuard",
        description="Información del proyecto, licencia y documentación.",
    ),
    MenuCommand(
        id=CommandID.API,
        category=CommandCategory.SYSTEM,
        title="Configurar API de Gemini",
        description="Configurar el APIKEY para el SOC Agent.",
    ),
    # SISTEMA
    MenuCommand(
        id=CommandID.STATUS,
        category=CommandCategory.SYSTEM,
        title="Estado del sistema",
        description="Mostrar información general del sistema.",
    ),
    MenuCommand(
        id=CommandID.CLEAR_CONSOLE,
        category=CommandCategory.SYSTEM,
        title="Limpiar consola",
        description="Borrar el contenido de la consola.",
    ),
    MenuCommand(
        id=CommandID.EXIT,
        category=CommandCategory.SYSTEM,
        title="Salir",
        description="Cerrar LogGuard TUI.",
    ),
]
