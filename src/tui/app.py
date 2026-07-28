import platform
from pathlib import Path

from commands import MENU_COMMANDS, CommandID
from config import ConfigManager
from controller import LogGuardController, RunningProcess
from rich.text import Text
from screens.file_picker import FilePickerScreen
from screens.path_input import PathInputScreen
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Label, OptionList, RichLog
from widgets.logo import RESTING, LogoWidget


class LogGuardApp(App):
    CSS_PATH = "theme.tcss"

    TITLE = "LogGuard Guaraní"

    SUB_TITLE = "v4"

    BINDINGS = [
        ("q", "quit", "Salir"),
        ("ctrl+l", "clear_console", "Limpiar"),
    ]

    def __init__(self) -> None:

        super().__init__()

        self.config_manager = ConfigManager()

        self.config = self.config_manager.load()

        self.controller = LogGuardController(
            self.config,
        )

    def compose(self) -> ComposeResult:

        yield Header()

        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label(
                    "LogGuard",
                    id="sidebar-title",
                )

                menu = OptionList(id="menu")

                for command in MENU_COMMANDS:
                    menu.add_option(f"{command.title}")

                yield menu

                yield LogoWidget(
                    RESTING,
                    id="logo",
                )

            with Vertical(id="main"):
                yield Label(
                    "Estado: Listo",
                    id="status",
                )

                yield RichLog(
                    id="console",
                    wrap=True,
                    highlight=True,
                )

        yield Footer()

    def show_welcome(self) -> None:

        console = self.query_one("#console", RichLog)

        console.clear()

        console.write("LogGuard Guaraní v4")
        console.write("")
        console.write(
            "Sistema de análisis defensivo de logs Apache para el SIU Guaraní."
        )
        console.write("")
        console.write(
            "Asegurese de configurar la carpeta de logs y el API de Gemini antes de usar LogGuard Guaraní, puede consultar el menú para ver cómo hacerlo."
        )
        console.write("")
        console.write("Seleccione una opción del menú para comenzar.")

    def update_status(
        self,
        status: str,
    ) -> None:

        label = self.query_one("#status", Label)
        logs_dir = self.config.logs_directory
        if logs_dir is None:
            location = "Sin configurar"
        else:
            location = self._short_path(logs_dir)
        label.update(f"Estado: {status:<18}{location}")

    def _short_path(
        self,
        path: Path,
    ) -> str:
        text = str(path)
        MAX = 40
        if len(text) <= MAX:
            return text
        return "..." + text[-(MAX - 3) :]

    def on_mount(self) -> None:
        menu = self.query_one("#menu", OptionList)
        menu.highlighted = 0
        self.show_welcome()
        self.update_status("Listo")

    def action_clear_console(self):

        console = self.query_one("#console", RichLog)

        console.clear()

    def show_info(self):

        console = self.query_one("#console", RichLog)

        console.clear()

        console.write("")
        console.write("Repositorio")
        console.write("  https://github.com/snsanchez/logguard-guarani")
        console.write("")
        console.write("Documentación")
        console.write("  https://snsanchez.github.io/logguard-guarani/")
        console.write("")
        console.write("Licencia")
        console.write("  GPL v3")
        console.write("")
        console.write("Autor")
        console.write("  Santiago Sánchez")

    def show_configure_soc(self):

        console = self.query_one("#console", RichLog)

        console.clear()

        console.write("")
        console.write("Para habilitar el SOC Agent cree un archivo")
        console.write("  .env")
        console.write("")
        console.write("en la raíz del proyecto con:")
        console.write("  GEMINI_MODEL=gemini-2.5-flash-lite")
        console.write("  GOOGLE_API_KEY=xxxxxxxxxxxxxxxx")
        console.write("")
        console.write("Asegurese que no haya espacios luego del '='")
        console.write("")
        console.write("Puede obtener una API Key gratuita desde:")
        console.write(" https://aistudio.google.com/app/apikey")

    def show_status(self):

        console = self.query_one("#console", RichLog)
        console.clear()
        status = self.controller.status()

        console.write("Estado de LogGuard")
        console.write("")
        console.write(f"Python              : {platform.python_version()}")
        console.write(f"Sistema             : {platform.system()}")
        console.write(f"Release             : {platform.release()}")
        console.write(f"Arquitectura        : {platform.machine()}")
        console.write("")
        console.write(
            f"Carpeta de logs     : {status['logs_directory'] or 'No configurada'}"
        )
        console.write(f"Archivos encontrados: {status['log_count']}")
        console.write(f"Base de conocimiento: {status['knowledge_directory']}")
        console.write(f"Último reporte SOC  : {status['latest_report'] or 'Ninguno'}")

    def show_cron_help(self):

        console = self.query_one("#console", RichLog)

        console.clear()

        console.write("Automatice los análisis con cron")
        console.write("")
        console.write("Ejecute:")
        console.write("")
        console.write("    crontab -e")
        console.write("")
        console.write("Y agregue una línea al final similar a:")
        console.write("")
        console.write("0 8,20 * * * python3 src/logguard_guarani.py access.log")

    def show_not_implemented(
        self,
        command: CommandID,
    ) -> None:

        console = self.query_one("#console", RichLog)

        console.clear()

        console.write(f"{command.value}")
        console.write("")
        console.write("Esta funcionalidad se implementará en la siguiente iteración.")

    @work(thread=True)
    def run_process(
        self,
        process: RunningProcess,
    ):
        console = self.query_one("#console", RichLog)
        console.clear()
        console.write("Aguarde un momento...")
        console.write("")
        self.call_from_thread(
            self.update_status,
            process.description,
        )
        assert process.process.stdout is not None
        for line in process.process.stdout:
            self.call_from_thread(
                console.write,
                # from_ansi para que renderice la salida a color
                Text.from_ansi(line.rstrip()),
            )
        process.process.wait()
        self.controller.process_finished(process)
        self.call_from_thread(
            self.update_status,
            "Listo",
        )

    def on_file_selected(
        self,
        path: Path | None,
    ) -> None:

        if path is None:
            return

        process = self.controller.run_analysis(path)

        # self.set_timer(0,lambda: self.run_process(process))
        self.call_after_refresh(self.run_process, process)

    def select_log_file(self) -> None:

        files = self.controller.list_log_files()

        if not files:
            console = self.query_one("#console", RichLog)

            console.clear()

            console.write("No se encontraron archivos de log.")

            return

        self.push_screen(
            FilePickerScreen(files, self.config.logs_directory),
            self.on_file_selected,
        )

    # CONFIGURAR CARPETA FUENTE DE LOGS
    def on_logs_directory_selected(
        self,
        path: Path | None,
    ) -> None:
        if path is None:
            return
        self.config.logs_directory = path
        self.config_manager.save()
        console = self.query_one("#console", RichLog)
        console.clear()
        console.write("Carpeta configurada correctamente.")
        console.write("")
        console.write(str(path))

    def configure_logs_directory(self):
        self.push_screen(
            PathInputScreen(),
            self.on_logs_directory_selected,
        )
        self.update_status("Listo")

    def update_knowledge(
        self,
        online: bool = False,
    ):
        process = self.controller.run_update_knowledge(
            online=online,
        )
        self.run_process(process)

    def open_last_report(self):
        console = self.query_one("#console", RichLog)
        console.clear()
        report = self.controller.latest_soc_report()
        if report is None:
            console.write("No existe ningún SOC Report.")
            return

        from rich.markdown import Markdown

        text = report.read_text(encoding="utf-8")
        console.write(Markdown(text))

    # EJECUTAR LOS COMANDOS DEL MENU
    def execute_command(
        self,
        command: CommandID,
    ) -> None:

        match command:
            case CommandID.UPDATE_KNOWLEDGE:
                self.update_knowledge(online=False)

            case CommandID.UPDATE_KNOWLEDGE_ONLINE:
                self.update_knowledge(online=True)

            case CommandID.OPEN_LAST_REPORT:
                self.open_last_report()

            case CommandID.INFO:
                self.show_info()

            case CommandID.API:
                self.show_configure_soc()

            case CommandID.STATUS:
                self.show_status()

            case CommandID.CRON_HELP:
                self.show_cron_help()

            case CommandID.EXIT:
                self.exit()

            case CommandID.ANALYZE:
                self.select_log_file()

            case CommandID.LOG_DIRECTORY:
                self.configure_logs_directory()

            case CommandID.CLEAR_CONSOLE:
                self.action_clear_console()

            case _:
                self.show_not_implemented(command)

    def on_option_list_option_selected(
        self,
        event: OptionList.OptionSelected,
    ) -> None:

        command = MENU_COMMANDS[event.option_index]

        self.execute_command(command.id)


if __name__ == "__main__":
    LogGuardApp().run()
