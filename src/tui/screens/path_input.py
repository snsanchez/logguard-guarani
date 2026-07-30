from pathlib import Path

from config import DEFAULT_LOG_DIR
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label


class PathInputScreen(ModalScreen[Path | None]):
    BINDINGS = [
        ("escape", "cancel", "Cancelar"),
    ]

    def compose(self) -> ComposeResult:

        with Vertical(id="modal-box"):
            yield Label(
                "Configurar carpeta de logs",
                id="modal-title",
            )

            yield Label(
                "Ingrese el directorio donde LogGuard buscará los archivos.",
                id="modal-description",
            )

            yield Input(
                placeholder="/var/log/apache2",
                id="path-input",
            )

            with Horizontal(id="buttons"):
                yield Button(
                    "Guardar",
                    id="save-path",
                    variant="primary",
                )

                yield Button(
                    "Por defecto",
                    id="default-path",
                    variant="default",
                )

    def on_button_pressed(
        self,
        event: Button.Pressed,
    ) -> None:

        if event.button.id == "default-path":
            self.dismiss(DEFAULT_LOG_DIR)
            return

        text = self.query_one(
            "#path-input",
            Input,
        ).value.strip()

        if not text:
            self.notify(
                "Ingrese una carpeta o utilice 'Por defecto'.",
                severity="warning",
            )
            return

        path = Path(text).expanduser().resolve()

        if not path.exists():
            self.notify(
                "La carpeta no existe.",
                severity="error",
            )
            return

        if not path.is_dir():
            self.notify(
                "La ruta no es un directorio.",
                severity="error",
            )
            return

        self.dismiss(path)

    def action_cancel(self):

        self.dismiss(None)
