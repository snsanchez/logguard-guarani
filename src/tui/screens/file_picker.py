from pathlib import Path

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import OptionList


class FilePickerScreen(ModalScreen[Path | None]):
    BINDINGS = [
        ("escape", "cancel", "Cancelar"),
    ]

    def __init__(
        self,
        files: list[Path],
        root: Path,
    ) -> None:

        super().__init__()

        self._files = files
        self._root = root

    def _human_size(self, size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def compose(self) -> ComposeResult:

        menu = OptionList()

        for file in self._files:
            relative = str(file.relative_to(self._root))
            size = self._human_size(file.stat().st_size)

            menu.add_option(f"{relative} ({size})")
        yield menu

    def on_option_list_option_selected(
        self,
        event: OptionList.OptionSelected,
    ) -> None:

        # importante el stop, sino tira de nuevo el modal filepicker
        event.stop()

        self.dismiss(self._files[event.option_index])

    def action_cancel(self) -> None:

        self.dismiss(None)
