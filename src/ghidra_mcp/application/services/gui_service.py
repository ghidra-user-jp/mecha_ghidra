"""The GUI tools (``get_gui_context``, ``show_in_gui``); only the Ghidra GUI backend publishes them."""

from __future__ import annotations

from typing import Any, Protocol


class GuiRuntimePort(Protocol):
    def get_gui_context(self) -> dict[str, Any]: ...

    def show_in_gui(self, name: str, *, address: str | None = None, function_name: str | None = None) -> dict: ...


class GuiService:
    """Read what the human sees in the GUI, and show a target's program there (spec §8, §9)."""

    def __init__(self, runtime: GuiRuntimePort) -> None:
        self._runtime = runtime

    def get_gui_context(self) -> dict[str, Any]:
        return self._runtime.get_gui_context()

    def show_in_gui(self, name: str, *, address: str | None = None, function_name: str | None = None) -> dict:
        return self._runtime.show_in_gui(name, address=address, function_name=function_name)


__all__ = ["GuiRuntimePort", "GuiService"]
