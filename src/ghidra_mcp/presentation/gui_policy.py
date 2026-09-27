"""Arguments the GUI backend refuses before a call starts (spec §7.4).

Each refusal is ``GUI_UNSUPPORTED`` with ``details.reason``, returned before
any transaction starts, so the call changed nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode

# apply_edits kinds whose before/after snapshots decompile inside the batch's
# transaction; on the GUI's Swing thread that would freeze the GUI (spec §7.2).
DECOMPILING_EDIT_KINDS = ("rename_variable", "set_local_variable_type")


def _refuse(message: str, hint: str, **details: Any) -> DomainError:
    return DomainError(code=ErrorCode.GUI_UNSUPPORTED, message=message, hint=hint, details=details)


class GuiArgumentPolicy:
    """Refuse, per call, the arguments the GUI backend does not support."""

    def __init__(
        self,
        *,
        project_key: tuple[str, str],
        resolve_project_key: Callable[[str, str | None], tuple[str, str]],
    ) -> None:
        self.project_key = project_key
        self._resolve_project_key = resolve_project_key

    def __call__(self, tool: str, arguments: dict[str, Any]) -> None:
        refusal = self.refusal(tool, arguments)
        if refusal is not None:
            raise refusal

    def refusal(self, tool: str, arguments: dict[str, Any]) -> DomainError | None:
        if tool == "apply_edits":
            if arguments.get("dry_run"):
                return _refuse(
                    "apply_edits cannot run with dry_run=true: a dry run rolls back a transaction the human's "
                    "GUI edits could share",
                    "Leave dry_run out and check the change with the read tools",
                    reason="dry_run",
                )
            kinds = sorted(
                {
                    str(edit.get("kind"))
                    for edit in arguments.get("edits") or []
                    if isinstance(edit, dict) and edit.get("kind") in DECOMPILING_EDIT_KINDS
                }
            )
            if kinds:
                return _refuse(
                    f"apply_edits cannot batch {', '.join(kinds)} with the GUI backend: their snapshots decompile "
                    "while the GUI waits",
                    "Rename a variable with the rename_variable tool, change its type with the "
                    "set_local_variable_type tool, and send the other edits without these kinds",
                    reason="edit_kind_decompiles",
                    kinds=kinds,
                )
        elif tool == "load_project_program" and arguments.get("version") is not None:
            return _refuse(
                "load_project_program cannot open a past version with the GUI backend",
                "Leave version out, or open the version in the Ghidra GUI",
                reason="version",
            )
        elif tool == "close_session" and arguments.get("discard_changes"):
            return _refuse(
                "close_session cannot discard changes with the GUI backend: they may include the human's",
                "Leave discard_changes out: close_session then only unbinds the target, and the program stays "
                "open in the GUI",
                reason="discard_changes",
            )
        elif tool in ("open_program", "register_target") and arguments.get("project_location") is not None:
            # An empty location resolves to the working directory, another project.
            try:
                key = self._resolve_project_key(arguments["project_location"], arguments.get("project_name"))
            except (ValueError, OSError, RuntimeError):  # RuntimeError: ~nosuchuser, a symlink loop
                return None  # the call's own validation reports the bad path
            if key != self.project_key:
                return _refuse(
                    f"{tool} can only use the project the Ghidra GUI has open ({self.project_key[1]})",
                    "Use that project's programs, or open the other project in the Ghidra GUI",
                    reason="other_project",
                )
        return None


__all__ = ["DECOMPILING_EDIT_KINDS", "GuiArgumentPolicy"]
