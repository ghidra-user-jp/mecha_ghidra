"""Data models for program sessions."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING, Dict

from .path_utils import _domain_path

if TYPE_CHECKING:
    from .project_handle import ProjectHandle


class ProgramSession:
    """Represents an opened Ghidra program (binary or project backed)."""

    def __init__(
        self,
        flat_api,
        program,
        project_handle: "ProjectHandle",
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self.project_handle: Optional["ProjectHandle"] = project_handle

    def get_program(self):
        if self.program is None:
            raise RuntimeError("Session is already closed")
        return self.program

    def get_project_handle(self) -> "ProjectHandle":
        if self.project_handle is None:
            raise RuntimeError("Session is already closed")
        return self.project_handle

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        if self.project_handle is None:
            raise RuntimeError("Session is already closed")

        def _mark_closed() -> None:
            self.project_handle = None
            self.flat_api = None
            self.program = None

        try:
            self.project_handle.release_program(self.program, save=save, remove_program=remove_program)
        except Exception as exc:
            message = str(exc)
            if message.startswith("SESSION_CLOSE_FAILED:") or message.startswith("REMOVE_PROGRAM_FAILED:"):
                _mark_closed()
            raise

        _mark_closed()

    def to_dict(self) -> Dict[str, Optional[str]]:
        project_name: Optional[str] = None
        project_location: Optional[str] = None
        domain_path: Optional[str] = _domain_path(self.program)

        handle = self.get_project_handle()
        project_name = handle.get_project_name()
        project_location = handle.get_project_location()

        return {
            "project_name": project_name,
            "project_location": project_location,
            "domain_path": domain_path,
        }


__all__ = ["ProgramSession"]
