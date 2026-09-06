"""Data models for program sessions."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Dict, Optional

from ghidra_headless.errors import error_code_of

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
        *,
        read_only_version: Optional[int] = None,
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self.project_handle: Optional["ProjectHandle"] = project_handle
        # Set when the session holds a past repository version opened read-only
        # (``load_project_program(version=N)``); mutating commands must refuse it.
        self.read_only_version: Optional[int] = None if read_only_version is None else int(read_only_version)
        self._close_lock = threading.Lock()

    @property
    def is_read_only(self) -> bool:
        return self.read_only_version is not None

    def get_program(self):
        if self.program is None:
            raise RuntimeError("Session is already closed")
        return self.program

    def get_project_handle(self) -> "ProjectHandle":
        if self.project_handle is None:
            raise RuntimeError("Session is already closed")
        return self.project_handle

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        # Serialize concurrent closes: without the lock two callers can both pass
        # the closed check and double-release the program, decrementing the
        # project handle's refcount twice and closing the project out from under
        # any other session that shares it.
        with self._close_lock:
            if self.project_handle is None:
                raise RuntimeError("Session is already closed")

            def _mark_closed() -> None:
                self.project_handle = None
                self.flat_api = None
                self.program = None

            try:
                self.project_handle.release_program(self.program, save=save, remove_program=remove_program)
            except Exception as exc:
                if error_code_of(exc) in {"SESSION_CLOSE_FAILED", "REMOVE_PROGRAM_FAILED"}:
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

        info: Dict[str, Optional[str]] = {
            "project_name": project_name,
            "project_location": project_location,
            "domain_path": domain_path,
        }
        if self.read_only_version is not None:
            info["read_only_version"] = self.read_only_version  # type: ignore[assignment]
        return info


__all__ = ["ProgramSession"]
