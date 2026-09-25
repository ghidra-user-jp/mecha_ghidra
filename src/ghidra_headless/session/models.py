"""Data models for program sessions."""

from __future__ import annotations

import itertools
import threading
from typing import TYPE_CHECKING, Dict, Optional

from ghidra_headless.errors import error_code_of

from .path_utils import _domain_path

if TYPE_CHECKING:
    from .project_handle import ProjectHandle

_SERIALS = itertools.count(1)


def program_is_analyzed(program) -> bool:
    """Whether Ghidra's auto-analysis has marked ``program`` as analyzed.

    Only an existing option is read: ``getBoolean`` on a missing option would
    register it, which is a write and needs a transaction.
    """
    options = program.getOptions("Program Information")
    return bool(options.contains("Analyzed") and options.getBoolean("Analyzed", False))


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
        # Unique per session object: a reload or reopen always gets a new one,
        # so a job accepted for this session can tell it was replaced.
        self.serial = next(_SERIALS)
        self._close_lock = threading.Lock()
        # Read once while the opener holds the target lock, so to_dict() and
        # list_targets never call into Ghidra or wait for that lock.
        self.project_name: Optional[str] = getattr(project_handle, "project_name", None)
        self.project_location: Optional[str] = getattr(project_handle, "project_location", None)
        self.domain_path: Optional[str] = None
        self.refresh_domain_path()

    @property
    def is_read_only(self) -> bool:
        return self.read_only_version is not None

    def get_program(self):
        if self.program is None:
            raise RuntimeError("Session is already closed")
        return self.program

    def is_analyzed(self) -> bool:
        return program_is_analyzed(self.get_program())

    def get_project_handle(self) -> "ProjectHandle":
        if self.project_handle is None:
            raise RuntimeError("Session is already closed")
        return self.project_handle

    def refresh_domain_path(self) -> None:
        """Re-read the program's project path; call with the target lock held.

        The path does not change while a program is open through the server's
        own tools; only a script can rename the file.
        """
        try:
            path = _domain_path(self.program)
        except Exception:
            # A program object without a DomainFile (test doubles) has no path.
            return
        if path:
            self.domain_path = path

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
        """Describe the session from values captured at open; never calls into Ghidra."""
        info: Dict[str, Optional[str]] = {
            "project_name": self.project_name,
            "project_location": self.project_location,
            "domain_path": self.domain_path,
        }
        if self.read_only_version is not None:
            info["read_only_version"] = self.read_only_version  # type: ignore[assignment]
        return info


__all__ = ["ProgramSession", "program_is_analyzed"]
