"""The project handle of the GUI backend: it borrows the GUI's project and programs (spec §5.3).

It keeps ``ProjectHandle``'s surface, so the runtime above it is unchanged,
and inherits every read of the project data (listing programs, sync status,
file IDs).  What differs is ownership:

- the project is the one GhidraRun opened (``AppInfo.getActiveProject()``);
  the handle never opens, saves through ``GhidraProject`` or closes it;
- a program opens through the GUI's ProgramManager (``programs.open_in_gui``),
  or is the one a GUI tool already has open;
- releasing a program only unbinds it from its target: no save (the default
  ``ProgramSession.close(save=True)`` must not save the human's work) and no
  release of the GUI's own consumer;
- import, versioning and deleting files are GUI_UNSUPPORTED: the human does
  them with the GUI's own commands.
"""

from __future__ import annotations

import logging
import os
import pathlib
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Optional

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import java_bindings, path_utils
from ghidra_headless.session.models import ProgramSession
from ghidra_headless.session.project_handle import ProjectHandle

from .edt import modal_dialog_titles
from .programs import is_open_in_gui, open_in_gui, save_in_gui

logger = logging.getLogger(__name__)


def active_gui_project():
    """The project the Ghidra GUI has open, or None."""
    from ghidra.framework.main import AppInfo

    return AppInfo.getActiveProject()


class _RuntimeProject:
    """The project the startup saw GhidraRun open for this runtime (spec §5.1)."""

    java_project = None


def bind_runtime_project(java_project) -> None:
    _RuntimeProject.java_project = java_project


def runtime_project():
    """The runtime's project while the GUI has it open, else None: the runtime is CLOSED for good.

    A reopened project does not count: Ghidra makes a new project object, and
    a ``DefaultProject`` equals only itself (spec §5.1).
    """
    project = _RuntimeProject.java_project
    active = active_gui_project()
    if project is None or active is None or not active.equals(project):
        return None
    return project


def project_closed_error() -> HeadlessError:
    return HeadlessError(
        "SESSION_NOT_FOUND: the Ghidra GUI closed this server's project; exit Ghidra and start the server again",
        details={"reason": "gui_project_closed"},
    )


def native_project_location(location: str, *, windows: bool = os.name == "nt") -> str:
    """``ProjectLocator.getLocation()`` as a path of this OS.

    Ghidra always writes the location with ``/``, and a Windows drive path as
    ``/C:/a/b``; pathlib would read that leading slash as the current drive's root.
    """
    if windows and len(location) >= 3 and location[0] == "/" and location[1].isalpha() and location[2] == ":":
        return location[1:]
    return location


def is_same_project(java_project, project_location: str, project_name: str) -> bool:
    locator = java_project.getProjectLocator()
    location = pathlib.Path(native_project_location(str(locator.getLocation()))).expanduser().resolve()
    return str(locator.getName()) == project_name and location == pathlib.Path(project_location).resolve()


def _new_consumer():
    """A consumer of Mecha's own: ``DomainObject.release`` removes the first consumer equal to it."""
    from java.lang import Object

    return Object()


def _unsupported(what: str, reason: str) -> HeadlessError:
    return HeadlessError(
        f"GUI_UNSUPPORTED: {what} is not available with the Ghidra GUI backend; use the Ghidra GUI for it",
        details={"reason": reason},
    )


class _GuiProjectView:
    """The subset of ``GhidraProject`` that the inherited reads use, backed by the GUI's project."""

    def __init__(self, java_project) -> None:
        self._java_project = java_project

    def getProjectData(self):
        return self._java_project.getProjectData()

    def getProject(self):
        return self._java_project

    def save(self, _program) -> None:
        raise _unsupported("saving through GhidraProject", "gui_owned_program")

    def close(self, *_args) -> None:
        raise _unsupported("closing the GUI's project", "gui_owned_project")

    def openProgram(self, *_args):
        raise _unsupported("opening a program outside the GUI", "gui_owned_program")


class GuiProjectHandle(ProjectHandle):
    """``ProjectHandle`` for the project the Ghidra GUI owns."""

    # Its programs are the GUI's live objects: reloading one means nothing to
    # reopen, and nothing may be saved on the human's behalf.
    live_programs = True

    def __init__(self, project_location: str, project_name: Optional[str]) -> None:
        # No super().__init__(): that opens the project with GhidraProject.openProject.
        self._lock = threading.RLock()
        self._repository_verified_at: float | None = None
        self.project_location, self.project_name = self.resolve_project_location_and_file(
            project_location, project_name
        )
        self.key = self.make_key(project_location, project_name)
        self._open_programs: set[tuple[str, ...]] = set()
        self._read_only_programs: list[tuple[Any, Any, tuple[str, ...]]] = []
        self._orphaned_programs: list[tuple[Any, tuple[str, ...], str]] = []
        self._program_keys: list[tuple[Any, tuple[str, ...]]] = []
        self._refcount = 0
        self._closed = False
        java_project = runtime_project()
        if java_project is None:
            raise project_closed_error()
        if not is_same_project(java_project, self.project_location, self.project_name):
            # GuiArgumentPolicy and the --session checks refuse other projects before they get here.
            raise _unsupported(f"the project {self.project_name}", "other_project")
        self._java_project = java_project
        self.project = _GuiProjectView(java_project)

    # ---- ownership --------------------------------------------------------

    def is_closed(self) -> bool:
        with self._lock:
            if self._closed:
                return True
            current = runtime_project()
            return current is None or not current.equals(self._java_project)

    def _ensure_open_locked(self) -> None:
        if self._closed or self.is_closed():
            raise project_closed_error()

    def get_java_project(self):
        with self._lock:
            self._ensure_open_locked()
            return self._java_project

    def close(self, *, force: bool = False) -> None:
        """Forget the handle; the project stays open in the GUI."""
        with self._lock:
            self._closed = True
            self._open_programs.clear()
            self._program_keys.clear()
            self._refcount = 0

    def _close_project_locked(self) -> None:
        # Inherited paths call this when the last program is released: the GUI's
        # project must stay open, so only this handle stops.
        self._closed = True

    def retain(self) -> None:
        with self._lock:
            self._ensure_open_locked()
            self._refcount += 1

    def release(self) -> None:
        with self._lock:
            self._refcount = max(0, self._refcount - 1)

    def release_orphaned_programs(self) -> int:
        return 0

    # ---- programs ---------------------------------------------------------

    def open_program(self, domain_path: Optional[str] = None, *, version: Optional[int] = None) -> ProgramSession:
        if version is not None:
            raise HeadlessError(
                "GUI_UNSUPPORTED: opening a past version is not available with the Ghidra GUI backend; "
                "open it in the GUI",
                details={"reason": "version"},
            )
        with self._lock:
            self._ensure_open_locked()
            domain_dir, domain_name = path_utils._parse_domain_path(self.project, domain_path)
            key = (domain_dir, domain_name)
            if key in self._open_programs:
                raise RuntimeError(f"Program already has an active session: {key}")
            path_text = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
            domain_file = self._get_domain_file_locked(path_text if path_text.startswith("/") else "/" + path_text)
            self._open_programs.add(key)  # reserved: a second open of it fails at once
        try:
            # Not under the handle's lock: the open waits on the GUI (a dialog may ask first).
            program = open_in_gui(self._java_project, domain_file)
            try:
                flat_api = java_bindings._flat_program_api_class()(program, java_bindings._console_monitor())
            except Exception as exc:
                raise HeadlessError(
                    f"PROGRAM_OPEN_FAILED: failed to initialize FlatProgramAPI for {path_text}: {exc}"
                ) from exc
        except BaseException:
            with self._lock:
                self._open_programs.discard(key)
            raise
        with self._lock:
            self._refcount += 1
            self._program_keys.append((program, key))
        return ProgramSession(flat_api, program, project_handle=self)

    @staticmethod
    def current_modal_dialog() -> str | None:
        """The title of a modal dialog the GUI shows (the auto-analysis prompt after a load), or None."""
        titles = modal_dialog_titles()
        return titles[0] if titles else None

    def program_is_open(self, program) -> bool:
        """Whether a GUI tool still has ``program`` open; False once the human closed its tab."""
        return is_open_in_gui(self._java_project, program)

    @contextmanager
    def hold_program(self, program) -> Iterator[bool]:
        """Keep ``program`` open for one operation with a consumer of its own (spec §5.2).

        Yields whether a GUI tool still has the program open.  A tab the human
        closes meanwhile closes the program only when the operation releases it.
        """
        if self.is_closed():  # the human closed the project or opened another one (spec §5.1)
            raise project_closed_error()
        consumer = _new_consumer()
        held = program is not None and bool(program.addConsumer(consumer))
        try:
            yield held and self.program_is_open(program)
        finally:
            if held:
                program.release(consumer)

    def _key_of_locked(self, program) -> tuple[str, ...] | None:
        for bound, key in self._program_keys:
            if bound is program or bound == program:
                return key
        return None

    def release_program(self, program, *, save: bool = True, remove_program: bool = False) -> None:
        """Unbind ``program`` from its target; it stays open, unsaved, in the GUI (spec §5.5)."""
        del save  # never: the program and its unsaved changes belong to the GUI
        if remove_program:
            raise _unsupported("removing a program from the project", "remove_program")
        with self._lock:
            key = self._key_of_locked(program)
            if key is None:
                raise HeadlessError("PROGRAM_NOT_OPEN: the program is not bound to a target of this server")
            self._program_keys = [(bound, k) for bound, k in self._program_keys if k != key]
            self._open_programs.discard(key)
            self._refcount = max(0, self._refcount - 1)

    def save_program(self, program, *, force: bool = False) -> bool:
        with self._lock:
            self._ensure_open_locked()
            if program is None:
                raise ValueError("program is required")
            if not force and not self._program_needs_save(program):
                return False
        save_in_gui(self._java_project, program)
        return True

    def list_programs(self):
        with self._lock:
            self._ensure_open_locked()
            results: list[Any] = []
            root = self.project.getProjectData().getRootFolder()
            self._collect_program_files_with_sync_locked(root, results)
            return results

    def refresh_project_data(self, *, force: bool = True) -> None:
        """The GUI keeps its project data current itself; nothing to refresh."""
        with self._lock:
            self._ensure_open_locked()

    def _ensure_repository_connected_locked(self, *, required: bool) -> bool:
        """Never connect or verify from a worker: in the GUI a connect may ask for the login in a modal
        dialog while the caller holds Mecha's locks.  The human connects in the GUI; until then the
        repository counts as offline."""
        del required
        if not self.is_repository_project_from_metadata(self.project_location, self.project_name):
            return False
        repository = self._get_repository_adapter_locked()
        if repository is None:
            return False
        try:
            return bool(repository.isConnected())
        except Exception:
            return False

    def _refresh_project_data_locked(self, *, force: bool = True) -> None:
        return None

    # ---- what the GUI does itself ------------------------------------------

    def import_program(self, *_args, **_kwargs):
        raise _unsupported("import_program", "import")

    def checkout_program(self, *_args, **_kwargs):
        raise _unsupported("checking out a program", "version_control")

    def add_program_to_version_control(self, *_args, **_kwargs):
        raise _unsupported("adding a program to version control", "version_control")

    def commit_program(self, *_args, **_kwargs):
        raise _unsupported("checking in a program", "version_control")

    def undo_checkout_program(self, *_args, **_kwargs):
        raise _unsupported("undoing a checkout", "version_control")

    def terminate_checkout_program(self, *_args, **_kwargs):
        raise _unsupported("terminating a checkout", "version_control")

    def merge_program(self, *_args, **_kwargs):
        raise _unsupported("merging a program", "version_control")

    def delete_domain_file(self, *_args, **_kwargs):
        raise _unsupported("deleting a project file", "delete_file")
