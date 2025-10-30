"""Helpers for managing Ghidra projects/programs via PyGhidra."""

from __future__ import annotations

import contextlib
import pathlib
import threading
from typing import Optional

import pyghidra
import pyghidra.core as pycore

__all__ = ["ProgramSession", "ProjectHandle"]

_FLAT_API_CLASS = None
_CONSOLE_MONITOR_CLASS = None


def _flat_program_api_class():
    global _FLAT_API_CLASS
    if _FLAT_API_CLASS is None:
        _FLAT_API_CLASS = pycore.JClass("ghidra.program.flatapi.FlatProgramAPI")
    return _FLAT_API_CLASS


def _console_monitor():
    global _CONSOLE_MONITOR_CLASS
    if _CONSOLE_MONITOR_CLASS is None:
        _CONSOLE_MONITOR_CLASS = pycore.JClass("ghidra.util.task.ConsoleTaskMonitor")
    return _CONSOLE_MONITOR_CLASS()


class ProgramSession:
    """Represents an opened Ghidra program (binary or project backed)."""

    def __init__(
        self,
        flat_api,
        program,
        *,
        context: Optional[contextlib.AbstractContextManager] = None,
        project_handle: Optional["ProjectHandle"] = None,
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self._context = context
        self.project_handle = project_handle

    @classmethod
    def from_binary(cls, binary_path: str) -> "ProgramSession":
        path = pathlib.Path(binary_path)
        if not path.exists():
            raise ValueError(f"バイナリが存在しません: {binary_path}")
        context = pyghidra.open_program(str(path))
        flat_api = context.__enter__()
        program = flat_api.getProgram()
        return cls(flat_api, program, context=context)

    def close(self) -> None:
        if self._context is not None:
            self._context.__exit__(None, None, None)
            self._context = None
        if self.project_handle is not None:
            self.project_handle.release_program(self.program)
            self.project_handle = None
        else:
            if self.program is not None and hasattr(self.program, "release"):
                try:
                    self.program.release()
                except Exception:
                    pass
        self.flat_api = None
        self.program = None

    def is_project_session(self) -> bool:
        return self.project_handle is not None


class ProjectHandle:
    """Shared handle for a Ghidra project, allowing multiple program sessions."""

    def __init__(self, project_dir: str, project_name: Optional[str]) -> None:
        self._lock = threading.RLock()
        self.project_dir = pathlib.Path(project_dir)
        self.requested_name = project_name

        location, resolved_name, nested = _project_location_and_name(project_dir, project_name)
        self.project_location = location
        self.resolved_name = resolved_name
        self.nested = nested
        self.root_dir = (location / resolved_name) if nested else location
        self.key = (str(location.resolve()), resolved_name)

        self.project, program = pycore._setup_project(
            None,
            location,
            resolved_name,
            program_name=None,
            nested_project_location=nested,
        )
        self._initial_program = program
        self._refcount = 0
        self._closed = False

    def open_program(self, domain_path: Optional[str] = None) -> ProgramSession:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトは既にクローズされています")
            monitor = _console_monitor()
            if self._initial_program is not None and (not domain_path or domain_path in {"", "/"}):
                program = self._initial_program
                self._initial_program = None
            else:
                domain_file = _resolve_domain_file(self.project, domain_path)
                program = domain_file.getDomainObject(self.project, True, False, monitor)
            if program is None:
                raise RuntimeError("プログラムを取得できませんでした")
            flat_api = _flat_program_api_class()(program, monitor)
            self._refcount += 1
            return ProgramSession(flat_api, program, project_handle=self)

    def release_program(self, program) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if program is not None:
                    self.project.save(program)
            except Exception:
                pass
            try:
                if program is not None and hasattr(program, "release"):
                    program.release()
            except Exception:
                pass
            self._refcount = max(0, self._refcount - 1)
            if self._refcount == 0:
                self._close_project_locked()

    def list_programs(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            results = []
            root = self.project.getProjectData().getRootFolder()
            _collect_program_files(root, results)
            return results

    def is_active(self) -> bool:
        with self._lock:
            return self._refcount > 0

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        with self._lock:
            self._close_project_locked()

    # ------------------------------------------------------------------

    def _close_project_locked(self) -> None:
        if self._closed:
            return
        try:
            self.project.close()
        except Exception:
            pass
        self._closed = True
        _remove_lock_dirs(self.root_dir, self.resolved_name)


# ----------------------------------------------------------------------
# helper functions


def _project_location_and_name(project_dir: str, project_name: Optional[str]):
    path = pathlib.Path(project_dir)
    nested = True
    inferred = project_name
    if path.suffix == ".gpr" and path.is_file():
        inferred = inferred or path.stem
        location = path.parent
        nested = False
    else:
        location = path
        if inferred is None:
            inferred = path.name
    return location, inferred, nested


def _resolve_domain_file(project, domain_path: Optional[str]):
    data = project.getProjectData()
    root = data.getRootFolder()
    if not domain_path:
        domain_path = _find_first_program_path(project)
    if not domain_path:
        raise ValueError("プロジェクト内にプログラムが見つかりません")
    folder_path, program_name = _split_domain_path(domain_path)
    folder = _get_folder(root, folder_path)
    if folder is None:
        raise ValueError(f"フォルダ '{folder_path}' が見つかりません")
    domain_file = folder.getFile(program_name)
    if domain_file is None:
        raise ValueError(f"プログラム '{program_name}' が見つかりません ({folder_path})")
    return domain_file


def _find_first_program_path(project) -> Optional[str]:
    data = project.getProjectData()
    queue = [data.getRootFolder()]
    while queue:
        folder = queue.pop(0)
        for f in list(folder.getFiles()):
            if f.getContentType() == "Program":
                return f.getPathname()
        queue.extend(list(folder.getFolders()))
    return None


def _split_domain_path(domain_path: Optional[str]) -> tuple[str, Optional[str]]:
    if not domain_path:
        return "/", None
    clean = domain_path.strip("/")
    if not clean:
        return "/", None
    if "/" in clean:
        folder, _, name = clean.rpartition("/")
        return f"/{folder}", name
    return "/", clean


def _get_folder(root_folder, folder_path: str):
    if folder_path == "/":
        return root_folder
    current = root_folder
    for segment in folder_path.strip("/").split("/"):
        if not segment:
            continue
        current = current.getFolder(segment)
        if current is None:
            break
    return current


def _collect_program_files(folder, results):
    for domain_file in list(folder.getFiles()):
        if domain_file.getContentType() == "Program":
            results.append(
                {
                    "path": domain_file.getPathname(),
                    "name": domain_file.getName(),
                    "contentType": domain_file.getContentType(),
                }
            )
    for sub in list(folder.getFolders()):
        _collect_program_files(sub, results)


def _remove_lock_dirs(root_dir: Optional[pathlib.Path], project_name: Optional[str]) -> None:
    if root_dir is None:
        return
    candidates = set()
    if project_name:
        candidates.add(root_dir / f"{project_name}.lock")
    candidates.add(root_dir.parent / f"{root_dir.name}.lock")
    for path in candidates:
        try:
            if path.exists():
                if path.is_dir():
                    _remove_tree(path)
                else:
                    path.unlink(missing_ok=True)
        except Exception:
            pass


def _remove_tree(path: pathlib.Path) -> None:
    for child in path.iterdir():
        if child.is_dir():
            _remove_tree(child)
        else:
            child.unlink(missing_ok=True)
    path.rmdir()
