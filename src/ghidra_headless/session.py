"""Helpers for managing Ghidra projects/programs via PyGhidra."""

from __future__ import annotations

import pathlib
import threading
from typing import Dict, Optional

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
        project_handle: "ProjectHandle",
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self.project_handle: Optional["ProjectHandle"] = project_handle

    def get_program(self):
        if self.program is None:
            raise RuntimeError("セッションはすでにクローズしています")
        return self.program

    def get_project_handle(self) -> "ProjectHandle":
        if self.project_handle is None:
            raise RuntimeError("セッションはすでにクローズしています")
        return self.project_handle

    def close(self, *, remove_program: bool = False) -> None:
        if self.project_handle is None:
            raise RuntimeError("セッションはすでにクローズしています")
        self.project_handle.release_program(self.program, remove_program=remove_program)

        self.project_handle = None
        self.flat_api = None
        self.program = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        project_name: Optional[str] = None
        project_location: Optional[str] = None
        dmain_path: Optional[str] = _domain_path(self.program)

        handle = self.get_project_handle()
        project_name = handle.get_project_name()
        project_location = handle.get_project_location()

        return {
            "project_name": project_name,
            "project_location": project_location,
            "domain_path": dmain_path
        }


class ProjectHandle:
    """Shared handle for a Ghidra project, allowing multiple program sessions."""

    def __init__(self, project_location: str, project_name: Optional[str]) -> None:
        self._lock = threading.RLock()
        self.project_location, self.project_name = self.resolve_project_location_and_file(project_location, project_name)
        self.key = self.make_key(project_location, project_name)
        self._open_programs: set[tuple[str, str]] = set()

        from ghidra.base.project import GhidraProject
        self.project = GhidraProject.openProject(self.project_location, self.project_name, True)
        self._refcount = 0
        self._closed = False

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        path = pathlib.Path(project_location).expanduser().resolve()
        if project_name is None and path.suffix.lower() != ".gpr":
            raise ValueError("project_location には .gpr のGhidraプロジェクトファイルを指定してください")
        if project_name is None and not path.is_file():
            raise ValueError(f"指定した .gpr ファイルが見つかりません: {path}")
        if project_name is None and path.is_dir():
            raise ValueError("project_name を指定してください")
        effective = project_name or path.stem
        return (str(path.parent if path.is_file() else path), effective)

    @staticmethod
    def make_key(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        return ProjectHandle.resolve_project_location_and_file(project_location, project_name)

    def get_project_location(self) -> str:
        return self.project_location

    def get_project_name(self) -> str:
        return self.project_name

    def get_key(self) -> tuple[str, str]:
        return self.key

    def open_program(self, domain_path: Optional[str] = None) -> ProgramSession:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトは既にクローズされています")
            monitor = _console_monitor()
            domain_dir, domain_name = _parse_domain_path(self.project, domain_path)
            domain_path_key = (domain_dir, domain_name)
            if domain_path_key in self._open_programs:
                raise RuntimeError(f"プログラムには既にセッションがあります: {domain_path_key}")
            program = self.project.openProgram(domain_dir, domain_name, False)
            if program is None:
                raise RuntimeError(f"プログラムを取得できませんでした: {domain_path}")
            flat_api = _flat_program_api_class()(program, monitor)
            self._refcount += 1
            self._open_programs.add(domain_path_key)
            return ProgramSession(flat_api, program, project_handle=self)

    def import_program(self, binary_path: str):
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトは既にクローズされています")
            path = pathlib.Path(binary_path)
            if not path.exists():
                raise ValueError(f"バイナリが存在しません: {binary_path}")
            program_dir = "/"
            program_name = path.name
            data = self.project.getProjectData()
            domain_file = data.getFile(program_dir + program_name)
            if domain_file is not None:
                raise RuntimeError(f"プログラムはすでに存在します: {domain_file.getPathname()}")
            program = None

            try:
                java_file = pycore.JClass("java.io.File")(str(path))
                program = self.project.importProgram(java_file)
                self.project.saveAs(program, program_dir, program_name, True)
                domain_file = program.getDomainFile()
            finally:
                if program is not None:
                    self.project.close(program)
            if domain_file is None:
                raise RuntimeError(f"プログラムの追加に失敗しました: {binary_path}")

            return domain_file

    def open_program_by_importing(self, binary_path: str) -> ProgramSession:
        domain_path = self.import_program(binary_path)
        return self.open_program(domain_path.getPathname())

    def release_program(self, program, *, remove_program: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            domain_path = _domain_path(program)
            if domain_path is None:
                raise RuntimeError("削除対象プログラムのパスを取得できません")
            domain_key = _parse_domain_path(self.project, domain_path)
            try:
                if program is not None:
                    self.project.save(program)
            except Exception:
                pass
            try:
                if program is not None:
                    self.project.close(program)
            except Exception:
                pass
            if remove_program:
                self._delete_program_locked(domain_path)
            self._open_programs.discard(domain_key)
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
        self._open_programs.clear()
        self._closed = True

    def _delete_program_locked(self, domain_path: str) -> None:
        if self._closed:
            return
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"削除対象のプログラムが見つかりません: {domain_path}")
        try:
            domain_file.delete()
        except Exception:
            pass


# ----------------------------------------------------------------------
# helper functions


def _parse_domain_path(project, domain_path: Optional[str]):
    if not domain_path:
        domain_path = _find_first_program_path(project)
    if not domain_path:
        raise ValueError("プロジェクト内にプログラムが見つかりません")
    domain_file = pathlib.PurePosixPath(domain_path)
    return domain_file.parent.as_posix(), domain_file.name


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


def _collect_program_files(folder, results):
    for domain_file in list(folder.getFiles()):
        if domain_file.getContentType() == "Program":
            results.append(
                {
                    "domain_path": domain_file.getPathname(),
                    "domain_name": domain_file.getName(),
                    "contentType": domain_file.getContentType(),
                }
            )
    for sub in list(folder.getFolders()):
        _collect_program_files(sub, results)


def _domain_path(program, domain_file=None) -> Optional[str]:
    if program is None:
        return None

    if domain_file is None:
        domain_file = program.getDomainFile()
    if domain_file is not None:
        return domain_file.getPathname()
    return None
