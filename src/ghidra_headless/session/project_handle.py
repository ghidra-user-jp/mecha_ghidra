"""Project-level operations for Ghidra sessions."""

from __future__ import annotations

import logging
import pathlib
import threading
from typing import Any, Dict, Optional

import pyghidra.core as pycore

from .models import ProgramSession
from . import java_bindings, path_utils, sync_utils

logger = logging.getLogger(__name__)


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
            raise ValueError("project_location must point to a .gpr Ghidra project file")
        if project_name is None and not path.is_file():
            raise ValueError(f"Specified .gpr file not found: {path}")
        if project_name is None and path.is_dir():
            raise ValueError("project_name is required")
        effective = project_name or path.stem
        return (str(path.parent if path.is_file() else path), effective)

    @staticmethod
    def make_key(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        return ProjectHandle.resolve_project_location_and_file(project_location, project_name)

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: Optional[str]) -> Optional[list[Dict[str, str]]]:
        resolved_location, resolved_name = ProjectHandle.resolve_project_location_and_file(project_location, project_name)
        rep_dir = pathlib.Path(resolved_location) / f"{resolved_name}.rep"
        idata_dir = rep_dir / "idata"
        if not idata_dir.is_dir():
            return None
        return path_utils._collect_program_files_from_idata(idata_dir)

    def get_project_location(self) -> str:
        return self.project_location

    def get_project_name(self) -> str:
        return self.project_name

    def get_key(self) -> tuple[str, str]:
        return self.key

    def open_program(self, domain_path: Optional[str] = None) -> ProgramSession:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is already closed")
            monitor = java_bindings._console_monitor()
            domain_dir, domain_name = path_utils._parse_domain_path(self.project, domain_path)
            domain_path_key = (domain_dir, domain_name)
            if domain_path_key in self._open_programs:
                raise RuntimeError(f"Program already has an active session: {domain_path_key}")
            program = self.project.openProgram(domain_dir, domain_name, False)
            if program is None:
                raise RuntimeError(f"Failed to open program: {domain_path}")
            flat_api = java_bindings._flat_program_api_class()(program, monitor)
            self._refcount += 1
            self._open_programs.add(domain_path_key)
            return ProgramSession(flat_api, program, project_handle=self)

    def import_program(self, binary_path: str):
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is already closed")
            path = pathlib.Path(binary_path)
            if not path.exists():
                raise ValueError(f"Binary does not exist: {binary_path}")
            program_dir = "/"
            program_name = path.name
            data = self.project.getProjectData()
            domain_file = data.getFile(program_dir + program_name)
            if domain_file is not None:
                raise RuntimeError(f"Program already exists: {domain_file.getPathname()}")
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
                raise RuntimeError(f"Failed to add program: {binary_path}")

            return domain_file

    def get_sync_status(self, domain_path: str) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            return sync_utils._sync_status_from_domain_file(domain_file)

    def get_version_history(self, domain_path: str, *, limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            normalized_limit = int(limit)
            if normalized_limit < 1:
                raise ValueError("limit must be >= 1")
            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(sync_utils._required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")
            versions = sync_utils._get_version_history_entries(domain_file)
            versions.sort(key=lambda item: item["version"], reverse=True)
            current_version = int(sync_utils._required_call(domain_file, "getVersion"))
            latest_version = int(sync_utils._required_call(domain_file, "getLatestVersion"))
            return {
                "program": domain_path,
                "current_version": current_version,
                "latest_version": latest_version,
                "total_versions": len(versions),
                "versions": versions[:normalized_limit],
            }

    def get_version_diff(
        self,
        domain_path: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
    ) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            source_version = int(from_version)
            target_version = int(to_version)
            if source_version < 1 or target_version < 1:
                raise ValueError("from_version and to_version must be >= 1")
            normalized_range_limit = int(range_limit)
            if normalized_range_limit < 0:
                raise ValueError("range_limit must be >= 0")

            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(sync_utils._required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")

            versions = sync_utils._get_version_history_entries(domain_file)
            known_versions = {item["version"] for item in versions}
            if source_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: from_version={source_version} not found in history"
                )
            if target_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: to_version={target_version} not found in history"
                )

            result = {
                "program": domain_path,
                "from_version": source_version,
                "to_version": target_version,
                "total_diff_addresses": 0,
                "total_diff_ranges": 0,
                "diff_types": [],
                "ranges": [],
                "ranges_truncated": False,
                "warnings": None,
            }
            if source_version == target_version:
                return result

            monitor = java_bindings._console_monitor()
            from_consumer = java_bindings._java_object()
            to_consumer = java_bindings._java_object()
            from_program = None
            to_program = None
            try:
                from_program = domain_file.getReadOnlyDomainObject(from_consumer, source_version, monitor)
                to_program = domain_file.getReadOnlyDomainObject(to_consumer, target_version, monitor)
                if from_program is None or to_program is None:
                    raise RuntimeError(
                        f"VERSION_LOAD_FAILED: failed to open version {source_version} or {target_version}"
                    )
                program_diff = java_bindings._program_diff_class()(from_program, to_program)
                differences = program_diff.getDifferences(monitor)

                type_counts = sync_utils._collect_diff_type_counts(program_diff, differences, monitor)
                ranges, truncated = sync_utils._collect_diff_ranges(differences, limit=normalized_range_limit)
                warnings = program_diff.getWarnings()
                result.update(
                    {
                        "total_diff_addresses": int(differences.getNumAddresses()) if differences is not None else 0,
                        "total_diff_ranges": int(differences.getNumAddressRanges()) if differences is not None else 0,
                        "diff_types": type_counts,
                        "ranges": ranges,
                        "ranges_truncated": truncated,
                        "warnings": None if warnings is None else str(warnings),
                    }
                )
                return result
            finally:
                sync_utils._release_domain_object(from_program, from_consumer)
                sync_utils._release_domain_object(to_program, to_consumer)

    def checkout_program(self, domain_path: str, *, exclusive: bool = False) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            return bool(domain_file.checkout(bool(exclusive), monitor))

    def add_program_to_version_control(
        self,
        domain_path: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            text = (comment or "").strip()
            if not text:
                raise ValueError("comment is required")
            domain_file = self._get_domain_file_locked(domain_path)
            can_add = sync_utils._safe_call(domain_file, "canAddToRepository")
            if can_add is False:
                raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed")
            monitor = java_bindings._console_monitor()
            domain_file.addToVersionControl(text, bool(keep_checked_out), monitor)

    def commit_program(
        self,
        domain_path: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        create_keep_file: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            text = (message or "").strip()
            if not text:
                raise ValueError("message is required")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            handler = java_bindings._default_checkin_handler_class()(text, bool(keep_checked_out), bool(create_keep_file))
            domain_file.checkin(handler, monitor)

    def merge_program(self, domain_path: str, *, ok_to_upgrade: bool = True) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            domain_file.merge(bool(ok_to_upgrade), monitor)

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.undoCheckout(bool(keep))

    def terminate_checkout_program(self, domain_path: str, checkout_id: int) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.terminateCheckout(int(checkout_id))

    def release_program(self, program, *, remove_program: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            domain_path = path_utils._domain_path(program)
            if domain_path is None:
                raise RuntimeError("Failed to resolve path of program to remove")
            domain_key = path_utils._parse_domain_path(self.project, domain_path)
            remove_error = None
            try:
                if program is not None:
                    self.project.save(program)
            except Exception as exc:
                logger.warning("program save failed before close: %s", exc)
            try:
                if program is not None:
                    self.project.close(program)
            except Exception as exc:
                logger.warning("program close failed: %s", exc)
            if remove_program:
                try:
                    self._delete_program_locked(domain_path)
                except Exception as exc:
                    remove_error = exc
            self._open_programs.discard(domain_key)
            self._refcount = max(0, self._refcount - 1)
            if self._refcount == 0:
                self._close_project_locked()
            if remove_error is not None:
                raise remove_error

    def list_programs(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            results = []
            root = self.project.getProjectData().getRootFolder()
            path_utils._collect_program_files(root, results)
            return results

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
        except Exception as exc:
            logger.warning("project close failed: %s", exc)
        self._open_programs.clear()
        self._closed = True

    def _delete_program_locked(self, domain_path: str) -> None:
        if self._closed:
            return
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Program to remove not found: {domain_path}")
        try:
            domain_file.delete()
        except Exception as exc:
            raise RuntimeError(f"Failed to remove program: {domain_path}: {exc}")

    def _get_domain_file_locked(self, domain_path: str):
        if not domain_path:
            raise ValueError("domain_path is required")
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Program not found: {domain_path}")
        return domain_file


__all__ = ["ProjectHandle"]
