"""Project-level operations for Ghidra sessions."""

from __future__ import annotations

import logging
import pathlib
import threading
from typing import Any, Dict, Optional

import pyghidra
import pyghidra.core as pycore

from .models import ProgramSession
from . import java_bindings, path_utils, sync_utils

logger = logging.getLogger(__name__)

_VERSION_DIFF_MAX_RANGE_LIMIT = 10_000
_VERSION_DIFF_TIMEOUT_SECONDS = 60


class _ImportedProgramCloseError(RuntimeError):
    pass


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
    def resolve_project_creation_target(
        project_location: str,
        project_name: Optional[str],
    ) -> tuple[str, str]:
        path = pathlib.Path(project_location).expanduser().resolve()
        if project_name is not None:
            effective_name = project_name.strip()
            if not effective_name:
                raise ValueError("project_name must not be empty")
            project_dir = path.parent if path.suffix.lower() == ".gpr" else path
            if path.suffix.lower() == ".gpr" and path.stem != effective_name:
                raise ValueError("project_name must match the .gpr filename when project_location points to a .gpr file")
        else:
            if path.suffix.lower() != ".gpr":
                raise ValueError("project_name is required when project_location is not a .gpr file")
            effective_name = path.stem
            project_dir = path.parent

        return (str(project_dir), effective_name)

    @staticmethod
    def _create_empty_project(
        project_dir: pathlib.Path,
        effective_name: str,
        *,
        overwrite: bool,
    ) -> Any:
        if overwrite:
            from ghidra.base.project import GhidraProject

            # GhidraProject.createProject intentionally deletes a previous project.
            # Callers must only select this path after authorizing overwrite.
            return GhidraProject.createProject(str(project_dir), effective_name, False)

        from ghidra.framework.model import ProjectLocator
        from ghidra.pyghidra import PyGhidraProjectManager
        from ghidra.util.exception import DuplicateFileException

        locator = ProjectLocator(str(project_dir), effective_name)
        try:
            # Unlike GhidraProject.createProject, this API fails if either the
            # marker file or project repository already exists; it never runs
            # deletePreviousProject().
            return PyGhidraProjectManager().createProject(locator, None, True)
        except DuplicateFileException as exc:
            project_file = project_dir / f"{effective_name}.gpr"
            raise RuntimeError(f"PROJECT_ALREADY_EXISTS: {project_file}") from exc

    @staticmethod
    def create_project(
        project_location: str,
        project_name: Optional[str] = None,
        *,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        resolved_dir, effective_name = ProjectHandle.resolve_project_creation_target(
            project_location,
            project_name,
        )
        project_dir = pathlib.Path(resolved_dir)

        project_file = project_dir / f"{effective_name}.gpr"
        project_rep = project_dir / f"{effective_name}.rep"
        existed = project_file.exists() or project_rep.exists()
        if existed and not overwrite:
            raise RuntimeError(f"PROJECT_ALREADY_EXISTS: {project_file}")
        project_dir.mkdir(parents=True, exist_ok=True)

        project = ProjectHandle._create_empty_project(
            project_dir,
            effective_name,
            overwrite=overwrite,
        )
        try:
            project.close()
        except Exception as exc:
            raise RuntimeError(f"PROJECT_CLOSE_FAILED: failed to close created project: {exc}") from exc
        return {
            "status": "ok",
            "project_location": str(project_dir),
            "project_name": effective_name,
            "project_file": str(project_file),
            "created": True,
            "overwritten": bool(existed),
        }

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: Optional[str]) -> Optional[list[Dict[str, str]]]:
        rep_dir = ProjectHandle._project_rep_dir(project_location, project_name)
        idata_dir = rep_dir / "idata"
        if not idata_dir.is_dir():
            return None
        return path_utils._collect_program_files_from_idata(idata_dir)

    @staticmethod
    def is_repository_project_from_metadata(project_location: str, project_name: Optional[str]) -> bool:
        info = path_utils._read_prp_basic_info(ProjectHandle._project_rep_dir(project_location, project_name) / "project.prp")
        if not info:
            return False
        return bool(str(info.get("SERVER") or "").strip())

    @staticmethod
    def _project_rep_dir(project_location: str, project_name: Optional[str]) -> pathlib.Path:
        resolved_location, resolved_name = ProjectHandle.resolve_project_location_and_file(project_location, project_name)
        return pathlib.Path(resolved_location) / f"{resolved_name}.rep"

    def get_project_location(self) -> str:
        return self.project_location

    def get_project_name(self) -> str:
        return self.project_name

    def get_key(self) -> tuple[str, str]:
        return self.key

    def get_shared_project_url(self) -> Optional[str]:
        """Return the server-backed project URL without changing repository state."""
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            is_repository_project = self.is_repository_project_from_metadata(
                self.project_location,
                self.project_name,
            )
            try:
                project_data = self.project.getProjectData()
                get_shared_url = getattr(project_data, "getSharedProjectURL", None)
                if get_shared_url is None:
                    if is_repository_project:
                        raise RuntimeError(
                            "SYNC_STATUS_UNAVAILABLE: ProjectData.getSharedProjectURL is unavailable"
                        )
                    return None
                shared_url = get_shared_url()
            except Exception as exc:  # noqa: BLE001
                if str(exc).startswith("SYNC_STATUS_UNAVAILABLE:"):
                    raise
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to resolve shared project URL: "
                    f"{exc}"
                ) from exc
            if shared_url is None:
                if is_repository_project:
                    raise RuntimeError(
                        "SYNC_STATUS_UNAVAILABLE: shared project URL is unavailable"
                    )
                return None
            normalized_url = str(shared_url).strip()
            if not normalized_url:
                if is_repository_project:
                    raise RuntimeError(
                        "SYNC_STATUS_UNAVAILABLE: shared project URL is empty"
                    )
                return None
            return normalized_url

    def get_domain_file_id(self, domain_path: str) -> Optional[str]:
        """Return Ghidra's stable file ID for a domain file, when available."""
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            get_file_id = getattr(domain_file, "getFileID", None)
            if get_file_id is None:
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: DomainFile.getFileID is unavailable"
                )
            try:
                file_id = get_file_id()
            except Exception as exc:
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to read DomainFile file ID: "
                    f"{exc}"
                ) from exc
            if file_id is None:
                return None
            normalized_id = str(file_id).strip()
            return normalized_id or None

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
            try:
                flat_api = java_bindings._flat_program_api_class()(program, monitor)
            except Exception as exc:  # noqa: BLE001
                domain_path_text = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
                try:
                    self.project.close(program)
                except Exception as close_exc:  # noqa: BLE001
                    raise RuntimeError(
                        "PROGRAM_OPEN_FAILED: failed to initialize FlatProgramAPI for "
                        f"{domain_path_text}: {exc}; cleanup close failed: {close_exc}"
                    ) from exc
                raise RuntimeError(
                    "PROGRAM_OPEN_FAILED: failed to initialize FlatProgramAPI for "
                    f"{domain_path_text}: {exc}"
                ) from exc
            self._refcount += 1
            self._open_programs.add(domain_path_key)
            return ProgramSession(flat_api, program, project_handle=self)

    def import_program(
        self,
        binary_path: str,
        *,
        import_mode: str = "auto",
        language_id: str | None = None,
        compiler_spec_id: str | None = None,
        base_address: str | None = None,
        file_offset: int | None = None,
        length: int | None = None,
        block_name: str | None = None,
        overlay: bool = False,
        entry_address: str | None = None,
        entry_offset: int | None = None,
        analyze_imported: bool | None = None,
    ):
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
            if import_mode == "auto":
                domain_file = self._import_program_auto_locked(path, program_dir, program_name)
            elif import_mode == "raw_binary":
                if language_id is None:
                    raise ValueError("language_id is required when import_mode='raw_binary'")
                domain_file = self._import_program_raw_locked(
                    path,
                    program_dir=program_dir,
                    program_name=program_name,
                    language_id=language_id,
                    compiler_spec_id=compiler_spec_id,
                    base_address=base_address,
                    file_offset=file_offset,
                    length=length,
                    block_name=block_name,
                    overlay=overlay,
                )
            else:
                raise ValueError(f"Unsupported import_mode: {import_mode}")
            if domain_file is None:
                raise RuntimeError(f"Failed to add program: {binary_path}")
            should_analyze = analyze_imported if analyze_imported is not None else (import_mode == "raw_binary")
            if should_analyze or entry_address is not None or entry_offset is not None:
                imported_domain_path = domain_file.getPathname()
                try:
                    self._post_process_imported_program_locked(
                        imported_domain_path,
                        entry_address=entry_address,
                        entry_offset=entry_offset,
                        analyze_imported=bool(should_analyze),
                    )
                except Exception as exc:
                    if isinstance(exc, _ImportedProgramCloseError):
                        raise RuntimeError(
                            "IMPORT_CLOSE_FAILED: imported program "
                            f"{imported_domain_path} but failed to close after post-processing: "
                            f"{self._short_error(exc)}"
                        ) from exc
                    try:
                        self._delete_domain_file_locked(imported_domain_path)
                    except Exception as cleanup_exc:
                        raise RuntimeError(
                            "IMPORT_POST_PROCESS_FAILED: imported program "
                            f"{imported_domain_path} but post-processing failed: {exc}; "
                            f"rollback delete failed: {cleanup_exc}"
                        ) from exc
                    raise RuntimeError(
                        "IMPORT_POST_PROCESS_FAILED: rolled back imported program "
                        f"{imported_domain_path} after post-processing failed: {exc}"
                    ) from exc

            return domain_file

    def get_sync_status(self, domain_path: str) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=False)
            domain_file = self._get_domain_file_locked(domain_path)
            return sync_utils._sync_status_from_domain_file(domain_file)

    def get_version_history(self, domain_path: str, *, limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=True)
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
            self._ensure_repository_connected_locked(required=True)
            source_version = int(from_version)
            target_version = int(to_version)
            if source_version < 1 or target_version < 1:
                raise ValueError("from_version and to_version must be >= 1")
            normalized_range_limit = int(range_limit)
            if normalized_range_limit < 0:
                raise ValueError("range_limit must be >= 0")
            if normalized_range_limit > _VERSION_DIFF_MAX_RANGE_LIMIT:
                raise ValueError(
                    f"range_limit must be <= {_VERSION_DIFF_MAX_RANGE_LIMIT}"
                )

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

            monitor = java_bindings._timeout_task_monitor(
                timeout_seconds=_VERSION_DIFF_TIMEOUT_SECONDS
            )
            from_consumer = None
            to_consumer = None
            from_program = None
            to_program = None
            try:
                try:
                    from_consumer = java_bindings._java_object()
                    to_consumer = java_bindings._java_object()
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
                except Exception as exc:
                    if bool(monitor.didTimeout()):
                        raise RuntimeError(
                            "VERSION_DIFF_TIMEOUT: version diff exceeded "
                            f"{_VERSION_DIFF_TIMEOUT_SECONDS} seconds"
                        ) from exc
                    raise
                if bool(monitor.didTimeout()):
                    raise RuntimeError(
                        "VERSION_DIFF_TIMEOUT: version diff exceeded "
                        f"{_VERSION_DIFF_TIMEOUT_SECONDS} seconds"
                    )
                return result
            finally:
                sync_utils._release_domain_object(from_program, from_consumer)
                sync_utils._release_domain_object(to_program, to_consumer)
                try:
                    monitor.finished()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("failed to finish version diff timeout monitor: %s", exc)

    def refresh_project_data(self, *, force: bool = True) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._refresh_project_data_locked(force=force)

    def _refresh_project_data_locked(self, *, force: bool = True) -> None:
        repository_connected = self._ensure_repository_connected_locked(required=True)
        data = self.project.getProjectData()
        refresh = getattr(data, "refresh", None)
        if refresh is None:
            if repository_connected:
                raise RuntimeError(
                    "PROJECT_DATA_REFRESH_FAILED: shared ProjectData.refresh is unavailable"
                )
            return
        try:
            refresh(bool(force))
        except Exception as exc:
            raise RuntimeError(f"PROJECT_DATA_REFRESH_FAILED: failed to refresh project data: {exc}") from exc
        if repository_connected:
            self._verify_repository_connected_after_refresh_locked()

    def checkout_program(self, domain_path: str, *, exclusive: bool = False) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=True)
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
            self._ensure_repository_connected_locked(required=True)
            text = (comment or "").strip()
            if not text:
                raise ValueError("comment is required")
            domain_file = self._get_domain_file_locked(domain_path)
            can_add = sync_utils._required_call(domain_file, "canAddToRepository")
            if can_add is None:
                raise RuntimeError("SYNC_STATUS_UNAVAILABLE: DomainFile.canAddToRepository returned None")
            if not bool(can_add):
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
            self._ensure_repository_connected_locked(required=True)
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
            self._ensure_repository_connected_locked(required=True)
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            domain_file.merge(bool(ok_to_upgrade), monitor)

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=True)
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.undoCheckout(bool(keep))

    def terminate_checkout_program(self, domain_path: str, checkout_id: int) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=True)
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.terminateCheckout(int(checkout_id))

    def delete_domain_file(self, domain_path: str) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            return self._delete_domain_file_locked(domain_path)

    def release_program(self, program, *, save: bool = True, remove_program: bool = False) -> None:
        with self._lock:
            if self._closed:
                # Never a silent success: the project is gone, so nothing can be
                # saved and the program was already force-closed with it.
                raise RuntimeError(
                    "SESSION_CLOSE_FAILED: project is already closed; the program was "
                    "closed without saving"
                )
            domain_path = path_utils._domain_path(program)
            if domain_path is None:
                raise RuntimeError("Failed to resolve path of program to remove")
            domain_key = path_utils._parse_domain_path(self.project, domain_path)
            if domain_key not in self._open_programs:
                # Guard against double release: a second release for the same
                # program would decrement the refcount again and close the
                # project out from under the remaining sessions.
                raise RuntimeError(
                    f"PROGRAM_NOT_OPEN: program '{domain_path}' is not open in this project handle"
                )
            remove_error = None
            project_close_error = None
            try:
                if save and program is not None:
                    self.save_program(program)
            except Exception as exc:
                raise RuntimeError(f"SAVE_FAILED: failed to save program before close: {self._save_error_text(exc)}") from exc
            try:
                if program is not None:
                    self.project.close(program)
            except Exception as exc:
                raise RuntimeError(f"PROGRAM_CLOSE_FAILED: failed to close program: {exc}") from exc
            if remove_program:
                try:
                    self._delete_program_locked(domain_path)
                except Exception as exc:
                    remove_error = exc
            self._open_programs.discard(domain_key)
            self._refcount = max(0, self._refcount - 1)
            if remove_error is not None:
                raise RuntimeError(f"REMOVE_PROGRAM_FAILED: {remove_error}")
            if self._refcount == 0:
                try:
                    self._close_project_locked()
                except Exception as exc:
                    project_close_error = exc
            if project_close_error is not None:
                raise RuntimeError(
                    "SESSION_CLOSE_FAILED: failed to close project: "
                    f"{self._project_close_error_text(project_close_error)}"
                ) from project_close_error

    def save_program(self, program, *, force: bool = False) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            if program is None:
                raise ValueError("program is required")
            if not force and not self._program_needs_save(program):
                return False
            try:
                self.project.save(program)
            except Exception as exc:
                raise RuntimeError(f"SAVE_FAILED: failed to save program: {exc}") from exc
            return True

    def list_programs(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            self._ensure_repository_connected_locked(required=False)
            try:
                self._refresh_project_data_locked(force=True)
            except Exception as exc:
                logger.debug("failed to refresh project data before listing programs: %s", exc)
            results = []
            root = self.project.getProjectData().getRootFolder()
            self._collect_program_files_with_sync_locked(root, results)
            return results

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self, *, force: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            if self._refcount > 0 and not force:
                # Closing the project force-closes every open program without
                # saving; callers must close the owning sessions first. Rollback
                # and shutdown paths reclaiming a handle whose program release
                # already failed pass force=True — for them, rejecting the close
                # would leave the project wedged until the process restarts.
                raise RuntimeError(
                    f"PROJECT_CLOSE_REJECTED: {self._refcount} program session(s) are "
                    "still open for this project; close them first"
                )
            self._close_project_locked()

    # ------------------------------------------------------------------

    def _close_project_locked(self) -> None:
        if self._closed:
            return
        try:
            self.project.close()
        except Exception as exc:
            logger.warning("project close failed: %s", exc)
            raise RuntimeError(f"PROJECT_CLOSE_FAILED: failed to close project: {exc}") from exc
        self._open_programs.clear()
        self._closed = True

    def _delete_domain_file_locked(self, domain_path: str) -> Dict[str, Any]:
        if self._closed:
            raise RuntimeError("Project is closed")
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Domain file not found: {domain_path}")
        content_type = None
        was_hijacked = bool(sync_utils._safe_call(domain_file, "isHijacked"))
        try:
            content_type = domain_file.getContentType()
        except Exception as exc:
            logger.debug("failed to read content type before domain file delete: %s", exc)
        try:
            domain_file.delete()
        except Exception as exc:
            raise RuntimeError(f"Failed to delete domain file: {domain_path}: {exc}") from exc
        try:
            self._refresh_project_data_locked(force=True)
        except Exception as exc:
            raise RuntimeError(
                "DELETE_POSTCONDITION_FAILED: domain file delete returned, but project data "
                f"refresh failed for {domain_path}: {exc}"
            ) from exc
        try:
            remaining_file = self.project.getProjectData().getFile(domain_path)
        except Exception as exc:
            raise RuntimeError(
                "DELETE_POSTCONDITION_FAILED: domain file delete returned, but path absence "
                f"could not be verified for {domain_path}: {exc}"
            ) from exc
        if remaining_file is None and was_hijacked:
            raise RuntimeError(
                "DELETE_POSTCONDITION_FAILED: hijacked shadow was deleted, but the repository "
                f"file was not revealed: {domain_path}"
            )
        if remaining_file is not None:
            if not was_hijacked:
                raise RuntimeError(
                    "DELETE_POSTCONDITION_FAILED: domain file delete returned, but the path still "
                    f"exists: {domain_path}"
                )
            try:
                revealed_status = sync_utils._sync_status_from_domain_file(remaining_file)
            except Exception as exc:
                raise RuntimeError(
                    "DELETE_POSTCONDITION_FAILED: hijacked shadow was deleted, but the revealed "
                    f"repository state could not be verified for {domain_path}: {exc}"
                ) from exc
            if revealed_status.get("is_hijacked") or not revealed_status.get("is_versioned"):
                raise RuntimeError(
                    "DELETE_POSTCONDITION_FAILED: hijacked shadow was deleted, but a versioned "
                    f"repository file was not revealed: {domain_path}"
                )
        return {
            "domain_path": domain_path,
            "content_type": None if content_type is None else str(content_type),
            "deleted_verified": True,
        }

    def _delete_program_locked(self, domain_path: str) -> None:
        try:
            self._delete_domain_file_locked(domain_path)
        except Exception as exc:
            raise RuntimeError(f"Failed to remove program: {domain_path}: {exc}") from exc

    @staticmethod
    def _program_needs_save(program) -> bool:
        is_changed = getattr(program, "isChanged", None)
        if is_changed is None:
            return True
        try:
            return bool(is_changed())
        except Exception:
            return True

    @staticmethod
    def _save_error_text(exc: Exception) -> str:
        text = str(exc)
        prefix = "SAVE_FAILED: failed to save program: "
        if text.startswith(prefix):
            return text[len(prefix) :]
        return text

    @staticmethod
    def _project_close_error_text(exc: Exception) -> str:
        text = str(exc)
        prefix = "PROJECT_CLOSE_FAILED: failed to close project: "
        if text.startswith(prefix):
            return text[len(prefix) :]
        return text

    def _ensure_repository_connected_locked(self, *, required: bool) -> bool:
        if not self.is_repository_project_from_metadata(self.project_location, self.project_name):
            return False
        repository = self._get_repository_adapter_locked()
        if repository is None:
            message = (
                "SHARED_PROJECT_UNAVAILABLE: shared project metadata exists, "
                "but no repository adapter is attached"
            )
            if required:
                raise RuntimeError(message)
            logger.debug(message)
            return False

        is_connected = getattr(repository, "isConnected", None)
        if is_connected is None:
            return True
        try:
            connected = bool(is_connected())
        except Exception as exc:
            raise RuntimeError(
                f"REPOSITORY_CONNECT_FAILED: failed to query repository connection state: {exc}"
            ) from exc
        if connected:
            verify_connection = getattr(repository, "verifyConnection", None)
            if verify_connection is None:
                return True
            try:
                verified = bool(verify_connection())
            except Exception as exc:
                raise RuntimeError(
                    f"REPOSITORY_CONNECT_FAILED: failed to verify repository connection: {exc}"
                ) from exc
            if verified:
                return True
            raise RuntimeError(
                "REPOSITORY_CONNECT_FAILED: repository connection verification failed"
            )

        connect = getattr(repository, "connect", None)
        if connect is None:
            raise RuntimeError("SHARED_PROJECT_UNAVAILABLE: repository adapter does not support connect()")
        try:
            connect()
        except Exception as exc:
            raise RuntimeError(f"REPOSITORY_CONNECT_FAILED: failed to connect to repository: {exc}") from exc
        try:
            connected = bool(is_connected())
        except Exception as exc:
            raise RuntimeError(
                f"REPOSITORY_CONNECT_FAILED: failed to re-check repository connection state: {exc}"
            ) from exc
        if not connected:
            raise RuntimeError("REPOSITORY_CONNECT_FAILED: repository is not connected after connect()")
        return True

    def _verify_repository_connected_after_refresh_locked(self) -> None:
        repository = self._get_repository_adapter_locked()
        if repository is None:
            raise RuntimeError(
                "PROJECT_DATA_REFRESH_FAILED: repository adapter became unavailable during refresh"
            )
        is_connected = getattr(repository, "isConnected", None)
        if is_connected is None:
            return
        try:
            connected = bool(is_connected())
        except Exception as exc:
            raise RuntimeError(
                "PROJECT_DATA_REFRESH_FAILED: failed to verify repository connection after refresh: "
                f"{exc}"
            ) from exc
        if not connected:
            raise RuntimeError(
                "PROJECT_DATA_REFRESH_FAILED: repository disconnected during project data refresh"
            )
        verify_connection = getattr(repository, "verifyConnection", None)
        if verify_connection is None:
            return
        try:
            verified = bool(verify_connection())
        except Exception as exc:
            raise RuntimeError(
                "PROJECT_DATA_REFRESH_FAILED: failed to verify repository connection after refresh: "
                f"{exc}"
            ) from exc
        if not verified:
            raise RuntimeError(
                "PROJECT_DATA_REFRESH_FAILED: repository connection verification failed after refresh"
            )

    def _get_repository_adapter_locked(self):
        project = None
        get_project = getattr(self.project, "getProject", None)
        if get_project is not None:
            try:
                project = get_project()
            except Exception as exc:
                logger.debug("failed to resolve wrapped project for repository lookup: %s", exc)
        if project is not None:
            get_repository = getattr(project, "getRepository", None)
            if get_repository is not None:
                try:
                    repository = get_repository()
                    if repository is not None:
                        return repository
                except Exception as exc:
                    logger.debug("failed to resolve project repository adapter: %s", exc)

        project_data = self.project.getProjectData()
        get_repository = getattr(project_data, "getRepository", None)
        if get_repository is None:
            return None
        try:
            return get_repository()
        except Exception as exc:
            logger.debug("failed to resolve project data repository adapter: %s", exc)
            return None

    def _collect_program_files_with_sync_locked(self, folder, results: list[Dict[str, Any]]) -> None:
        for domain_file in list(folder.getFiles()):
            if domain_file.getContentType() != "Program":
                continue
            item: Dict[str, Any] = {
                "domain_path": domain_file.getPathname(),
                "domain_name": domain_file.getName(),
                "contentType": domain_file.getContentType(),
            }
            item.update(self._program_sync_summary(domain_file))
            results.append(item)
        for sub in list(folder.getFolders()):
            self._collect_program_files_with_sync_locked(sub, results)

    @staticmethod
    def _program_sync_summary(domain_file) -> Dict[str, Any]:
        try:
            status = sync_utils._sync_status_from_domain_file(domain_file)
        except Exception as exc:
            logger.debug("failed to read sync status while listing project program: %s", exc)
            return {
                "is_versioned": None,
                "version": None,
                "latest_version": None,
                "is_latest_version": None,
                "can_add_to_repository": None,
                "sync_status_error": ProjectHandle._short_error(exc),
            }
        return {
            "is_versioned": status.get("is_versioned"),
            "version": status.get("version"),
            "latest_version": status.get("latest_version"),
            "is_latest_version": status.get("is_latest_version"),
            "can_add_to_repository": status.get("can_add_to_repository"),
            "sync_status_error": None,
        }

    @staticmethod
    def _short_error(exc: Exception) -> str:
        message = str(exc).strip() or exc.__class__.__name__
        if len(message) > 200:
            return message[:197] + "..."
        return message

    def _get_domain_file_locked(self, domain_path: str):
        if not domain_path:
            raise ValueError("domain_path is required")
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Program not found: {domain_path}")
        return domain_file

    def _import_program_auto_locked(self, path: pathlib.Path, program_dir: str, program_name: str):
        program = None
        domain_file = None
        operation_error = None
        try:
            java_file = pycore.JClass("java.io.File")(str(path))
            program = self.project.importProgram(java_file)
            self.project.saveAs(program, program_dir, program_name, True)
            domain_file = program.getDomainFile()
            return domain_file
        except Exception as exc:
            operation_error = exc
            raise
        finally:
            if program is not None:
                try:
                    self.project.close(program)
                except Exception as close_exc:
                    if operation_error is not None:
                        raise _ImportedProgramCloseError(
                            "PROGRAM_CLOSE_FAILED: failed to close imported program after "
                            f"auto import failure for {path}: {close_exc}; "
                            f"original error: {operation_error}"
                        ) from operation_error
                    domain_path = None
                    if domain_file is not None:
                        try:
                            domain_path = domain_file.getPathname()
                        except Exception:
                            domain_path = None
                    imported_name = domain_path or program_name
                    raise _ImportedProgramCloseError(
                        f"PROGRAM_CLOSE_FAILED: failed to close imported program {imported_name}: {close_exc}"
                    ) from close_exc

    def _import_program_raw_locked(
        self,
        path: pathlib.Path,
        *,
        program_dir: str,
        program_name: str,
        language_id: str,
        compiler_spec_id: str | None,
        base_address: str | None,
        file_offset: int | None,
        length: int | None,
        block_name: str | None,
        overlay: bool,
    ):
        monitor = java_bindings._console_monitor()
        loader_factory = getattr(pyghidra, "program_loader", None)
        builder_factory = loader_factory or (lambda: pycore.JClass("ghidra.app.util.importer.ProgramLoader").builder())
        loader_value = "ghidra.app.util.opinion.BinaryLoader"
        try:
            loader_value = pycore.JClass(loader_value)
        except Exception:
            pass
        builder = (
            builder_factory()
            .project(self.project.getProject())
            .projectFolderPath(program_dir)
            .source(str(path))
            .name(program_name)
            .loaders(loader_value)
            .language(language_id)
        )
        if compiler_spec_id is not None:
            builder = builder.compiler(compiler_spec_id)

        loader_args = {
            "Base Address": base_address,
            "File Offset": file_offset,
            "Length": length,
            "Block Name": block_name,
        }
        requested_loader_options = {option_name for option_name, value in loader_args.items() if value is not None}
        if overlay:
            requested_loader_options.add("Overlay")
        loader_option_args = self._resolve_binary_loader_args_locked(
            builder,
            required_options=requested_loader_options,
        )
        for option_name, value in loader_args.items():
            if value is None:
                continue
            option_arg = loader_option_args.get(option_name)
            if option_arg is None:
                raise RuntimeError(f"RAW_LOADER_OPTION_UNAVAILABLE: {option_name}")
            builder = builder.addLoaderArg(option_arg, str(value))
        if overlay:
            option_arg = loader_option_args.get("Overlay")
            if option_arg is None:
                raise RuntimeError("RAW_LOADER_OPTION_UNAVAILABLE: Overlay")
            builder = builder.addLoaderArg(option_arg, "true")

        load_results = builder.load()
        domain_file = None
        operation_error = None
        try:
            loaded_program = load_results.getPrimary()
            if loaded_program is None:
                raise RuntimeError(f"Failed to add program: {path}")
            domain_file = loaded_program.save(monitor)
            return domain_file
        except Exception as exc:
            operation_error = exc
            raise
        finally:
            try:
                load_results.close()
            except Exception as close_exc:
                if operation_error is not None:
                    raise _ImportedProgramCloseError(
                        "PROGRAM_CLOSE_FAILED: failed to close raw import results after "
                        f"import failure for {path}: {close_exc}; "
                        f"original error: {operation_error}"
                    ) from operation_error
                domain_path = None
                if domain_file is not None:
                    try:
                        domain_path = domain_file.getPathname()
                    except Exception:
                        domain_path = None
                imported_name = domain_path or program_name
                raise _ImportedProgramCloseError(
                    "PROGRAM_CLOSE_FAILED: failed to close raw import results for imported program "
                    f"{imported_name}: {close_exc}"
                ) from close_exc

    def _post_process_imported_program_locked(
        self,
        domain_path: str,
        *,
        entry_address: str | None,
        entry_offset: int | None,
        analyze_imported: bool,
    ) -> None:
        monitor = java_bindings._console_monitor()
        domain_dir, domain_name = path_utils._parse_domain_path(self.project, domain_path)
        program = self.project.openProgram(domain_dir, domain_name, False)
        if program is None:
            raise RuntimeError(f"Failed to reopen imported program: {domain_path}")
        operation_error = None
        try:
            flat_api = java_bindings._flat_program_api_class()(program, monitor)
            entry = self._resolve_entry_address_locked(
                program,
                entry_address=entry_address,
                entry_offset=entry_offset,
            )
            if entry is not None:
                self._bootstrap_entry_locked(program, flat_api, entry)
            if analyze_imported:
                self._analyze_program_locked(program, flat_api)
            self.project.save(program)
        except Exception as exc:
            operation_error = exc
            raise
        finally:
            try:
                self.project.close(program)
            except Exception as close_exc:
                if operation_error is not None:
                    raise _ImportedProgramCloseError(
                        "PROGRAM_CLOSE_FAILED: failed to close imported program "
                        f"{domain_path} after post-processing failure: {close_exc}; "
                        f"original error: {operation_error}"
                    ) from operation_error
                raise _ImportedProgramCloseError(
                    f"PROGRAM_CLOSE_FAILED: failed to close imported program {domain_path}: {close_exc}"
                ) from close_exc

    def _resolve_entry_address_locked(
        self,
        program,
        *,
        entry_address: str | None,
        entry_offset: int | None,
    ):
        if entry_address is not None:
            return self._address_from_int_locked(program, int(entry_address, 0))
        if entry_offset is None:
            return None
        min_address = self._get_imported_min_address_locked(program)
        return self._address_from_int_locked(program, int(min_address.getOffset()) + int(entry_offset))

    def _bootstrap_entry_locked(self, program, flat_api, entry) -> None:
        tx = program.startTransaction("Bootstrap imported entry")
        committed = False
        try:
            listing = program.getListing()
            function_manager = program.getFunctionManager()
            symbol_table = program.getSymbolTable()
            if listing.getInstructionAt(entry) is None:
                flat_api.disassemble(entry)
            if function_manager.getFunctionAt(entry) is None:
                flat_api.createFunction(entry, None)
            if not bool(symbol_table.isExternalEntryPoint(entry)):
                flat_api.addEntryPoint(entry)
            committed = True
        finally:
            program.endTransaction(tx, committed)

    def _analyze_program_locked(self, program, flat_api) -> None:
        utilities = java_bindings._ghidra_program_utilities()
        if not bool(utilities.shouldAskToAnalyze(program)):
            return
        script_util = java_bindings._ghidra_script_util()
        script_util.acquireBundleHostReference()
        try:
            flat_api.analyzeAll(program)
            utilities.markProgramAnalyzed(program)
        finally:
            script_util.releaseBundleHostReference()

    def _get_imported_min_address_locked(self, program):
        memory = program.getMemory()
        for getter_name in ("getLoadedAndInitializedAddressSet", "getLoadedAddressSet"):
            getter = getattr(memory, getter_name, None)
            if getter is None:
                continue
            address_set = getter()
            if address_set is None:
                continue
            min_address = address_set.getMinAddress()
            if min_address is not None:
                return min_address
        for getter_name in ("getImageBase", "getMinAddress"):
            getter = getattr(program, getter_name, None)
            if getter is None:
                continue
            address = getter()
            if address is not None:
                return address
        raise RuntimeError("Failed to resolve imported program base address")

    def _address_from_int_locked(self, program, value: int):
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        if address_space is None:
            raise RuntimeError("Program has no default address space")
        return address_space.getAddress(int(value))

    def _resolve_binary_loader_args_locked(
        self,
        builder,
        *,
        required_options: set[str] | None = None,
    ) -> dict[str, str]:
        required_options = required_options or set()
        fallback = {
            "Base Address": "Base Address",
            "File Offset": "File Offset",
            "Length": "Length",
            "Block Name": "Block Name",
            "Overlay": "Overlay",
        }
        try:
            builder_class = builder.getClass()
            byte_provider_class = pycore.JClass("ghidra.app.util.bin.ByteProvider")
            load_spec_class = pycore.JClass("ghidra.app.util.opinion.LoadSpec")
            get_source = builder_class.getDeclaredMethod("getSourceAsProvider")
            get_source.setAccessible(True)
            provider = get_source.invoke(builder)
            try:
                get_load_spec = builder_class.getDeclaredMethod("getLoadSpec", byte_provider_class.class_)
                get_load_spec.setAccessible(True)
                load_spec = get_load_spec.invoke(builder, provider)
                get_loader_options = builder_class.getDeclaredMethod(
                    "getLoaderOptions",
                    byte_provider_class.class_,
                    load_spec_class.class_,
                )
                get_loader_options.setAccessible(True)
                options = get_loader_options.invoke(builder, provider, load_spec)
            finally:
                close = getattr(provider, "close", None)
                if close is not None:
                    close()
            if options is None:
                if required_options:
                    requested = ", ".join(sorted(required_options))
                    raise RuntimeError(f"failed to resolve BinaryLoader option metadata for: {requested}")
                return dict(fallback)
            resolved = {} if required_options else dict(fallback)
            for option in options:
                option_name = option.getName()
                option_arg = option.getArg()
                if option_name is None or option_arg is None:
                    continue
                resolved[str(option_name)] = str(option_arg)
            return resolved
        except Exception as exc:
            if required_options:
                raise RuntimeError(f"RAW_LOADER_OPTION_UNAVAILABLE: failed to resolve BinaryLoader options: {exc}") from exc
            logger.debug("failed to resolve binary loader option args; using fallback names: %s", exc)
            return fallback


__all__ = ["ProjectHandle"]
