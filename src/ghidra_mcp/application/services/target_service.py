"""Target lifecycle service."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ghidra_mcp.application.locks import LockManager
from ghidra_mcp.application.services.path_policy import UNRESTRICTED_PATH_POLICY, PathPolicy
from ghidra_mcp.application.services.ports import LoadedProgram, OperationControl, TargetRuntimePort
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_mapping import to_domain_error


class TargetService:
    def __init__(
        self,
        runtime_state: TargetRuntimePort,
        *,
        lock_manager: LockManager | None = None,
        path_policy: PathPolicy | None = None,
    ) -> None:
        self._runtime = runtime_state
        self._lock_manager = lock_manager or LockManager()
        self._path_policy = path_policy or UNRESTRICTED_PATH_POLICY

    @property
    def path_policy(self) -> PathPolicy:
        return self._path_policy

    def _to_domain_error(self, exc: Exception, *, operation: str, target: str | None = None) -> DomainError:
        return to_domain_error(
            exc,
            operation=operation,
            target=target,
            hint="Check target/session state for this operation",
            cause_detail_codes={ErrorCode.PROJECT_LOCKED, ErrorCode.SAVE_FAILED},
            keep_none_details=("target",),
        )

    def _project_key(self, target: str) -> str | None:
        return self._runtime.project_lock_key(target)

    def project_key(self, target: str) -> str | None:
        """The ``location::name`` key of the project ``target`` is bound to, or None."""
        return self._project_key(target)

    def _raise_domain_error(self, exc: Exception, *, operation: str, target: str | None = None) -> None:
        raise self._to_domain_error(exc, operation=operation, target=target) from exc

    def create_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        overwrite: bool = False,
    ):
        try:
            self._path_policy.validate_project_location(project_location)
            return self._runtime.create_project(
                project_location,
                project_name=project_name,
                overwrite=overwrite,
            )
        except Exception as exc:
            self._raise_domain_error(exc, operation="create_project")

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
        validate: Callable[[], None] | None = None,
    ):
        try:
            self._path_policy.validate_project_location(project_location)
            with self._lock_manager.acquire(target=name):
                validation_options = {"validate": validate} if validate is not None else {}
                session = self._runtime.create_session(
                    name,
                    project_location,
                    project_name=project_name,
                    domain_path=domain_path,
                    **validation_options,
                )
                info = {}
                if hasattr(session, "to_dict"):
                    info = session.to_dict()
                elif isinstance(session, dict):
                    info = dict(session)
                is_analyzed = getattr(session, "is_analyzed", None)
                return {
                    "target": name,
                    "project_location": info.get("project_location", project_location),
                    "project_name": info.get("project_name", project_name),
                    "domain_path": info.get("domain_path", domain_path),
                    # Opening never analyzes; false tells the caller to run analyze_program.
                    "is_analyzed": bool(is_analyzed() if callable(is_analyzed) else info.get("is_analyzed", False)),
                }
        except Exception as exc:
            self._raise_domain_error(exc, operation="create_session", target=name)

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None):
        try:
            self._path_policy.validate_project_location(project_location)
            with self._lock_manager.acquire(target=name):
                return self._runtime.register_target(name, project_location, project_name=project_name)
        except Exception as exc:
            self._raise_domain_error(exc, operation="register_target", target=name)

    def list_targets(self):
        return self._runtime.list_targets()

    def list_programs(self, name: str):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.list_programs(name)
        except Exception as exc:
            self._raise_domain_error(exc, operation="list_programs", target=name)

    def load_program(self, name: str, domain_path: str, *, version: int | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.load_program(name, domain_path, version=version)
        except Exception as exc:
            self._raise_domain_error(exc, operation="load_program", target=name)

    def validate_export_path(self, output_path: str) -> str:
        """Validate ``--allowed-export-root`` and return the path to write."""
        return self._path_policy.validate_export_path(output_path)

    def create_repository_cache_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        repository_url: str,
    ):
        try:
            self._path_policy.validate_project_location(project_location)
            return self._runtime.create_repository_cache_project(
                project_location,
                project_name=project_name,
                repository_url=repository_url,
            )
        except Exception as exc:
            self._raise_domain_error(exc, operation="create_repository_cache_project")

    def prepare_import(self, name: str, binary_path: str) -> tuple[str, str]:
        """Resolve an import request without opening a project.

        Returns the absolute input path and the project key the target is
        registered to; only registration metadata and the input file are read.
        """
        try:
            try:
                # absolute(), not resolve(): with a symlinked directory,
                # "link/../x.bin" must keep naming the file it names today.
                path = str(Path(binary_path).expanduser().absolute())
                self._path_policy.validate_import_path(path)
            except RuntimeError as exc:
                # Unknown "~user" or a symlink loop: an input problem, reported
                # without echoing the resolved server path.
                raise ValueError(f"binary_path cannot be resolved: {exc}") from exc
            if not Path(path).is_file():
                raise DomainError(
                    ErrorCode.VALIDATION_ERROR,
                    f"Binary is not a file: {path}",
                    hint="binary_path must name an existing regular file on the server",
                    details={"field": "binary_path"},
                )
            key = self._project_key(name)
            if key is None:
                raise DomainError(ErrorCode.TARGET_NOT_REGISTERED, "Target is not registered", details={"target": name})
            return path, key
        except Exception as exc:
            self._raise_domain_error(exc, operation="import_program", target=name)

    def import_program(self, name: str, binary_path: str, *, control: OperationControl | None = None, **options):
        try:
            self._path_policy.validate_import_path(binary_path)
            project_key = self._project_key(name) if control is None else control.expected_project_key
            with self._lock_manager.acquire(target=name, project_key=project_key):
                if control is None:
                    return self._runtime.import_program(name, binary_path, **options)
                return self._runtime.import_program(name, binary_path, control=control, **options)
        except Exception as exc:
            self._raise_domain_error(exc, operation="import_program", target=name)

    def prepare_analysis(self, name: str) -> LoadedProgram:
        """Resolve an analysis request from registry state only, without Ghidra locks."""
        try:
            return self._runtime.loaded_program(name)
        except Exception as exc:
            self._raise_domain_error(exc, operation="analyze_program", target=name)

    def analyze_program(self, name: str, *, force: bool = False, control: OperationControl):
        # Like every core command, the analysis takes only the runtime's
        # target/project locks, not this service's lock manager.
        try:
            return self._runtime.analyze_program(name, force=force, control=control)
        except Exception as exc:
            self._raise_domain_error(exc, operation="analyze_program", target=name)

    def save_project_program(self, name: str, *, domain_path: str | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.save_project_program(name, domain_path=domain_path)
        except Exception as exc:
            self._raise_domain_error(exc, operation="save_project_program", target=name)

    def close_session(self, name: str, *, remove_program: bool = False, discard_changes: bool = False):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                if discard_changes:
                    self._runtime.close_session(name, remove_program=remove_program, discard_changes=True)
                else:
                    self._runtime.close_session(name, remove_program=remove_program)
                return {
                    "closed": True,
                    "target": name,
                    "remove_program": bool(remove_program),
                    "discard_changes": bool(discard_changes),
                }
        except Exception as exc:
            self._raise_domain_error(exc, operation="close_session", target=name)

    def close_all(self) -> None:
        return self._runtime.close_all()

    def has_sessions(self) -> bool:
        return self._runtime.has_sessions()

    def has_targets(self) -> bool:
        return self._runtime.has_targets()


__all__ = ["TargetService"]
