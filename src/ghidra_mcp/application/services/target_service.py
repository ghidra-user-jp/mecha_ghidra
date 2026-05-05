"""Target lifecycle service."""

from __future__ import annotations

from ghidra_mcp.application.services.ports import TargetRuntimePort
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.locks import LockManager


class TargetService:
    def __init__(self, runtime_state: TargetRuntimePort, *, lock_manager: LockManager | None = None) -> None:
        self._runtime = runtime_state
        self._lock_manager = lock_manager or LockManager()

    def _to_domain_error(self, exc: Exception, *, operation: str, target: str | None = None) -> DomainError:
        if isinstance(exc, DomainError):
            details = dict(exc.details or {})
            details.setdefault("operation", operation)
            if target is not None:
                details.setdefault("target", target)
            return DomainError(
                code=exc.code,
                message=exc.message,
                hint=exc.hint,
                retryable=exc.retryable,
                details=details,
            )

        return DomainError(
            code=ErrorCode.OPERATION_FAILED,
            message=str(exc),
            hint="Check target/session state for this operation",
            retryable=False,
            details={"operation": operation, "target": target},
        )

    def _project_key(self, target: str) -> str | None:
        return self._runtime.project_lock_key(target)

    def _raise_domain_error(self, exc: Exception, *, operation: str, target: str | None = None) -> None:
        raise self._to_domain_error(exc, operation=operation, target=target) from exc

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name):
                session = self._runtime.create_session(
                    name,
                    project_location,
                    project_name=project_name,
                    domain_path=domain_path,
                )
                info = {}
                if hasattr(session, "to_dict"):
                    info = session.to_dict()
                elif isinstance(session, dict):
                    info = dict(session)
                return {
                    "target": name,
                    "project_location": info.get("project_location", project_location),
                    "project_name": info.get("project_name", project_name),
                    "domain_path": info.get("domain_path", domain_path),
                }
        except Exception as exc:
            self._raise_domain_error(exc, operation="create_session", target=name)

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None):
        try:
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

    def load_program(self, name: str, domain_path: str):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.load_program(name, domain_path)
        except Exception as exc:
            self._raise_domain_error(exc, operation="load_program", target=name)

    def import_program(self, name: str, binary_path: str, **kwargs):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.import_program(name, binary_path, **kwargs)
        except Exception as exc:
            self._raise_domain_error(exc, operation="import_program", target=name)

    def save_project_program(self, name: str, *, domain_path: str | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.save_project_program(name, domain_path=domain_path)
        except Exception as exc:
            self._raise_domain_error(exc, operation="save_project_program", target=name)

    def close_session(self, name: str, *, remove_program: bool = False):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                self._runtime.close_session(name, remove_program=remove_program)
                return {"closed": True, "target": name, "remove_program": bool(remove_program)}
        except Exception as exc:
            self._raise_domain_error(exc, operation="close_session", target=name)

    def close_all(self) -> None:
        return self._runtime.close_all()

    def has_sessions(self) -> bool:
        return self._runtime.has_sessions()

    def has_targets(self) -> bool:
        return self._runtime.has_targets()


__all__ = ["TargetService"]
