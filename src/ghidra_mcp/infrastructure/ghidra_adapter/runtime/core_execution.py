"""Core command execution delegate for runtime backend."""

from __future__ import annotations

from typing import Any, Dict

from .session_store import RuntimeSessionStore


class RuntimeCoreExecution:
    def __init__(
        self,
        *,
        store: RuntimeSessionStore,
        checkout_required_commands: set[str],
        normalize_result,
    ) -> None:
        self._store = store
        self._checkout_required_commands = set(checkout_required_commands)
        self._normalize_result = normalize_result

    def call(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        with self._store.registry_lock.read_lock():
            self._store.ensure_session(target)
            lock = self._store.ensure_lock(target)
            with lock:
                self._ensure_checkout_for_mutating_command_locked(command, target)
                result = self._store.core_accessor().execute(command, params or {}, key=target)
                return self._normalize_result(result)

    def _ensure_checkout_for_mutating_command_locked(self, command: str, target: str) -> None:
        if command not in self._checkout_required_commands:
            return
        session = self._store.sessions.get(target)
        if session is None:
            return
        handle = session.get_project_handle()
        domain_path = self._store.session_domain_path(session)
        status = handle.get_sync_status(domain_path)
        if not status.get("is_versioned"):
            return
        if status.get("is_checked_out"):
            return
        raise RuntimeError(
            "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects. "
            "Run checkout_project_program first"
        )


__all__ = ["RuntimeCoreExecution"]
