"""Target/project lock acquisition shared by every sync operation."""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Iterator

from ghidra_headless.errors import HeadlessError
from ghidra_mcp.application.locks import acquire_ordered_locks
from ghidra_mcp.domain import LOCK_ORDER, DomainError, ErrorCode, get_lock_timeout_seconds

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class SyncLockingMixin:
    """Mixin for :class:`RuntimeSyncOperations`; expects ``self._store``."""

    _store: RuntimeSessionStore

    @contextlib.contextmanager
    def _target_operation(self, name: str, *, exclusive: bool = False) -> Iterator[None]:
        operation_lock = (
            self._store.operation_lock.write_lock() if exclusive else self._store.operation_lock.read_lock()
        )
        with operation_lock:
            with self._store.registry_lock.write_lock():
                lock = self._store.ensure_lock(name)
                project_key = self._store.get_target_project_key_locked(name)
            with acquire_ordered_locks(
                [("target", lock)],
                message_prefix="runtime ",
            ):
                requested_handle = self._store.get_target_handle(name)
                snapshot_timeout = get_lock_timeout_seconds()
                snapshot_deadline = time.monotonic() + snapshot_timeout
                while True:
                    with self._store.registry_lock.read_lock():
                        handle_snapshot = dict(self._store.project_handles)

                    project_keys = {project_key}
                    for candidate_key, candidate_handle in handle_snapshot.items():
                        try:
                            if candidate_handle.is_closed():
                                continue
                            if self._handles_share_project_identity(
                                requested_handle,
                                candidate_handle,
                            ):
                                project_keys.add(candidate_key)
                        except Exception as exc:
                            raise HeadlessError(
                                f"SYNC_STATUS_UNAVAILABLE: failed to determine project lock identity: {exc}"
                            ) from exc

                    with self._store.registry_lock.write_lock():
                        snapshot_unchanged = len(handle_snapshot) == len(self._store.project_handles) and all(
                            self._store.project_handles.get(key) is handle for key, handle in handle_snapshot.items()
                        )
                        if snapshot_unchanged:
                            project_locks = [
                                self._store.ensure_project_lock(key)
                                for key in sorted(
                                    project_keys,
                                    key=lambda item: (str(item[0]), str(item[1])),
                                )
                            ]
                        else:
                            project_locks = []

                    if not snapshot_unchanged:
                        if time.monotonic() >= snapshot_deadline:
                            raise DomainError(
                                code=ErrorCode.LOCK_TIMEOUT,
                                message="Failed to stabilize runtime project lock identity",
                                hint=f"Lock acquisition order: {' -> '.join(LOCK_ORDER)}",
                                retryable=True,
                                details={
                                    "lock": "registry_snapshot",
                                    "timeout": snapshot_timeout,
                                },
                            )
                        continue

                    named_project_locks = [("project", project_lock) for project_lock in project_locks]
                    with acquire_ordered_locks(
                        named_project_locks,
                        message_prefix="runtime ",
                    ):
                        with self._store.registry_lock.read_lock():
                            still_unchanged = len(handle_snapshot) == len(self._store.project_handles) and all(
                                self._store.project_handles.get(key) is handle
                                for key, handle in handle_snapshot.items()
                            )
                        if not still_unchanged:
                            if time.monotonic() >= snapshot_deadline:
                                raise DomainError(
                                    code=ErrorCode.LOCK_TIMEOUT,
                                    message="Failed to stabilize runtime project lock identity",
                                    hint=f"Lock acquisition order: {' -> '.join(LOCK_ORDER)}",
                                    retryable=True,
                                    details={
                                        "lock": "registry_snapshot",
                                        "timeout": snapshot_timeout,
                                    },
                                )
                            continue
                        yield
                        return
