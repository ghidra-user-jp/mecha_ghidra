from __future__ import annotations

import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.core_execution import RuntimeCoreExecution
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore


class _Core:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, str]] = []
        self.initialized: list[tuple[object, str]] = []
        self.removed: list[str] = []

    def execute(self, command: str, params: dict, *, key: str):
        self.calls.append((command, params, key))
        return {"status": "ok"}

    def initialize(self, program, key: str):  # noqa: ANN001
        self.initialized.append((program, key))

    def remove_context(self, key: str) -> None:
        self.removed.append(key)


class _DomainFile:
    def getPathname(self) -> str:
        return "/main"


class _Program:
    def __init__(self, *, changed: bool = False, fail_changed: bool = False) -> None:
        self._changed = changed
        self._fail_changed = fail_changed

    def getDomainFile(self):
        return _DomainFile()

    def isChanged(self) -> bool:
        if self._fail_changed:
            raise RuntimeError("dirty state unavailable")
        return self._changed


class _Session:
    def __init__(self, handle, *, changed: bool = False, fail_changed: bool = False) -> None:  # noqa: ANN001
        self._handle = handle
        self._changed = changed
        self._fail_changed = fail_changed
        self.closed_with: list[bool] = []

    def get_project_handle(self):
        return self._handle

    def get_program(self):
        return _Program(changed=self._changed, fail_changed=self._fail_changed)

    def close(self, *, save: bool = True) -> None:
        self.closed_with.append(save)


class _FailingCloseSession(_Session):
    def close(self, *, save: bool = True) -> None:
        self.closed_with.append(save)
        raise RuntimeError("reopened close failed")


class _Handle:
    def __init__(self) -> None:
        self.refresh_calls = 0
        self._status = {
            "is_versioned": False,
            "is_checked_out": False,
        }

    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_calls += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_checked_out": False,
            }
        )

    def get_sync_status(self, _domain_path: str):
        return dict(self._status)


class _CheckedOutAfterRefreshHandle(_Handle):
    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_calls += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_checked_out": True,
            }
        )


class _FailingRefreshHandle(_Handle):
    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_calls += 1
        raise RuntimeError("refresh failed")


class _ReopenVersionedHandle(_Handle):
    def __init__(self) -> None:
        super().__init__()
        self.open_program_calls = 0
        self._closed = False
        self._status["can_add_to_repository"] = True

    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_calls += 1

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_checked_out": False,
                "can_add_to_repository": False,
            }
        )
        return _Session(self)

    def get_project_location(self) -> str:
        return "/tmp/prj"

    def get_project_name(self) -> str:
        return "sample"

    def get_key(self) -> tuple[str, str]:
        return ("/tmp/prj", "sample")

    def is_closed(self) -> bool:
        return self._closed


class _UnversionedAddableHandle(_ReopenVersionedHandle):
    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        return _Session(self)


class _FailingCloseReopenHandle(_ReopenVersionedHandle):
    def __init__(self) -> None:
        super().__init__()
        self.reopened_sessions: list[_FailingCloseSession] = []

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_checked_out": False,
                "can_add_to_repository": False,
            }
        )
        reopened = _FailingCloseSession(self)
        self.reopened_sessions.append(reopened)
        return reopened


def _build_core_execution(
    handle,  # noqa: ANN001
    *,
    changed: bool = False,
    fail_changed: bool = False,
) -> tuple[RuntimeCoreExecution, RuntimeSessionStore, _Core]:
    core = _Core()
    state = RuntimeState(
        core_accessor=lambda: core,
        checkout_required_commands={"rename_function"},
        normalize_result=lambda value: value,
    )
    store = RuntimeSessionStore(state=state, core_accessor=lambda: core)
    store.sessions["fw"] = _Session(handle, changed=changed, fail_changed=fail_changed)
    store.locks["fw"] = threading.RLock()
    return (
        RuntimeCoreExecution(
            store=store,
            checkout_required_commands={"rename_function"},
            normalize_result=lambda value: value,
        ),
        store,
        core,
    )


def test_mutating_checkout_guard_refreshes_external_version_control_state():
    handle = _Handle()
    execution, _store, core = _build_core_execution(handle)

    with pytest.raises(RuntimeError, match="CHECKOUT_REQUIRED"):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert handle.refresh_calls == 1
    assert core.calls == []


def test_mutating_checkout_guard_allows_checked_out_state_after_refresh():
    handle = _CheckedOutAfterRefreshHandle()
    execution, store, core = _build_core_execution(handle)

    result = execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert result == {"status": "ok"}
    assert handle.refresh_calls == 1
    assert core.calls == [("rename_function", {"oldName": "old", "newName": "new"}, "fw")]
    assert store.is_dirty_program("fw", "/main")


def test_mutating_checkout_guard_aborts_when_refresh_fails():
    handle = _FailingRefreshHandle()
    execution, _store, core = _build_core_execution(handle)

    with pytest.raises(RuntimeError, match="SYNC_OPERATION_FAILED"):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert handle.refresh_calls == 1
    assert core.calls == []


def test_mutating_checkout_guard_reopens_stale_unversioned_active_program():
    handle = _ReopenVersionedHandle()
    execution, _store, core = _build_core_execution(handle)

    with pytest.raises(RuntimeError, match="CHECKOUT_REQUIRED"):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 1
    assert core.calls == []


def test_mutating_checkout_guard_preserves_reopened_session_when_rollback_close_fails():
    handle = _FailingCloseReopenHandle()
    execution, store, core = _build_core_execution(handle)
    original_initialize = core.initialize

    def fail_initialize(_program, _key):  # noqa: ANN001
        raise RuntimeError("initialize failed")

    core.initialize = fail_initialize

    with pytest.raises(
        RuntimeError,
        match="PROGRAM_CLOSE_FAILED: failed to close reopened session during checkout guard rollback",
    ):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert store.sessions["fw"] is handle.reopened_sessions[-1]
    assert "fw" in store.locks
    assert core.calls == []
    assert core.removed == []
    core.initialize = original_initialize


def test_mutating_checkout_guard_rejects_dirty_stale_unversioned_active_program():
    handle = _ReopenVersionedHandle()
    execution, _store, core = _build_core_execution(handle, changed=True)

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 0
    assert core.calls == []


def test_mutating_checkout_guard_fails_closed_when_dirty_state_unavailable():
    handle = _ReopenVersionedHandle()
    execution, _store, core = _build_core_execution(handle, fail_changed=True)

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 0
    assert core.calls == []


def test_mutating_checkout_guard_allows_repeated_mcp_mutations_on_unversioned_program():
    handle = _UnversionedAddableHandle()
    execution, store, core = _build_core_execution(handle)

    result = execution.call("rename_function", {"oldName": "old", "newName": "new"}, target="fw")
    assert result == {"status": "ok"}
    assert store.is_dirty_program("fw", "/main")

    result = execution.call("rename_function", {"oldName": "new", "newName": "newer"}, target="fw")

    assert result == {"status": "ok"}
    assert handle.refresh_calls == 2
    assert handle.open_program_calls == 1
    assert core.calls == [
        ("rename_function", {"oldName": "old", "newName": "new"}, "fw"),
        ("rename_function", {"oldName": "new", "newName": "newer"}, "fw"),
    ]
