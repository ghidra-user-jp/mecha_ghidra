from __future__ import annotations

import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.sync_operations import RuntimeSyncOperations


class _DummyCore:
    def __init__(self) -> None:
        self.initialized: list[tuple[object, str]] = []
        self.removed: list[str] = []

    def initialize(self, program, key: str):  # noqa: ANN001
        self.initialized.append((program, key))

    def remove_context(self, key: str) -> None:
        self.removed.append(key)


class _FakeProject:
    def __init__(self) -> None:
        self.saved = 0

    def save(self, _program) -> None:  # noqa: ANN001
        self.saved += 1


class _FakeDomainFile:
    def __init__(self, path: str) -> None:
        self._path = path

    def getPathname(self) -> str:
        return self._path


class _FakeProgram:
    def __init__(self, path: str) -> None:
        self._path = path

    def getDomainFile(self):
        return _FakeDomainFile(self._path)


class _FakeSession:
    def __init__(self, handle, path: str):  # noqa: ANN001
        self._handle = handle
        self._path = path
        self.closed = 0

    def get_project_handle(self):
        return self._handle

    def get_program(self):
        return _FakeProgram(self._path)

    def close(self, *, remove_program: bool = False) -> None:  # noqa: ARG002
        self.closed += 1


class _FakeHandle:
    def __init__(self, project_location: str, project_name: str) -> None:
        self._location = project_location
        self._name = project_name
        self._key = (self._location, self._name)
        self.project = _FakeProject()
        self._closed = False
        self.fail_reopen = False
        self._status: dict[str, object] = {
            "is_versioned": True,
            "is_checked_out": False,
            "is_checked_out_exclusive": False,
            "modified_since_checkout": False,
            "can_merge": False,
            "can_checkout": True,
            "can_checkin": True,
            "version": 1,
            "latest_version": 1,
            "is_latest_version": True,
            "checkouts": [],
        }

    def get_key(self) -> tuple[str, str]:
        return self._key

    def get_project_location(self) -> str:
        return self._location

    def get_project_name(self) -> str:
        return self._name

    def is_closed(self) -> bool:
        return self._closed

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        return dict(self._status)

    def checkout_program(self, domain_path: str, *, exclusive: bool = False):  # noqa: ARG002
        self._status["is_checked_out"] = True
        self._status["is_checked_out_exclusive"] = bool(exclusive)
        return True

    def add_program_to_version_control(self, domain_path: str, comment: str, *, keep_checked_out: bool = False):  # noqa: ARG002
        self._status["is_versioned"] = True
        self._status["is_checked_out"] = bool(keep_checked_out)

    def commit_program(self, domain_path: str, message: str, *, keep_checked_out: bool = False):  # noqa: ARG002
        self._status["version"] = int(self._status["version"]) + 1
        self._status["latest_version"] = self._status["version"]
        self._status["is_checked_out"] = bool(keep_checked_out)
        self._status["is_latest_version"] = True

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):  # noqa: ARG002
        self._status["is_checked_out"] = bool(keep)

    def terminate_checkout_program(self, domain_path: str, checkout_id: int):  # noqa: ARG002
        return None

    def merge_program(self, domain_path: str, *, ok_to_upgrade: bool = True):  # noqa: ARG002
        self._status["can_merge"] = False
        self._status["is_latest_version"] = True

    def open_program(self, domain_path: str):
        if self.fail_reopen:
            raise RuntimeError("reopen failed")
        return _FakeSession(self, domain_path)

    def get_version_history(self, domain_path: str, *, limit: int = 50):  # noqa: ARG002
        return {"versions": [], "current_version": 1, "latest_version": 1, "limit": limit}

    def get_version_diff(
        self,
        domain_path: str,  # noqa: ARG002
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
    ):
        return {
            "from_version": from_version,
            "to_version": to_version,
            "range_limit": range_limit,
            "ranges": [],
        }


class _PatchedProjectHandle:
    @staticmethod
    def make_key(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")


def _build_sync_runtime(monkeypatch: pytest.MonkeyPatch) -> tuple[RuntimeSyncOperations, RuntimeSessionStore, _DummyCore, _FakeHandle]:
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as session_store_module

    monkeypatch.setattr(session_store_module, "ProjectHandle", _PatchedProjectHandle)

    core = _DummyCore()
    state = RuntimeState(
        core_accessor=lambda: core,
        checkout_required_commands=set(),
        normalize_result=lambda value: value,
    )
    store = RuntimeSessionStore(state=state, core_accessor=lambda: core)
    handle = _FakeHandle("/tmp/prj", "sample")
    session = _FakeSession(handle, "/main")
    store.sessions["fw"] = session
    store.locks["fw"] = threading.RLock()
    store.target_projects["fw"] = handle.get_key()
    store.project_handles[handle.get_key()] = handle
    return RuntimeSyncOperations(store=store), store, core, handle


def test_pull_abort_on_local_changes(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["modified_since_checkout"] = True  # noqa: SLF001

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")


def test_checkout_reloads_active_program_and_rebinds_context(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)

    result = sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert isinstance(store.sessions["fw"], _FakeSession)
    assert store.sessions["fw"] is not None
    assert handle._status["is_checked_out"] is True  # noqa: SLF001


def test_reload_reopen_failure_cleans_target_state(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    handle.fail_reopen = True

    with pytest.raises(RuntimeError, match="REOPEN_FAILED"):
        sync.reload_project_program("fw", domain_path="/main")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert core.removed == ["fw"]
