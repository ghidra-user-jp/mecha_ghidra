from __future__ import annotations

import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore


class _DummyCore:
    def __init__(self) -> None:
        self.removed: list[str] = []

    def remove_context(self, key: str) -> None:
        self.removed.append(key)


class _FakeProjectHandle:
    metadata_programs = None

    def __init__(self, project_location: str, project_name: str | None) -> None:
        self._key = (project_location, project_name or "")
        self._closed = False

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def make_key(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    def get_key(self) -> tuple[str, str]:
        return self._key

    def is_closed(self) -> bool:
        return self._closed


class _FakeSession:
    def __init__(self) -> None:
        self.closed_with: list[tuple[bool, bool]] = []

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))

    def get_project_handle(self):  # noqa: ANN001
        return _FakeProjectHandle("/tmp/prj", "sample")


def _build_store() -> tuple[RuntimeSessionStore, _DummyCore]:
    core = _DummyCore()
    state = RuntimeState(
        core_accessor=lambda: core,
        checkout_required_commands=set(),
        normalize_result=lambda value: value,
    )
    return RuntimeSessionStore(state=state, core_accessor=lambda: core), core


def test_get_or_create_project_handle_reuses_open_handle(monkeypatch: pytest.MonkeyPatch):
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as module

    monkeypatch.setattr(module, "ProjectHandle", _FakeProjectHandle)
    store, _core = _build_store()

    first = store.get_or_create_project_handle("/tmp/prj", "sample")
    second = store.get_or_create_project_handle("/tmp/prj", "sample")
    assert first is second

    first._closed = True  # noqa: SLF001
    third = store.get_or_create_project_handle("/tmp/prj", "sample")
    assert third is not first


def test_cleanup_session_removes_entries_and_context():
    store, core = _build_store()
    session = _FakeSession()
    handle = _FakeProjectHandle("/tmp/prj", "sample")
    handle._closed = True  # noqa: SLF001
    store.sessions["fw"] = session
    store.locks["fw"] = threading.RLock()
    store.project_handles[handle.get_key()] = handle

    store.cleanup_session(
        "fw",
        session,
        handle,
        remove_registry_entry=True,
        remove_context=True,
        remove_program=True,
    )

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert handle.get_key() not in store.project_handles
    assert core.removed == ["fw"]
    assert session.closed_with == [(True, True)]


def test_ensure_session_reports_not_loaded_program():
    store, _core = _build_store()
    store.target_projects["fw"] = ("/tmp/prj", "sample")

    with pytest.raises(RuntimeError, match="program not loaded"):
        store.ensure_session("fw")


def test_analyzed_load_tracking_by_target_and_domain():
    store, _core = _build_store()

    assert not store.is_analyzed_load("a", "/x")
    store.mark_analyzed_load("a", "/x")
    store.mark_analyzed_load("a", "/y")
    store.mark_analyzed_load("b", "/x")
    assert store.is_analyzed_load("a", "/x")
    assert store.is_analyzed_load("a", "/y")
    assert store.is_analyzed_load("b", "/x")

    store.clear_analyzed_loads_for_target("a")
    assert not store.is_analyzed_load("a", "/x")
    assert not store.is_analyzed_load("a", "/y")
    assert store.is_analyzed_load("b", "/x")

    store.clear_analyzed_loads()
    assert not store.is_analyzed_load("b", "/x")


def test_dirty_program_tracking_by_target_and_domain():
    store, _core = _build_store()

    assert not store.is_dirty_program("a", "/x")
    store.mark_dirty_program("a", "/x")
    store.mark_dirty_program("a", "/y")
    store.mark_dirty_program("b", "/x")
    assert store.is_dirty_program("a", "/x")
    assert store.is_dirty_program("a", "/y")
    assert store.is_dirty_program("b", "/x")

    store.clear_dirty_program("a", "/x")
    assert not store.is_dirty_program("a", "/x")
    assert store.is_dirty_program("a", "/y")

    store.clear_dirty_programs_for_target("a")
    assert not store.is_dirty_program("a", "/y")
    assert store.is_dirty_program("b", "/x")

    store.clear_dirty_programs()
    assert not store.is_dirty_program("b", "/x")
