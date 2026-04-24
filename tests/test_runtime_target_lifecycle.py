from __future__ import annotations

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle import RuntimeTargetLifecycle


class _DummyCore:
    def __init__(self) -> None:
        self.initialized: list[tuple[object, str]] = []
        self.removed: list[str] = []
        self.cleared = 0

    def initialize(self, program, key: str):  # noqa: ANN001
        self.initialized.append((program, key))

    def remove_context(self, key: str) -> None:
        self.removed.append(key)

    def clear_contexts(self) -> None:
        self.cleared += 1


class _TrackingCore(_DummyCore):
    def __init__(self) -> None:
        super().__init__()
        self.contexts: dict[str, str] = {}

    def initialize(self, program, key: str):  # noqa: ANN001
        super().initialize(program, key)
        self.contexts[key] = program.getDomainFile().getPathname()

    def remove_context(self, key: str) -> None:
        super().remove_context(key)
        self.contexts.pop(key, None)


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


class _FakeProjectData:
    def __init__(self) -> None:
        self.files: dict[str, _FakeDomainFile] = {}

    def getFile(self, path: str):
        return self.files.get(path)


class _FakeProject:
    def __init__(self) -> None:
        self._data = _FakeProjectData()

    def getProjectData(self):
        return self._data


class _FakeSession:
    def __init__(self, handle, path: str, flat_api) -> None:  # noqa: ANN001
        self._handle = handle
        self._path = path
        self.flat_api = flat_api
        self.closed_with: list[tuple[bool, bool]] = []

    def get_program(self):
        return _FakeProgram(self._path)

    def get_project_handle(self):
        return self._handle

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))

    def to_dict(self) -> dict[str, str | None]:
        return {
            "project_location": self._handle.get_project_location(),
            "project_name": self._handle.get_project_name(),
            "domain_path": self._path,
        }


class _FakeProjectHandle:
    metadata_programs = None
    repository_backed = False
    should_analyze = True
    fail_analyze = False

    def __init__(self, project_location: str, project_name: str | None) -> None:
        self._location = project_location
        self._name = project_name or ""
        self._key = (self._location, self._name)
        self._closed = False
        self.project = _FakeProject()
        self._programs = [{"path": "/main"}]
        self.analyze_calls: list[str] = []
        self.import_calls: list[dict[str, object]] = []
        self.sync_status = {
            "is_versioned": False,
            "version": None,
            "latest_version": None,
        }

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def make_key(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: str | None):  # noqa: ARG004
        return _FakeProjectHandle.metadata_programs

    @staticmethod
    def is_repository_project_from_metadata(project_location: str, project_name: str | None):  # noqa: ARG004
        return _FakeProjectHandle.repository_backed

    def open_program(self, domain_path: str | None = None):
        path = domain_path or "/main"
        handle = self

        class _FakeFlatAPI:
            def analyzeAll(self, program):  # noqa: ANN001
                handle.analyze_calls.append(program.getDomainFile().getPathname())
                if _FakeProjectHandle.fail_analyze:
                    raise RuntimeError("analyze failed")

        return _FakeSession(self, path, _FakeFlatAPI())

    def import_program(self, binary_path: str, **kwargs):
        self.import_calls.append({"binary_path": binary_path, **kwargs})
        return _FakeDomainFile("/imported.bin")

    def list_programs(self):
        return list(self._programs)

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        return dict(self.sync_status)

    def is_closed(self) -> bool:
        return self._closed

    def get_key(self) -> tuple[str, str]:
        return self._key

    def get_project_location(self) -> str:
        return self._location

    def get_project_name(self) -> str:
        return self._name

    def close(self) -> None:
        self._closed = True


class _FailingSaveCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        self._handle = None
        raise RuntimeError("SAVE_FAILED: failed to save program before close: disk full")

    def get_project_handle(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return self._handle


class _FailingRollbackCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        raise RuntimeError("rollback close failed")


def _build_target_lifecycle(monkeypatch: pytest.MonkeyPatch, *, core: _DummyCore | None = None):
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as store_module
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle as lifecycle_module

    _FakeProjectHandle.metadata_programs = None
    _FakeProjectHandle.repository_backed = False
    monkeypatch.setattr(store_module, "ProjectHandle", _FakeProjectHandle)
    monkeypatch.setattr(lifecycle_module, "ProjectHandle", _FakeProjectHandle)

    class _FakeUtilities:
        def shouldAskToAnalyze(self, _program) -> bool:  # noqa: ANN001
            return _FakeProjectHandle.should_analyze

        def markProgramAnalyzed(self, _program) -> None:  # noqa: ANN001
            return None

    class _FakeScriptUtil:
        def acquireBundleHostReference(self) -> None:
            return None

        def releaseBundleHostReference(self) -> None:
            return None

    class _FakeJavaBindings:
        @staticmethod
        def _ghidra_program_utilities():
            return _FakeUtilities()

        @staticmethod
        def _ghidra_script_util():
            return _FakeScriptUtil()

    monkeypatch.setattr(lifecycle_module, "java_bindings", _FakeJavaBindings())

    core = core or _DummyCore()
    state = RuntimeState(
        core_accessor=lambda: core,
        checkout_required_commands=set(),
        normalize_result=lambda value: value,
    )
    store = RuntimeSessionStore(state=state, core_accessor=lambda: core)
    lifecycle = RuntimeTargetLifecycle(store=store)
    return lifecycle, store, core


def test_target_lifecycle_register_create_import_and_close(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    registered = lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    assert registered["target"] == "fw"
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")

    session = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    assert session is store.sessions["fw"]
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.analyzed_loads == {("fw", "/main")}

    loaded = lifecycle.load_program("fw", "/next")
    assert loaded == "/next"
    handle = store.get_target_handle_locked("fw")
    assert handle.analyze_calls == ["/main", "/next"]

    imported = lifecycle.import_program(
        "fw",
        "/tmp/binary.exe",
        import_mode="raw_binary",
        language_id="x86:LE:32:default",
        entry_offset=0,
    )
    assert imported == "/imported.bin"
    assert lifecycle.list_programs("fw") == [{"path": "/main"}]
    assert handle.import_calls == [
        {
            "binary_path": "/tmp/binary.exe",
            "import_mode": "raw_binary",
            "language_id": "x86:LE:32:default",
            "entry_offset": 0,
        }
    ]

    lifecycle.close_session("fw", remove_program=True)
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_refuses_to_remove_versioned_program(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle_locked("fw")
    handle.sync_status.update(
        {
            "is_versioned": True,
            "version": 3,
            "latest_version": 3,
        }
    )

    with pytest.raises(DomainError) as exc_info:
        lifecycle.close_session("fw", remove_program=True)

    err = exc_info.value
    assert err.code == ErrorCode.UNSAFE_PROGRAM_REMOVE
    assert err.details == {
        "operation": "close_session",
        "target": "fw",
        "domain_path": "/main",
        "version": 3,
        "latest_version": 3,
    }
    assert "fw" in store.sessions
    assert store.sessions["fw"].closed_with == []
    assert core.removed == []


def test_target_lifecycle_list_programs_uses_metadata_when_no_session(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    _FakeProjectHandle.repository_backed = False
    lifecycle, _store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    _FakeProjectHandle.metadata_programs = [{"path": "/meta.bin"}]
    try:
        programs = lifecycle.list_programs("fw")
    finally:
        _FakeProjectHandle.metadata_programs = None
    assert programs == [{"path": "/meta.bin"}]


def test_target_lifecycle_list_programs_ignores_metadata_for_repository_projects(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    _FakeProjectHandle.repository_backed = True
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    _FakeProjectHandle.metadata_programs = [{"path": "/meta.bin"}]
    try:
        programs = lifecycle.list_programs("fw")
    finally:
        _FakeProjectHandle.metadata_programs = None
        _FakeProjectHandle.repository_backed = False
    assert programs == [{"path": "/main"}]
    assert store.get_target_handle_locked("fw").list_programs() == [{"path": "/main"}]


def test_target_lifecycle_create_session_rolls_back_on_analysis_failure(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = True
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert not store.analyzed_loads
    assert core.removed == ["fw"]


def test_target_lifecycle_create_session_closes_leaked_handle_when_rollback_close_fails(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)
    original_open = _FakeProjectHandle.open_program

    def patched_open(self, domain_path: str | None = None):  # noqa: ANN001
        path = domain_path or "/main"
        if path == "/main":
            handle = self

            class _FailingFlatAPI:
                def analyzeAll(self, program):  # noqa: ANN001
                    raise RuntimeError("analyze failed")

            return _FailingRollbackCloseSession(handle, path, _FailingFlatAPI())
        return original_open(self, domain_path)

    monkeypatch.setattr(_FakeProjectHandle, "open_program", patched_open)

    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert not store.project_handles
    assert core.contexts == {}


def test_target_lifecycle_create_session_failure_does_not_close_shared_handle(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)

    created = lifecycle.create_session("fw1", "/tmp/prj", project_name="sample", domain_path="/main")
    _FakeProjectHandle.fail_analyze = True

    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.create_session("fw2", "/tmp/prj", project_name="sample", domain_path="/bad")

    assert created.get_project_handle().is_closed() is False
    assert store.session_domain_path(store.sessions["fw1"]) == "/main"
    assert core.contexts == {"fw1": "/main"}


def test_target_lifecycle_create_session_failure_restores_registered_target_project(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.register_target("fw", "/tmp/orig", project_name="orig")
    _FakeProjectHandle.fail_analyze = True

    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.create_session("fw", "/tmp/new", project_name="new", domain_path="/main")

    assert store.target_projects["fw"] == ("/tmp/orig", "orig")
    assert "fw" in store.locks
    assert "fw" not in store.sessions


def test_target_lifecycle_create_session_open_failure_restores_registered_target_project(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    original_open = _FakeProjectHandle.open_program

    def patched_open(self, domain_path: str | None = None):  # noqa: ANN001
        path = domain_path or "/main"
        if path == "/bad":
            raise RuntimeError("open failed")
        return original_open(self, domain_path)

    monkeypatch.setattr(_FakeProjectHandle, "open_program", patched_open)
    lifecycle.register_target("fw", "/tmp/orig", project_name="orig")

    with pytest.raises(RuntimeError, match="open failed"):
        lifecycle.create_session("fw", "/tmp/new", project_name="new", domain_path="/bad")

    assert store.target_projects["fw"] == ("/tmp/orig", "orig")
    assert "fw" in store.locks
    assert "fw" not in store.sessions
    assert ("/tmp/new", "new") not in store.project_handles


def test_target_lifecycle_load_program_restores_existing_context_on_analysis_failure(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    assert core.contexts == {"fw": "/main"}

    _FakeProjectHandle.fail_analyze = True
    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.load_program("fw", "/next")

    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert core.contexts == {"fw": "/main"}


def test_target_lifecycle_load_program_failure_does_not_close_shared_handle(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)

    created = lifecycle.create_session("fw1", "/tmp/prj", project_name="sample", domain_path="/main")
    lifecycle.register_target("fw2", "/tmp/prj", project_name="sample")
    _FakeProjectHandle.fail_analyze = True

    with pytest.raises(RuntimeError, match="analyze failed"):
        lifecycle.load_program("fw2", "/bad")

    assert created.get_project_handle().is_closed() is False
    assert store.session_domain_path(store.sessions["fw1"]) == "/main"
    assert core.contexts == {"fw1": "/main"}


def test_target_lifecycle_load_program_restores_existing_context_when_rollback_close_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    original_open = _FakeProjectHandle.open_program

    def patched_open(self, domain_path: str | None = None):  # noqa: ANN001
        path = domain_path or "/main"
        if path == "/next":
            handle = self

            class _FailingFlatAPI:
                def analyzeAll(self, program):  # noqa: ANN001
                    raise RuntimeError("analyze failed")

            return _FailingRollbackCloseSession(handle, path, _FailingFlatAPI())
        return original_open(self, domain_path)

    monkeypatch.setattr(_FakeProjectHandle, "open_program", patched_open)

    with pytest.raises(RuntimeError, match="SESSION_CLOSE_FAILED: rollback close failed"):
        lifecycle.load_program("fw", "/next")

    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert core.contexts == {"fw": "/main"}


def test_target_lifecycle_load_program_rolls_back_new_session_when_old_close_fails(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)

    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    store.mark_dirty_program("fw", "/main")
    store.sessions["fw"] = _FailingSaveCloseSession(created.get_project_handle(), "/main", created.flat_api)

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program before close: disk full"):
        lifecycle.load_program("fw", "/next")

    assert "fw" not in store.sessions
    assert "fw" in store.target_projects
    assert "fw" in store.locks
    assert not store.is_dirty_program("fw", "/main")
    assert core.contexts == {}
    assert core.removed == ["fw"]


def test_target_lifecycle_close_session_preserves_save_failed_and_cleans_closed_session(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    failing = _FailingSaveCloseSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program before close: disk full"):
        lifecycle.close_session("fw")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_duplicate_load_same_target_raises_specific_error(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, _store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.load_program("fw", "/main")

    err = exc_info.value
    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "load_program",
        "target": "fw",
        "domain_path": "/main",
    }


def test_target_lifecycle_duplicate_load_other_target_includes_owner(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, _store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("fw-primary", "/tmp/prj", project_name="sample", domain_path="/main")
    lifecycle.register_target("fw-shadow", "/tmp/prj", project_name="sample")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.load_program("fw-shadow", "/main")

    err = exc_info.value
    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "load_program",
        "target": "fw-shadow",
        "domain_path": "/main",
        "owner_target": "fw-primary",
    }


def test_target_lifecycle_duplicate_import_raises_specific_error(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    handle = store.get_target_handle_locked("fw")
    handle.project.getProjectData().files["/binary.exe"] = _FakeDomainFile("/binary.exe")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.import_program("fw", "/tmp/binary.exe")

    err = exc_info.value
    assert err.code == ErrorCode.PROGRAM_ALREADY_IMPORTED
    assert err.details == {
        "operation": "import_program",
        "target": "fw",
        "binary_path": "/tmp/binary.exe",
        "existing_domain_path": "/binary.exe",
    }
    assert handle.import_calls == []
