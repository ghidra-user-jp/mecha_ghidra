from __future__ import annotations

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
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
    def __init__(self, handle, path: str, flat_api) -> None:  # noqa: ANN001
        self._handle = handle
        self._path = path
        self.flat_api = flat_api
        self.closed_with: list[bool] = []

    def get_program(self):
        return _FakeProgram(self._path)

    def get_project_handle(self):
        return self._handle

    def close(self, *, remove_program: bool = False) -> None:
        self.closed_with.append(remove_program)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "project_location": self._handle.get_project_location(),
            "project_name": self._handle.get_project_name(),
            "domain_path": self._path,
        }


class _FakeProjectHandle:
    metadata_programs = None
    should_analyze = True
    fail_analyze = False

    def __init__(self, project_location: str, project_name: str | None) -> None:
        self._location = project_location
        self._name = project_name or ""
        self._key = (self._location, self._name)
        self._closed = False
        self._programs = [{"path": "/main"}]
        self.analyze_calls: list[str] = []
        self.import_calls: list[dict[str, object]] = []

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def make_key(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: str | None):  # noqa: ARG004
        return _FakeProjectHandle.metadata_programs

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


def _build_target_lifecycle(monkeypatch: pytest.MonkeyPatch):
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as store_module
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle as lifecycle_module

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

    core = _DummyCore()
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

    loaded = lifecycle.load_program("fw", "/main")
    assert loaded == "/main"
    handle = store.get_target_handle_locked("fw")
    assert handle.analyze_calls == ["/main"]

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


def test_target_lifecycle_list_programs_uses_metadata_when_no_session(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, _store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    _FakeProjectHandle.metadata_programs = [{"path": "/meta.bin"}]
    try:
        programs = lifecycle.list_programs("fw")
    finally:
        _FakeProjectHandle.metadata_programs = None
    assert programs == [{"path": "/meta.bin"}]


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
