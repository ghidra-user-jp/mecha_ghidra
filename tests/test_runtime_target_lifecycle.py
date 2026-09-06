from __future__ import annotations

import contextlib
import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle import RuntimeTargetLifecycle
from runtime_fakes import FakeDomainFile as _FakeDomainFile
from runtime_fakes import FakeProgram as _FakeProgram


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


class _FailingChangedProgram(_FakeProgram):
    def isChanged(self) -> bool:
        raise RuntimeError("dirty state unavailable")


class _FakeProjectData:
    def __init__(self) -> None:
        self.files: dict[str, _FakeDomainFile] = {}

    def getFile(self, path: str):
        return self.files.get(path)


class _FakeProject:
    def __init__(self) -> None:
        self._data = _FakeProjectData()
        self.saved_programs: list[str] = []

    def getProjectData(self):
        return self._data

    def save(self, program) -> None:  # noqa: ANN001
        self.saved_programs.append(program.getDomainFile().getPathname())


class _FailingSaveProject(_FakeProject):
    def save(self, program) -> None:  # noqa: ANN001
        super().save(program)
        raise RuntimeError("disk full")


class _FakeSession:
    def __init__(self, handle, path: str, flat_api, *, read_only_version: int | None = None) -> None:  # noqa: ANN001
        self._handle = handle
        self._path = path
        self.flat_api = flat_api
        self.read_only_version = read_only_version
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


class _FailingChangedSession(_FakeSession):
    def get_program(self):
        return _FailingChangedProgram(self._path)


class _ClosingFakeSession(_FakeSession):
    def get_project_handle(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return self._handle

    def get_program(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return super().get_program()

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        self.closed_with.append((save, remove_program))
        self._handle = None


class _FakeProjectHandle:
    metadata_programs = None
    repository_backed = False
    should_analyze = True
    fail_analyze = False
    save_result = True
    fail_save = False

    def __init__(self, project_location: str, project_name: str | None) -> None:
        self._location = project_location
        self._name = project_name or ""
        self._key = (self._location, self._name)
        self._closed = False
        self.project = _FakeProject()
        self._programs = [{"path": "/main"}]
        self.analyze_calls: list[str] = []
        self.import_calls: list[dict[str, object]] = []
        self.save_calls: list[str] = []
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
    def resolve_project_creation_target(
        project_location: str,
        project_name: str | None,
    ) -> tuple[str, str]:
        return (project_location, project_name or "")

    @staticmethod
    def create_project(
        project_location: str,
        project_name: str | None = None,
        *,
        overwrite: bool = False,
    ) -> dict[str, object]:
        return {
            "status": "ok",
            "project_location": project_location,
            "project_name": project_name or "",
            "created": True,
            "overwritten": overwrite,
        }

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: str | None):  # noqa: ARG004
        return _FakeProjectHandle.metadata_programs

    @staticmethod
    def is_repository_project_from_metadata(project_location: str, project_name: str | None):  # noqa: ARG004
        return _FakeProjectHandle.repository_backed

    def open_program(self, domain_path: str | None = None, *, version: int | None = None):
        path = domain_path or "/main"
        handle = self

        class _FakeFlatAPI:
            def analyzeAll(self, program):  # noqa: ANN001
                handle.analyze_calls.append(program.getDomainFile().getPathname())
                if _FakeProjectHandle.fail_analyze:
                    raise RuntimeError("analyze failed")

        return _FakeSession(self, path, _FakeFlatAPI(), read_only_version=version)

    def import_program(self, binary_path: str, **kwargs):
        self.import_calls.append({"binary_path": binary_path, **kwargs})
        return _FakeDomainFile("/imported.bin")

    def list_programs(self):
        return list(self._programs)

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        return dict(self.sync_status)

    def refresh_project_data(self, *, force: bool = True) -> None:
        return None

    def save_program(self, program, *, force: bool = False) -> bool:
        if _FakeProjectHandle.fail_save:
            raise RuntimeError("SAVE_FAILED: failed to save program: disk full")
        self.save_calls.append(program.getDomainFile().getPathname())
        if force:
            return True
        return bool(_FakeProjectHandle.save_result)

    def is_closed(self) -> bool:
        return self._closed

    def get_key(self) -> tuple[str, str]:
        return self._key

    def get_project_location(self) -> str:
        return self._location

    def get_project_name(self) -> str:
        return self._name

    def close(self, *, force: bool = False) -> None:  # noqa: ARG002
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


class _FailingOpenSaveCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        raise RuntimeError("SAVE_FAILED: failed to save program before close: disk full")


class _FailingProgramCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        raise RuntimeError("PROGRAM_CLOSE_FAILED: failed to close program: close failed")


class _RemoveFailedClosedSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        self._handle = None
        raise RuntimeError("REMOVE_PROGRAM_FAILED: delete failed")

    def get_project_handle(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return self._handle


class _FailingRollbackCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        raise RuntimeError("rollback close failed")


class _FailingReopenedCloseSession(_ClosingFakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:
        self.closed_with.append((save, remove_program))
        raise RuntimeError("reopened close failed")


class _ExternallyVersionedOnReopenProjectHandle(_FakeProjectHandle):
    def __init__(self, project_location: str, project_name: str | None) -> None:
        super().__init__(project_location, project_name)
        self.refresh_calls = 0
        self.open_program_calls = 0
        self.sync_status["can_add_to_repository"] = True

    def refresh_project_data(self, *, force: bool = True) -> None:  # noqa: ARG002
        self.refresh_calls += 1

    def open_program(self, domain_path: str | None = None):
        self.open_program_calls += 1
        if self.open_program_calls > 1:
            self.sync_status.update(
                {
                    "is_versioned": True,
                    "version": 1,
                    "latest_version": 1,
                    "can_add_to_repository": False,
                }
            )
        return super().open_program(domain_path)


class _NeverVersionedOnReopenProjectHandle(_FakeProjectHandle):
    def __init__(self, project_location: str, project_name: str | None) -> None:
        super().__init__(project_location, project_name)
        self.refresh_calls = 0
        self.open_program_calls = 0
        self.opened_sessions: list[_ClosingFakeSession] = []
        self.sync_status["can_add_to_repository"] = True

    def refresh_project_data(self, *, force: bool = True) -> None:  # noqa: ARG002
        self.refresh_calls += 1

    def open_program(self, domain_path: str | None = None):
        self.open_program_calls += 1
        base_session = super().open_program(domain_path)
        session = _ClosingFakeSession(self, domain_path or "/main", base_session.flat_api)
        self.opened_sessions.append(session)
        return session


class _NeverVersionedFailingCloseOnReopenProjectHandle(_NeverVersionedOnReopenProjectHandle):
    def open_program(self, domain_path: str | None = None):
        session = super().open_program(domain_path)
        if self.open_program_calls > 1:
            session = _FailingReopenedCloseSession(self, domain_path or "/main", session.flat_api)
            self.opened_sessions[-1] = session
        return session


class _RestoreOpenFailsProjectHandle(_FakeProjectHandle):
    def __init__(self, project_location: str, project_name: str | None) -> None:
        super().__init__(project_location, project_name)
        self.open_program_calls = 0

    def open_program(self, domain_path: str | None = None):
        self.open_program_calls += 1
        if self.open_program_calls > 1:
            raise RuntimeError("restore open failed")
        return super().open_program(domain_path)


class _DomainErrorDuringRemoveVerifyProjectHandle(_FakeProjectHandle):
    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        raise DomainError(
            code=ErrorCode.UNSAFE_PROGRAM_REMOVE,
            message="UNSAFE_PROGRAM_REMOVE: refusing to remove versioned program",
            retryable=False,
            details={
                "domain_path": domain_path,
                "version": 4,
                "latest_version": 5,
            },
        )


class _FailingAnalysisSaveProjectHandle(_FakeProjectHandle):
    def save_program(self, program, *, force: bool = False) -> bool:
        self.save_calls.append(program.getDomainFile().getPathname())
        raise RuntimeError("disk full")


class _ProjectLockingFakeProjectHandle(_FakeProjectHandle):
    def __init__(self, project_location: str, project_name: str | None) -> None:
        raise RuntimeError(f"Unable to lock project! {project_location}/{project_name}")


class _FailingProjectCloseHandle(_FakeProjectHandle):
    def close(self, *, force: bool = False) -> None:  # noqa: ARG002
        raise RuntimeError("project close failed")


class _OpenFailsAndProjectCloseFailsHandle(_FailingProjectCloseHandle):
    def open_program(self, domain_path: str | None = None):  # noqa: ARG002
        raise RuntimeError("open failed after partial resource")


class _ImportCloseFailureHandle(_FakeProjectHandle):
    def import_program(self, binary_path: str, **kwargs):  # noqa: ARG002
        raise RuntimeError(
            "IMPORT_CLOSE_FAILED: imported program /sample.bin but failed to close after post-processing: close failed"
        )


class _ImportFailureCleanupCloseHandle(_FakeProjectHandle):
    def import_program(self, binary_path: str, **kwargs):  # noqa: ARG002
        raise RuntimeError(
            "PROGRAM_CLOSE_FAILED: failed to close raw import results after import failure "
            "for /tmp/sample.bin: close failed; original error: import failed"
        )


def _build_target_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    core: _DummyCore | None = None,
    handle_cls: type[_FakeProjectHandle] = _FakeProjectHandle,
):
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as store_module
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle as lifecycle_module

    _FakeProjectHandle.metadata_programs = None
    _FakeProjectHandle.repository_backed = False
    _FakeProjectHandle.save_result = True
    _FakeProjectHandle.fail_save = False
    monkeypatch.setattr(store_module, "ProjectHandle", handle_cls)
    monkeypatch.setattr(lifecycle_module, "ProjectHandle", handle_cls)

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


def test_create_project_uses_exclusive_operation_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)

    class _WriterOnlyLock:
        def __init__(self) -> None:
            self.writer_entries = 0

        @contextlib.contextmanager
        def write_lock(self):
            self.writer_entries += 1
            yield

        def read_lock(self):
            raise AssertionError("create_project must not use a shared operation lock")

    operation_lock = _WriterOnlyLock()
    store.operation_lock = operation_lock

    result = lifecycle.create_project("/tmp/prj", project_name="sample")

    assert result["project_name"] == "sample"
    assert operation_lock.writer_entries == 1


@pytest.mark.parametrize("registered", [False, True], ids=["open-handle", "registered-target"])
def test_create_project_rejects_overwrite_when_project_is_in_use(
    monkeypatch: pytest.MonkeyPatch,
    registered: bool,
):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    project_key = ("/tmp/prj", "sample")
    if registered:
        store.target_projects["fw"] = project_key
    else:
        store.project_handles[project_key] = _FakeProjectHandle(*project_key)

    create_called = False

    def unexpected_create(*_args, **_kwargs):
        nonlocal create_called
        create_called = True
        raise AssertionError("destructive project creation must not run")

    monkeypatch.setattr(_FakeProjectHandle, "create_project", staticmethod(unexpected_create))

    with pytest.raises(RuntimeError, match="PROJECT_IN_USE"):
        lifecycle.create_project("/tmp/prj", project_name="sample", overwrite=True)

    assert create_called is False


def test_create_project_allows_overwrite_with_only_closed_stale_handle(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    project_key = ("/tmp/prj", "sample")
    stale_handle = _FakeProjectHandle(*project_key)
    stale_handle.close()
    store.project_handles[project_key] = stale_handle

    result = lifecycle.create_project(
        "/tmp/prj",
        project_name="sample",
        overwrite=True,
    )

    assert result["overwritten"] is True


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
    assert loaded == {"program": "/next", "reloaded": False, "version": None, "read_only": False}
    handle = store.get_target_handle("fw")
    assert handle.analyze_calls == ["/main", "/next"]
    assert handle.save_calls == ["/main", "/next"]

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


def test_target_lifecycle_import_close_failure_exposes_imported_domain_path(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, _store, _core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_ImportCloseFailureHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.import_program("fw", "/tmp/sample.bin")

    err = exc_info.value
    assert err.code == ErrorCode.OPERATION_FAILED
    assert err.details == {
        "operation": "import_program",
        "target": "fw",
        "binary_path": "/tmp/sample.bin",
        "partial_import": True,
        "imported_domain_path": "/sample.bin",
    }


def test_target_lifecycle_import_failure_cleanup_close_is_not_partial_import(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, _store, _core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_ImportFailureCleanupCloseHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.import_program("fw", "/tmp/sample.bin")

    err = exc_info.value
    assert err.code == ErrorCode.OPERATION_FAILED
    assert err.details == {
        "operation": "import_program",
        "target": "fw",
        "binary_path": "/tmp/sample.bin",
        "partial_import": False,
        "cleanup_error": True,
    }


def test_target_lifecycle_register_target_uses_target_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lock = store.locks["fw"]
    started = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def register_other_project() -> None:
        started.set()
        try:
            lifecycle.register_target("fw", "/tmp/other", project_name="other")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            finished.set()

    with lock:
        thread = threading.Thread(target=register_other_project)
        thread.start()
        assert started.wait(1)
        assert not finished.wait(0.05)

    thread.join(1)
    assert finished.is_set()
    assert errors == []
    assert store.target_projects["fw"] == ("/tmp/other", "other")


def test_target_lifecycle_remove_failure_restores_session_for_retry(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = created.get_project_handle()
    failing = _RemoveFailedClosedSession(handle, "/main", created.flat_api)
    store.sessions["fw"] = failing

    with pytest.raises(RuntimeError, match="REMOVE_PROGRAM_FAILED: delete failed"):
        lifecycle.close_session("fw", remove_program=True)

    restored = store.sessions["fw"]
    assert restored is not failing
    assert store.session_domain_path(restored) == "/main"
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert "fw" in store.locks
    assert core.contexts == {"fw": "/main"}
    assert core.removed == []
    assert failing.closed_with == [(True, True)]


def test_target_lifecycle_remove_restore_close_failure_preserves_restored_session(
    monkeypatch: pytest.MonkeyPatch,
):
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(
        monkeypatch,
        core=core,
        handle_cls=_NeverVersionedFailingCloseOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = created.get_project_handle()
    handle.sync_status["can_add_to_repository"] = False
    failing = _RemoveFailedClosedSession(handle, "/main", created.flat_api)
    store.sessions["fw"] = failing

    def fail_initialize(_program, key):  # noqa: ANN001, ARG001
        raise RuntimeError("initialize failed")

    core.initialize = fail_initialize

    with pytest.raises(
        RuntimeError,
        match="PROGRAM_CLOSE_FAILED: failed to close restored session during remove-failure recovery",
    ):
        lifecycle.close_session("fw", remove_program=True)

    assert store.sessions["fw"] is handle.opened_sessions[-1]
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert "fw" in store.locks
    assert core.contexts == {"fw": "/main"}


def test_target_lifecycle_remove_restore_open_failure_drops_closed_session(
    monkeypatch: pytest.MonkeyPatch,
):
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(
        monkeypatch,
        core=core,
        handle_cls=_RestoreOpenFailsProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = created.get_project_handle()
    handle.sync_status["can_add_to_repository"] = False
    failing = _RemoveFailedClosedSession(handle, "/main", created.flat_api)
    store.sessions["fw"] = failing

    with pytest.raises(RuntimeError, match="REOPEN_FAILED: failed to restore session: restore open failed"):
        lifecycle.close_session("fw", remove_program=True)

    assert "fw" not in store.sessions
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert "fw" in store.locks
    assert core.contexts == {}
    assert core.removed == ["fw"]


def test_target_lifecycle_close_stale_session_preserves_reentrant_replacement(
    monkeypatch: pytest.MonkeyPatch,
):
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    replacement_handle = _FakeProjectHandle("/tmp/replacement", "replacement")
    replacement = _FakeSession(replacement_handle, "/replacement", created.flat_api)
    replacement_lock = threading.RLock()

    class _ReentrantReplacementSession(_FakeSession):
        def close(self, *, save: bool = True, remove_program: bool = False) -> None:
            self.closed_with.append((save, remove_program))
            self._handle = None
            with store.registry_lock.write_lock():
                store.sessions["fw"] = replacement
                store.locks["fw"] = replacement_lock
                store.target_projects["fw"] = replacement_handle.get_key()
            core.contexts["fw"] = "/replacement"

    stale = _ReentrantReplacementSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = stale
    store.mark_dirty_program("fw", "/main")

    lifecycle.close_session("fw")

    assert stale.closed_with == [(True, False)]
    assert store.sessions["fw"] is replacement
    assert store.locks["fw"] is replacement_lock
    assert store.target_projects["fw"] == replacement_handle.get_key()
    assert store.is_dirty_program("fw", "/main")
    assert core.contexts == {"fw": "/replacement"}
    assert core.removed == []


def test_target_lifecycle_refuses_to_remove_versioned_program(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")
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


def test_target_lifecycle_remove_guard_reopens_stale_versioned_program(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.close_session("fw", remove_program=True)

    err = exc_info.value
    assert err.code == ErrorCode.UNSAFE_PROGRAM_REMOVE
    assert err.details == {
        "operation": "close_session",
        "target": "fw",
        "domain_path": "/main",
        "version": 1,
        "latest_version": 1,
    }
    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 2
    assert "fw" in store.sessions
    assert core.removed == []


def test_target_lifecycle_remove_uses_reopened_session_for_cleanup(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_NeverVersionedOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")
    original_session = store.sessions["fw"]

    lifecycle.close_session("fw", remove_program=True)

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 2
    assert original_session.closed_with == [(False, False)]
    assert handle.opened_sessions[-1].closed_with == [(True, True)]
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_remove_saves_dirty_program_before_reopen(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_NeverVersionedOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")
    original_session = store.sessions["fw"]
    store.mark_dirty_program("fw", "/main")

    lifecycle.close_session("fw", remove_program=True)

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 2
    assert original_session.closed_with == [(True, False)]
    assert handle.opened_sessions[-1].closed_with == [(True, True)]
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_remove_saves_when_dirty_state_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_NeverVersionedOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")
    failing = _FailingChangedSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing

    lifecycle.close_session("fw", remove_program=True)

    assert handle.refresh_calls == 1
    assert handle.open_program_calls == 2
    assert failing.closed_with == [(True, False)]
    assert handle.opened_sessions[-1].closed_with == [(True, True)]
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_remove_guard_surfaces_save_failure(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_NeverVersionedOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    failing = _FailingOpenSaveCloseSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing
    store.mark_dirty_program("fw", "/main")

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program before close: disk full"):
        lifecycle.close_session("fw", remove_program=True)

    assert store.sessions["fw"] is failing
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.removed == []


def test_target_lifecycle_remove_guard_preserves_reopened_session_when_rollback_close_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(
        monkeypatch,
        core=core,
        handle_cls=_NeverVersionedFailingCloseOnReopenProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")

    def fail_initialize(_program, _key):  # noqa: ANN001
        raise RuntimeError("initialize failed")

    core.initialize = fail_initialize

    with pytest.raises(
        RuntimeError,
        match="PROGRAM_CLOSE_FAILED: failed to close reopened session during remove guard rollback",
    ):
        lifecycle.close_session("fw", remove_program=True)

    assert store.sessions["fw"] is handle.opened_sessions[-1]
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.contexts == {"fw": "/main"}


def test_target_lifecycle_remove_preserves_domain_error_from_verification(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_DomainErrorDuringRemoveVerifyProjectHandle,
    )
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    with pytest.raises(DomainError) as exc_info:
        lifecycle.close_session("fw", remove_program=True)

    err = exc_info.value
    assert err.code == ErrorCode.UNSAFE_PROGRAM_REMOVE
    assert err.details == {
        "operation": "close_session",
        "target": "fw",
        "domain_path": "/main",
        "version": 4,
        "latest_version": 5,
    }
    assert "fw" in store.sessions
    assert core.removed == []


def test_target_lifecycle_close_session_preserves_registered_target(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    lifecycle.close_session("fw")

    assert "fw" not in store.sessions
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.removed == ["fw"]
    assert lifecycle.list_targets() == [
        {
            "target": "fw",
            "project_location": "/tmp/prj",
            "project_name": "sample",
            "domain_path": None,
        }
    ]

    assert lifecycle.load_program("fw", "/main")["program"] == "/main"
    assert "fw" in store.sessions


def test_target_lifecycle_close_registered_target_without_loaded_session_is_noop(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    lifecycle.close_session("fw")

    assert "fw" not in store.sessions
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.removed == []


def test_target_lifecycle_list_targets_waits_for_target_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    target_lock = store.locks["fw"]
    started = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def list_targets() -> None:
        started.set()
        try:
            lifecycle.list_targets()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            finished.set()

    with target_lock:
        thread = threading.Thread(target=list_targets)
        thread.start()
        assert started.wait(1)
        assert not finished.wait(0.05)

    thread.join(1)
    assert finished.is_set()
    assert errors == []


def test_target_lifecycle_list_targets_reads_session_outside_registry_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    session = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    original_to_dict = session.to_dict

    def to_dict():  # noqa: ANN202
        acquired = threading.Event()

        def acquire_registry() -> None:
            with store.registry_lock.write_lock():
                acquired.set()

        thread = threading.Thread(target=acquire_registry)
        thread.start()
        assert acquired.wait(1), "session metadata was read while registry_lock was held"
        thread.join(1)
        assert not thread.is_alive()
        return original_to_dict()

    session.to_dict = to_dict

    assert lifecycle.list_targets() == [
        {
            "target": "fw",
            "project_location": "/tmp/prj",
            "project_name": "sample",
            "domain_path": "/main",
        }
    ]


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
    assert store.get_target_handle("fw").list_programs() == [{"path": "/main"}]


def test_target_lifecycle_list_programs_falls_back_to_metadata_when_repository_project_is_locked(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, _store, _core = _build_target_lifecycle(monkeypatch, handle_cls=_ProjectLockingFakeProjectHandle)
    _FakeProjectHandle.repository_backed = True
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    _FakeProjectHandle.metadata_programs = [{"path": "/meta.bin"}]
    try:
        programs = lifecycle.list_programs("fw")
    finally:
        _FakeProjectHandle.metadata_programs = None
        _FakeProjectHandle.repository_backed = False
    assert programs == [
        {
            "path": "/meta.bin",
            "is_versioned": None,
            "version": None,
            "latest_version": None,
            "is_latest_version": None,
            "can_add_to_repository": None,
            "sync_status_error": "PROJECT_LOCKED: returned metadata snapshot because the project is locked",
        }
    ]


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


def test_target_lifecycle_create_session_rolls_back_on_analysis_save_failure(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_FailingAnalysisSaveProjectHandle,
    )

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save analysis results"):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert not store.analyzed_loads
    assert core.removed == ["fw"]


def test_target_lifecycle_skips_initial_analysis_for_unchecked_versioned_program(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    handle = store.get_target_handle("fw")
    handle.sync_status.update(
        {
            "is_versioned": True,
            "is_checked_out": False,
            "version": 3,
            "latest_version": 3,
        }
    )

    session = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert session is store.sessions["fw"]
    assert handle.analyze_calls == []
    assert handle.save_calls == []
    assert store.analyzed_loads == set()
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_target_lifecycle_skips_initial_analysis_for_unversioned_shared_project_program(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)
    lifecycle.register_target("fw", "/tmp/prj", project_name="sample")
    handle = store.get_target_handle("fw")
    handle.sync_status.update(
        {
            "is_versioned": False,
            "can_add_to_repository": True,
            "version": None,
            "latest_version": None,
        }
    )

    session = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert session is store.sessions["fw"]
    assert handle.analyze_calls == []
    assert handle.save_calls == []
    assert store.analyzed_loads == set()
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_target_lifecycle_create_session_closes_leaked_handle_when_rollback_close_fails(
    monkeypatch: pytest.MonkeyPatch,
):
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

    with pytest.raises(RuntimeError, match="SESSION_CLOSE_FAILED: rollback close failed"):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    assert not store.project_handles
    assert core.contexts == {}


def test_target_lifecycle_create_session_surfaces_handle_close_failure_after_session_cleanup(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = True
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_FailingProjectCloseHandle,
    )

    with pytest.raises(
        RuntimeError,
        match="PROJECT_CLOSE_FAILED: failed to close leaked project handle during rollback",
    ):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    handle_key = ("/tmp/prj", "sample")
    assert handle_key in store.project_handles
    assert store.project_handles[handle_key].is_closed() is False
    assert "fw" not in store.sessions
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


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


def test_target_lifecycle_failed_cleanup_closes_stale_same_key_handle(
    monkeypatch: pytest.MonkeyPatch,
):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    stale_handle = _FakeProjectHandle("/tmp/prj", "sample")
    replacement_handle = _FakeProjectHandle("/tmp/prj", "sample")
    replacement = _FakeSession(replacement_handle, "/main", object())
    store.sessions["fw"] = replacement
    store.project_handles[replacement_handle.get_key()] = replacement_handle

    cleanup_error = lifecycle._cleanup_failed_create_session_locked(  # noqa: SLF001
        name="stale",
        session=None,
        handle=stale_handle,
    )

    assert cleanup_error is None
    assert stale_handle.is_closed()
    assert store.sessions["fw"] is replacement
    assert store.project_handles[replacement_handle.get_key()] is replacement_handle


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


def test_target_lifecycle_create_session_open_failure_restores_registered_target_project(
    monkeypatch: pytest.MonkeyPatch,
):
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


def test_target_lifecycle_create_session_open_failure_surfaces_handle_close_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(
        monkeypatch,
        handle_cls=_OpenFailsAndProjectCloseFailsHandle,
    )

    with pytest.raises(
        RuntimeError,
        match="PROJECT_CLOSE_FAILED: failed to close leaked project handle during rollback",
    ):
        lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    handle_key = ("/tmp/prj", "sample")
    assert handle_key in store.project_handles
    assert store.project_handles[handle_key].is_closed() is False
    assert "fw" not in store.sessions
    assert "fw" not in store.target_projects
    assert "fw" not in store.locks
    assert core.removed == []


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


def test_target_lifecycle_close_session_preserves_save_failed_and_cleans_closed_session(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    failing = _FailingSaveCloseSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program before close: disk full"):
        lifecycle.close_session("fw")

    assert "fw" not in store.sessions
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.removed == ["fw"]


def test_target_lifecycle_close_session_preserves_open_session_on_program_close_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    failing = _FailingProgramCloseSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing

    with pytest.raises(RuntimeError, match="PROGRAM_CLOSE_FAILED: failed to close program: close failed"):
        lifecycle.close_session("fw")

    assert store.sessions["fw"] is failing
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.removed == []
    assert failing.closed_with == [(True, False)]


def test_target_lifecycle_close_all_preserves_open_session_on_save_failure(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    core = _TrackingCore()
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch, core=core)

    created = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    failing = _FailingOpenSaveCloseSession(created.get_project_handle(), "/main", created.flat_api)
    store.sessions["fw"] = failing
    store.mark_dirty_program("fw", "/main")

    with pytest.raises(RuntimeError, match="CLOSE_ALL_FAILED: failed to close runtime resource"):
        lifecycle.close_all()

    assert store.sessions["fw"] is failing
    assert store.is_dirty_program("fw", "/main")
    assert "fw" in store.locks
    assert store.target_projects["fw"] == ("/tmp/prj", "sample")
    assert core.contexts == {"fw": "/main"}
    assert failing.closed_with == [(True, False)]


def test_target_lifecycle_close_all_preserves_handle_on_project_close_failure(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch, handle_cls=_FailingProjectCloseHandle)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")

    with pytest.raises(RuntimeError, match="CLOSE_ALL_FAILED: failed to close runtime resource"):
        lifecycle.close_all()

    assert handle.get_key() in store.project_handles
    assert handle.is_closed() is False
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_target_lifecycle_close_all_waits_for_active_runtime_operation(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    started = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def close_all() -> None:
        started.set()
        try:
            lifecycle.close_all()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            finished.set()

    with store.operation_lock.read_lock():
        thread = threading.Thread(target=close_all)
        thread.start()
        assert started.wait(1)
        assert not finished.wait(0.05)
        assert "fw" in store.sessions

    thread.join(1)
    assert finished.is_set()
    assert errors == []
    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.cleared == 1


def test_target_lifecycle_close_all_calls_resources_outside_registry_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    session = lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = session.get_project_handle()
    original_session_close = session.close
    original_handle_close = handle.close

    def assert_registry_writer_available() -> None:
        acquired = threading.Event()

        def acquire_registry() -> None:
            with store.registry_lock.write_lock():
                acquired.set()

        thread = threading.Thread(target=acquire_registry)
        thread.start()
        assert acquired.wait(1), "resource close was called while registry_lock was held"
        thread.join(1)
        assert not thread.is_alive()

    def close_session(*, save: bool = True, remove_program: bool = False) -> None:
        assert_registry_writer_available()
        original_session_close(save=save, remove_program=remove_program)

    def close_handle(*, force: bool = False) -> None:
        assert_registry_writer_available()
        original_handle_close(force=force)

    session.close = close_session
    handle.close = close_handle

    lifecycle.close_all()

    assert not store.sessions
    assert not store.project_handles


def test_target_lifecycle_duplicate_load_same_target_reloads_in_place(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    first_session = store.sessions["fw"]
    handle = store.get_target_handle("fw")

    result = lifecycle.load_program("fw", "/main")

    assert result == {"program": "/main", "reloaded": True, "version": None, "read_only": False}
    assert first_session.closed_with == [(False, False)]
    assert store.sessions["fw"] is not first_session
    assert [key for _program, key in core.initialized] == ["fw", "fw"]
    # A reload never re-runs the first-load analysis.
    assert handle.analyze_calls == ["/main"]


def test_target_lifecycle_load_version_opens_read_only_session(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = True
    _FakeProjectHandle.fail_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")

    result = lifecycle.load_program("fw", "/main", version=2)

    assert result == {"program": "/main", "reloaded": False, "version": 2, "read_only": True}
    assert store.sessions["fw"].read_only_version == 2
    # A past version is immutable: no analysis, no save.
    assert handle.analyze_calls == ["/main"]
    assert handle.save_calls == ["/main"]

    # Loading the same version again reopens it instead of failing.
    again = lifecycle.load_program("fw", "/main", version=2)
    assert again["reloaded"] is True and again["read_only"] is True


def test_target_lifecycle_read_only_version_does_not_block_live_load(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.should_analyze = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)

    lifecycle.create_session("history", "/tmp/prj", project_name="sample", domain_path="/main")
    lifecycle.load_program("history", "/main", version=1)
    lifecycle.register_target("live", "/tmp/prj", project_name="sample")

    result = lifecycle.load_program("live", "/main")

    assert result["read_only"] is False
    assert store.sessions["history"].read_only_version == 1

    with pytest.raises(ValueError, match="version must be >= 1"):
        lifecycle.load_program("live", "/main", version=0)


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
    handle = store.get_target_handle("fw")
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


def test_target_lifecycle_checks_cached_handle_outside_registry_lock(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    handle = _FakeProjectHandle("/tmp/prj", "sample")
    store.project_handles[handle.get_key()] = handle

    def is_closed() -> bool:
        acquired = threading.Event()

        def acquire_registry() -> None:
            with store.registry_lock.write_lock():
                acquired.set()

        thread = threading.Thread(target=acquire_registry)
        thread.start()
        assert acquired.wait(1), "cached handle state was checked while registry_lock was held"
        thread.join(1)
        assert not thread.is_alive()
        return False

    handle.is_closed = is_closed

    assert store.get_or_create_project_handle(handle.get_key()) is handle


def test_target_lifecycle_save_project_program_saves_active_and_clears_dirty(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    store.mark_dirty_program("fw", "/main")

    result = lifecycle.save_project_program("fw")

    handle = store.get_target_handle("fw")
    assert result == {"status": "ok", "target": "fw", "program": "/main", "saved": True}
    # One save after initial analysis, one explicit save_project_program.
    assert handle.save_calls == ["/main", "/main"]
    assert not store.is_dirty_program("fw", "/main")


def test_target_lifecycle_save_project_program_runtime_dirty_forces_save_and_clears_dirty(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.save_result = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    _FakeProjectHandle.save_result = False
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    store.mark_dirty_program("fw", "/main")

    result = lifecycle.save_project_program("fw", domain_path="/main")

    assert result == {"status": "ok", "target": "fw", "program": "/main", "saved": True}
    assert not store.is_dirty_program("fw", "/main")


def test_target_lifecycle_save_project_program_keeps_dirty_until_versioned_status_updates(
    monkeypatch: pytest.MonkeyPatch,
):
    _FakeProjectHandle.save_result = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    _FakeProjectHandle.save_result = False
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")
    handle.sync_status.update(
        {
            "is_versioned": True,
            "is_checked_out": True,
            "modified_since_checkout": False,
        }
    )
    store.mark_dirty_program("fw", "/main")

    result = lifecycle.save_project_program("fw", domain_path="/main")

    assert result == {"status": "ok", "target": "fw", "program": "/main", "saved": True}
    assert store.is_dirty_program("fw", "/main")


def test_target_lifecycle_save_project_program_clean_noop_does_not_set_dirty(monkeypatch: pytest.MonkeyPatch):
    _FakeProjectHandle.save_result = False
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    _FakeProjectHandle.save_result = False
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")

    result = lifecycle.save_project_program("fw", domain_path="/main")

    assert result == {"status": "ok", "target": "fw", "program": "/main", "saved": False}
    assert not store.is_dirty_program("fw", "/main")


def test_target_lifecycle_save_project_program_failure_keeps_dirty(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    store.mark_dirty_program("fw", "/main")
    _FakeProjectHandle.fail_save = True

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program: disk full"):
        lifecycle.save_project_program("fw")

    assert store.is_dirty_program("fw", "/main")


def test_target_lifecycle_save_project_program_rejects_non_active_domain_path(monkeypatch: pytest.MonkeyPatch):
    lifecycle, store, _core = _build_target_lifecycle(monkeypatch)
    lifecycle.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main")
    handle = store.get_target_handle("fw")

    saves_before = list(handle.save_calls)
    with pytest.raises(ValueError, match="domain_path must match"):
        lifecycle.save_project_program("fw", domain_path="/other")

    assert handle.save_calls == saves_before
