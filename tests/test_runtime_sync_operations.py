from __future__ import annotations

import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode
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


class _FailingSaveProject(_FakeProject):
    def save(self, _program) -> None:  # noqa: ANN001
        super().save(_program)
        raise RuntimeError("disk full")


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

    def isChanged(self) -> bool:
        return False


class _FakeSession:
    def __init__(self, handle, path: str):  # noqa: ANN001
        self._handle = handle
        self._path = path
        self.closed = 0
        self.close_saves: list[bool] = []

    def get_project_handle(self):
        return self._handle

    def get_program(self):
        return _FakeProgram(self._path)

    def close(self, *, save: bool = True, remove_program: bool = False) -> None:  # noqa: ARG002
        self.close_saves.append(bool(save))
        if save:
            self._handle.project.save(self.get_program())
        self.closed += 1


class _DirtyAwareFakeProgram(_FakeProgram):
    def __init__(self, path: str, handle) -> None:  # noqa: ANN001
        super().__init__(path)
        self._handle = handle

    def isChanged(self) -> bool:
        return bool(getattr(self._handle, "program_reports_changed", False))


class _FailingChangedFakeProgram(_FakeProgram):
    def isChanged(self) -> bool:
        raise RuntimeError("dirty state unavailable")


class _DirtyAwareFakeSession(_FakeSession):
    def get_program(self):
        return _DirtyAwareFakeProgram(self._path, self._handle)


class _FailingChangedFakeSession(_FakeSession):
    def get_program(self):
        return _FailingChangedFakeProgram(self._path)


class _ClosingSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:  # noqa: ARG002
        super().close(save=save, remove_program=remove_program)
        self._handle = None
        self._path = ""

    def get_project_handle(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return self._handle

    def get_program(self):
        if not self._path:
            raise RuntimeError("Session is already closed")
        return super().get_program()


class _FailingCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:  # noqa: ARG002
        self.close_saves.append(bool(save))
        self._handle = None
        self._path = ""
        raise RuntimeError("SESSION_CLOSE_FAILED: failed to close program: close failed")

    def get_project_handle(self):
        if self._handle is None:
            raise RuntimeError("Session is already closed")
        return self._handle

    def get_program(self):
        if not self._path:
            raise RuntimeError("Session is already closed")
        return super().get_program()


class _FakeHandle:
    def __init__(self, project_location: str, project_name: str) -> None:
        self._location = project_location
        self._name = project_name
        self._key = (self._location, self._name)
        self.project = _FakeProject()
        self._closed = False
        self.fail_reopen = False
        self.checkout_calls = 0
        self.merge_calls = 0
        self.undo_checkout_calls = 0
        self.deleted_domain_files: list[str] = []
        self.refresh_project_data_calls = 0
        self._status: dict[str, object] = {
            "is_versioned": True,
            "is_checked_out": False,
            "is_checked_out_exclusive": False,
            "modified_since_checkout": False,
            "can_merge": False,
            "can_checkout": True,
            "can_checkin": True,
            "is_hijacked": False,
            "version": 1,
            "latest_version": 1,
            "is_latest_version": True,
            "checkouts": [],
        }
        self.program_paths = {"/main"}

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

    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_project_data_calls += 1

    def checkout_program(self, domain_path: str, *, exclusive: bool = False):  # noqa: ARG002
        self.checkout_calls += 1
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
        self.undo_checkout_calls += 1
        self._status["is_checked_out"] = bool(keep)
        self._status["modified_since_checkout"] = False
        self._status["can_merge"] = False
        self._status["is_latest_version"] = True

    def terminate_checkout_program(self, domain_path: str, checkout_id: int):  # noqa: ARG002
        return None

    def delete_domain_file(self, domain_path: str):
        self.deleted_domain_files.append(domain_path)
        self.program_paths.discard(domain_path)
        return {"domain_path": domain_path, "content_type": "Program"}

    def merge_program(self, domain_path: str, *, ok_to_upgrade: bool = True):  # noqa: ARG002
        self.merge_calls += 1
        self._status["can_merge"] = False
        self._status["is_latest_version"] = True

    def open_program(self, domain_path: str):
        if self.fail_reopen:
            raise RuntimeError("reopen failed")
        return _FakeSession(self, domain_path)

    def list_programs(self):
        return [
            {
                "domain_path": path,
                "domain_name": path.rsplit("/", 1)[-1],
                "contentType": "Program",
            }
            for path in sorted(self.program_paths)
        ]

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


class _StaleStatusProject(_FakeProject):
    def __init__(self, handle) -> None:  # noqa: ANN001
        super().__init__()
        self._handle = handle

    def save(self, _program) -> None:  # noqa: ANN001
        super().save(_program)
        if getattr(self._handle, "active_program_changed", False):
            self._handle.active_program_changed = False
            self._handle.program_reports_changed = False
            self._handle.pending_domain_refresh = True


class _StaleStatusHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.project = _StaleStatusProject(self)
        self.active_program_changed = False
        self.pending_domain_refresh = False
        self.program_reports_changed = False

    def mark_active_change(self) -> None:
        self._status["is_checked_out"] = True
        self._status["modified_since_checkout"] = False
        self._status["can_checkin"] = False
        self.active_program_changed = True
        self.program_reports_changed = True

    def open_program(self, domain_path: str):
        if self.fail_reopen:
            raise RuntimeError("reopen failed")
        if self.pending_domain_refresh:
            self.pending_domain_refresh = False
            self._status["modified_since_checkout"] = True
            self._status["can_checkin"] = True
        return _DirtyAwareFakeSession(self, domain_path)


class _FailingRefreshHandle(_FakeHandle):
    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_project_data_calls += 1
        raise RuntimeError("repository refresh failed")


class _UnversionedAddableHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.add_calls = 0
        self._status.update(
            {
                "is_versioned": False,
                "is_checked_out": False,
                "is_checked_out_exclusive": False,
                "can_add_to_repository": True,
                "can_checkout": False,
                "can_checkin": False,
                "can_merge": False,
                "version": None,
                "latest_version": None,
                "is_latest_version": None,
            }
        )

    def add_program_to_version_control(self, domain_path: str, comment: str, *, keep_checked_out: bool = False):  # noqa: ARG002
        self.add_calls += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_checked_out": bool(keep_checked_out),
                "is_checked_out_exclusive": False,
                "can_add_to_repository": False,
                "can_checkout": not bool(keep_checked_out),
                "can_checkin": False,
                "version": 1,
                "latest_version": 1,
                "is_latest_version": True,
            }
        )


class _ExternallyVersionedOnReopenHandle(_UnversionedAddableHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.open_program_calls = 0

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        if not self._status["is_versioned"]:
            self._status.update(
                {
                    "is_versioned": True,
                    "can_add_to_repository": False,
                    "can_checkout": True,
                    "version": 1,
                    "latest_version": 1,
                    "is_latest_version": True,
                }
            )
        return _FakeSession(self, domain_path)


class _ExternallyVersionedOnRefreshHandle(_UnversionedAddableHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.open_program_calls = 0

    def refresh_project_data(self, *, force: bool = True):
        super().refresh_project_data(force=force)
        self._status.update(
            {
                "is_versioned": True,
                "can_add_to_repository": False,
                "can_checkout": True,
                "version": 1,
                "latest_version": 1,
                "is_latest_version": True,
            }
        )

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        return _FakeSession(self, domain_path)


class _UndoKeepProject(_FakeProject):
    def __init__(self, handle) -> None:  # noqa: ANN001
        super().__init__()
        self._handle = handle

    def save(self, _program) -> None:  # noqa: ANN001
        super().save(_program)
        if getattr(self._handle, "active_program_changed", False):
            self._handle.saved_before_keep = True


class _UndoKeepHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.project = _UndoKeepProject(self)
        self.active_program_changed = False
        self.program_reports_changed = False
        self.saved_before_keep = False
        self.kept_local_changes = False

    def mark_active_change(self) -> None:
        self._status["is_checked_out"] = True
        self.active_program_changed = True
        self.program_reports_changed = True
        self.saved_before_keep = False
        self.kept_local_changes = False

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):  # noqa: ARG002
        super().undo_checkout_program(domain_path, keep=keep)
        self._status["is_checked_out"] = False
        self.kept_local_changes = bool(keep and self.saved_before_keep and self.active_program_changed)
        self.active_program_changed = False
        self.program_reports_changed = False


class _UndoKeepPathHandle(_UndoKeepHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.keep_index = 0

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):  # noqa: ARG002
        super().undo_checkout_program(domain_path, keep=keep)
        if keep and self.kept_local_changes:
            suffix = ".keep" if self.keep_index == 0 else f".keep.{self.keep_index}"
            self.program_paths.add(f"{domain_path}{suffix}")
            self.keep_index += 1


class _TerminateCheckoutHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "can_checkout": False,
                "can_checkin": True,
                "version": 3,
                "latest_version": 3,
                "checkout_status": {"checkout_id": 7},
                "checkouts": [
                    {"checkout_id": 4, "user": "user"},
                    {"checkout_id": 7, "user": "mecha_ghidra"},
                ],
            }
        )
        self.terminated_checkout_ids: list[int] = []
        self.needs_reopen_after_terminate = False

    def terminate_checkout_program(self, domain_path: str, checkout_id: int):  # noqa: ARG002
        self.terminated_checkout_ids.append(int(checkout_id))
        if int(checkout_id) == 7:
            self.needs_reopen_after_terminate = True
            self._status.update(
                {
                    "is_versioned": False,
                    "is_checked_out": False,
                    "can_checkout": False,
                    "can_checkin": False,
                    "is_hijacked": True,
                    "version": 2,
                    "latest_version": 0,
                    "checkout_status": None,
                    "checkouts": [{"checkout_id": 4, "user": "user"}],
                }
            )

    def open_program(self, domain_path: str):
        if self.fail_reopen:
            raise RuntimeError("reopen failed")
        if self.needs_reopen_after_terminate:
            self.needs_reopen_after_terminate = False
            self._status.update(
                {
                    "is_versioned": True,
                    "is_checked_out": False,
                    "can_checkout": True,
                    "can_checkin": False,
                    "is_hijacked": False,
                    "version": 3,
                    "latest_version": 3,
                    "is_latest_version": True,
                    "checkout_status": None,
                    "checkouts": [{"checkout_id": 4, "user": "user"}],
                }
            )
        return _FakeSession(self, domain_path)


class _CleanCheckedOutHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": False,
                "can_checkin": False,
            }
        )


class _FailingSaveStaleHandle(_StaleStatusHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.project = _FailingSaveProject()


class _FailingSaveCleanCheckedOutHandle(_CleanCheckedOutHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.project = _FailingSaveProject()


class _DuplicateSessionRejectingHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.open_program_calls = 0

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        raise RuntimeError(f"Program already has an active session: {domain_path}")


class _ExplodingCommitHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": True,
                "can_checkin": True,
            }
        )

    def commit_program(self, domain_path: str, message: str, *, keep_checked_out: bool = False):  # noqa: ARG002
        raise RuntimeError("commit exploded")


class _PatchedProjectHandle:
    @staticmethod
    def make_key(project_location: str, project_name: str | None) -> tuple[str, str]:
        return (project_location, project_name or "")


def _build_sync_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    handle_cls: type[_FakeHandle] = _FakeHandle,
    session_cls: type[_FakeSession] = _FakeSession,
) -> tuple[RuntimeSyncOperations, RuntimeSessionStore, _DummyCore, _FakeHandle]:
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store as session_store_module

    monkeypatch.setattr(session_store_module, "ProjectHandle", _PatchedProjectHandle)

    core = _DummyCore()
    state = RuntimeState(
        core_accessor=lambda: core,
        checkout_required_commands=set(),
        normalize_result=lambda value: value,
    )
    store = RuntimeSessionStore(state=state, core_accessor=lambda: core)
    handle = handle_cls("/tmp/prj", "sample")
    session = session_cls(handle, "/main")
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


def test_pull_abort_refreshes_active_checked_out_changes(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert handle.project.saved == 0
    assert core.initialized == []


def test_pull_abort_fails_closed_when_dirty_state_unavailable(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FailingChangedFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert handle.project.saved == 0
    assert core.initialized == []


def test_pull_discard_refreshes_active_checked_out_changes(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["updated"] is True
    assert result["discarded_local_changes"] is True
    assert result["followed_latest"] is False
    assert result["merged"] is False
    assert handle.project.saved == 0
    assert handle.undo_checkout_calls == 0
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_pull_abort_on_runtime_marked_dirty_changes(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    store.mark_dirty_program("fw", "/main")

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert handle.project.saved == 0


def test_pull_discard_on_runtime_marked_dirty_changes(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    store.mark_dirty_program("fw", "/main")

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["discarded_local_changes"] is True
    assert handle.project.saved == 0
    assert handle.undo_checkout_calls == 0
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_pull_abort_unsaved_active_changes_does_not_try_to_save(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailingSaveStaleHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _FailingSaveStaleHandle)
    handle.mark_active_change()

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert handle.project.saved == 0


def test_pull_discard_unsaved_active_changes_does_not_try_to_save(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailingSaveStaleHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _FailingSaveStaleHandle)
    handle.mark_active_change()

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["discarded_local_changes"] is True
    assert handle.project.saved == 0


def test_pull_follows_latest_by_dropping_stale_checkout_instead_of_merging(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = True  # noqa: SLF001
    handle._status["can_merge"] = True  # noqa: SLF001
    handle._status["is_latest_version"] = False  # noqa: SLF001
    handle._status["latest_version"] = 2  # noqa: SLF001

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["updated"] is True
    assert result["merged"] is False
    assert result["followed_latest"] is True
    assert result["discarded_local_changes"] is False
    assert handle.undo_checkout_calls == 1
    assert handle.merge_calls == 0
    assert handle._status["is_checked_out"] is False  # noqa: SLF001
    assert handle._status["can_merge"] is False  # noqa: SLF001


def test_pull_rejects_unsafe_merge_when_merge_is_required_without_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = False  # noqa: SLF001
    handle._status["can_merge"] = True  # noqa: SLF001

    with pytest.raises(RuntimeError, match="UNSAFE_MERGE_REQUIRED"):
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert handle.undo_checkout_calls == 0
    assert handle.merge_calls == 0


def test_commit_aborts_on_conflict_by_default(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = True  # noqa: SLF001
    handle._status["can_merge"] = True  # noqa: SLF001
    handle._status["is_latest_version"] = False  # noqa: SLF001

    with pytest.raises(RuntimeError, match="UNSAFE_MERGE_REQUIRED"):
        sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert handle.undo_checkout_calls == 0
    assert handle.merge_calls == 0


def test_commit_abort_on_conflict_does_not_save_unsaved_active_changes(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    handle._status["can_merge"] = True  # noqa: SLF001
    handle._status["is_latest_version"] = False  # noqa: SLF001

    with pytest.raises(RuntimeError, match="UNSAFE_MERGE_REQUIRED"):
        sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert handle.project.saved == 0
    assert handle.undo_checkout_calls == 0
    assert handle.merge_calls == 0
    assert core.initialized == []


def test_commit_discards_conflict_only_when_requested(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = True  # noqa: SLF001
    handle._status["can_merge"] = True  # noqa: SLF001
    handle._status["is_latest_version"] = False  # noqa: SLF001
    handle._status["latest_version"] = 2  # noqa: SLF001

    result = sync.commit_project_program(
        "fw",
        "rename functions",
        auto_checkout=False,
        on_conflict="discard",
        domain_path="/main",
    )

    assert result["status"] == "noop"
    assert result["reason"] == "conflict_discarded"
    assert result["discarded_local_changes"] is False
    assert result["merged"] is False
    assert handle.undo_checkout_calls == 1
    assert handle.merge_calls == 0


def test_commit_discard_on_conflict_does_not_save_unsaved_active_changes(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    handle._status["can_merge"] = True  # noqa: SLF001
    handle._status["is_latest_version"] = False  # noqa: SLF001
    handle._status["latest_version"] = 2  # noqa: SLF001

    result = sync.commit_project_program(
        "fw",
        "rename functions",
        auto_checkout=False,
        on_conflict="discard",
        domain_path="/main",
    )

    assert result["status"] == "noop"
    assert result["reason"] == "conflict_discarded"
    assert result["discarded_local_changes"] is True
    assert result["merged"] is False
    assert handle.project.saved == 0
    assert handle.undo_checkout_calls == 1
    assert handle.merge_calls == 0
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_commit_rejects_invalid_conflict_action(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, _handle = _build_sync_runtime(monkeypatch)

    with pytest.raises(ValueError, match="on_conflict must be either 'abort' or 'discard'"):
        sync.commit_project_program("fw", "rename functions", on_conflict="merge", domain_path="/main")


def test_undo_checkout_keep_changes_saves_active_program(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_UndoKeepPathHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _UndoKeepPathHandle)
    handle.mark_active_change()

    result = sync.undo_checkout_project_program("fw", discard_local_changes=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is False
    assert handle.project.saved == 1
    assert handle.kept_local_changes is True
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_undo_checkout_keep_changes_reopens_keep_file(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_UndoKeepPathHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _UndoKeepPathHandle)
    handle.mark_active_change()

    result = sync.undo_checkout_project_program("fw", discard_local_changes=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["program"] == "/main"
    assert result["kept_program"] == "/main.keep"
    assert store.session_domain_path(store.sessions["fw"]) == "/main.keep"
    assert handle.project.saved == 1
    assert handle.kept_local_changes is True
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_undo_checkout_keep_path_uses_numeric_suffix_order(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UndoKeepPathHandle)
    handle.program_paths.update({"/main.keep.9", "/main.keep.10"})

    result = sync._resolve_new_keep_domain_path(handle, "/main", {"/main"})  # noqa: SLF001

    assert result == "/main.keep.10"


def test_undo_checkout_keep_without_changes_reopens_original_program(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UndoKeepPathHandle)
    assert isinstance(handle, _UndoKeepPathHandle)
    handle._status["is_checked_out"] = True  # noqa: SLF001

    result = sync.undo_checkout_project_program("fw", discard_local_changes=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["program"] == "/main"
    assert "kept_program" not in result
    assert result["checked_out"] is False
    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert handle.kept_local_changes is False
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_undo_checkout_discard_changes_does_not_save_active_program(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UndoKeepHandle)
    assert isinstance(handle, _UndoKeepHandle)
    handle.mark_active_change()

    result = sync.undo_checkout_project_program("fw", discard_local_changes=True, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is False
    assert handle.project.saved == 0
    assert handle.kept_local_changes is False
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_checkout_reloads_active_program_and_rebinds_context(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)

    result = sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert isinstance(store.sessions["fw"], _FakeSession)
    assert store.sessions["fw"] is not None
    assert handle.project.saved == 0
    assert handle._status["is_checked_out"] is True  # noqa: SLF001


def test_add_to_version_control_then_checkout_reloads_and_checks_out(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UnversionedAddableHandle)
    original_session = store.sessions["fw"]

    add_result = sync.add_project_program_to_version_control(
        "fw",
        "Initial import",
        keep_checked_out=False,
        domain_path="/main",
    )
    checkout_result = sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert add_result["status"] == "ok"
    assert add_result["is_versioned"] is True
    assert add_result["checked_out"] is False
    assert checkout_result["status"] == "ok"
    assert checkout_result["checked_out"] is True
    assert checkout_result["already_checked_out"] is False
    assert handle.add_calls == 1
    assert handle._status["is_checked_out"] is True  # noqa: SLF001
    assert store.sessions["fw"] is not original_session
    assert [key for _program, key in core.initialized] == ["fw", "fw"]


def test_checkout_refreshes_loaded_program_after_external_add_to_version_control(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnRefreshHandle,
    )
    original_session = store.sessions["fw"]

    result = sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["already_checked_out"] is False
    assert handle.refresh_project_data_calls == 1
    assert handle.open_program_calls == 1
    assert handle._status["is_checked_out"] is True  # noqa: SLF001
    assert store.sessions["fw"] is not original_session
    assert [key for _program, key in core.initialized] == ["fw"]


def test_sync_status_refreshes_project_data_after_external_add_to_version_control(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnRefreshHandle,
    )

    result = sync.get_project_sync_status("fw", domain_path="/main")

    assert result["is_versioned"] is True
    assert result["can_add_to_repository"] is False
    assert result["version"] == 1
    assert handle.refresh_project_data_calls == 1
    assert handle.open_program_calls == 0
    assert core.initialized == []


def test_sync_status_tolerates_refresh_failure(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_FailingRefreshHandle)

    result = sync.get_project_sync_status("fw", domain_path="/main")

    assert result["is_versioned"] is True
    assert handle.refresh_project_data_calls == 1


def test_mutating_sync_refresh_failure_aborts_before_operation(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_FailingRefreshHandle)

    with pytest.raises(RuntimeError, match="SYNC_REFRESH_FAILED"):
        sync.checkout_project_program("fw", domain_path="/main")

    assert handle.refresh_project_data_calls == 1
    assert handle.checkout_calls == 0


def test_add_to_version_control_noops_after_external_add_to_version_control(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnRefreshHandle,
    )

    result = sync.add_project_program_to_version_control(
        "fw",
        "Initial import",
        keep_checked_out=False,
        domain_path="/main",
    )

    assert result == {
        "status": "noop",
        "reason": "already_versioned",
        "target": "fw",
        "program": "/main",
        "version": 1,
    }
    assert handle.add_calls == 0
    assert handle.refresh_project_data_calls == 1
    assert handle.open_program_calls == 0
    assert core.initialized == []


@pytest.mark.parametrize(
    "operation",
    [
        lambda sync: sync.commit_project_program("fw", "rename functions", auto_checkout=True, domain_path="/main"),
        lambda sync: sync.pull_project_program("fw", domain_path="/main"),
        lambda sync: sync.get_version_history("fw", domain_path="/main"),
        lambda sync: sync.get_version_diff("fw", from_version=1, to_version=1, domain_path="/main"),
    ],
)
def test_versioned_sync_operations_refresh_project_data_after_external_add_to_version_control(
    monkeypatch: pytest.MonkeyPatch,
    operation,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnRefreshHandle,
    )

    result = operation(sync)

    assert isinstance(result, dict)
    assert handle.refresh_project_data_calls == 1
    assert handle.add_calls == 0


def test_checkout_reopens_loaded_program_when_external_add_requires_reopen(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnReopenHandle,
    )
    original_session = store.sessions["fw"]

    result = sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["already_checked_out"] is False
    assert handle.refresh_project_data_calls == 1
    assert handle.open_program_calls == 2
    assert handle._status["is_checked_out"] is True  # noqa: SLF001
    assert store.sessions["fw"] is not original_session
    assert [key for _program, key in core.initialized] == ["fw", "fw"]


def test_commit_reopens_loaded_program_when_external_add_requires_reopen(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnReopenHandle,
    )
    original_session = store.sessions["fw"]

    result = sync.commit_project_program("fw", "rename functions", auto_checkout=True, domain_path="/main")

    assert result["status"] == "noop"
    assert result["reason"] == "not_modified"
    assert result["checked_out"] is True
    assert handle.refresh_project_data_calls == 1
    assert handle.open_program_calls == 2
    assert handle.checkout_calls == 1
    assert store.sessions["fw"] is not original_session
    assert [key for _program, key in core.initialized] == ["fw", "fw"]


def test_checkout_does_not_refresh_unversioned_dirty_loaded_program(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UnversionedAddableHandle)
    store.mark_dirty_program("fw", "/main")

    with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
        sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    assert handle._status["is_versioned"] is False  # noqa: SLF001
    assert handle._status["is_checked_out"] is False  # noqa: SLF001
    assert core.initialized == []


def test_checkout_registered_only_target_reloads_loaded_owner_after_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.checkout_project_program("fw-shadow", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["already_checked_out"] is False
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert handle._status["is_checked_out"] is True  # noqa: SLF001


def test_checkout_already_checked_out_reloads_loaded_owner(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_CleanCheckedOutHandle)
    assert isinstance(handle, _CleanCheckedOutHandle)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.checkout_project_program("fw-shadow", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["already_checked_out"] is True
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.session_domain_path(store.sessions["fw"]) == "/main"


def test_checkout_already_checked_out_does_not_reload_dirty_loaded_owner(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    original_session = store.sessions["fw"]
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.checkout_project_program("fw-shadow", exclusive=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["already_checked_out"] is True
    assert store.sessions["fw"] is original_session
    assert original_session.close_saves == []
    assert handle.project.saved == 0
    assert core.initialized == []


def test_reload_reopen_failure_cleans_target_state(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    handle.fail_reopen = True

    with pytest.raises(RuntimeError, match="REOPEN_FAILED"):
        sync.reload_project_program("fw", domain_path="/main")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert "fw" not in store.target_projects
    assert core.removed == ["fw"]


def test_reload_close_failure_cleans_target_state(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, _handle = _build_sync_runtime(monkeypatch, session_cls=_FailingCloseSession)

    with pytest.raises(RuntimeError, match="SESSION_CLOSE_FAILED: failed to close program: close failed"):
        sync.reload_project_program("fw", domain_path="/main")

    assert "fw" not in store.sessions
    assert "fw" not in store.locks
    assert core.removed == ["fw"]


def test_reload_registered_only_target_reports_target_already_loaded(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_DuplicateSessionRejectingHandle)
    assert isinstance(handle, _DuplicateSessionRejectingHandle)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(DomainError) as exc_info:
        sync.reload_project_program("fw-shadow", domain_path="main")

    err = exc_info.value
    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "reload_project_program",
        "target": "fw-shadow",
        "domain_path": "/main",
        "owner_target": "fw",
    }
    assert handle.open_program_calls == 0
    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert core.initialized == []


def test_commit_operation_failure_after_reopen_preserves_reopened_target(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExplodingCommitHandle,
        session_cls=_ClosingSession,
    )
    assert isinstance(handle, _ExplodingCommitHandle)

    with pytest.raises(RuntimeError, match="commit exploded"):
        sync.commit_project_program("fw", "msg", auto_checkout=False, domain_path="/main")

    assert "fw" in store.sessions
    assert "fw" in store.locks
    assert "fw" in store.target_projects
    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert core.removed == []


def test_commit_unversioned_addable_program_returns_required_action(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_versioned": False,
            "can_add_to_repository": True,
            "can_checkout": False,
            "can_checkin": False,
            "version": None,
            "latest_version": None,
            "is_latest_version": None,
        }
    )

    result = sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert result == {
        "status": "noop",
        "reason": "not_versioned",
        "target": "fw",
        "program": "/main",
        "required_action": "add_project_program_to_version_control",
        "can_add_to_repository": True,
        "message": (
            "Program is not under version control; "
            "run add_project_program_to_version_control before commit_project_program."
        ),
    }
    assert handle.project.saved == 0


@pytest.mark.parametrize(
    "operation",
    [
        lambda sync: sync.checkout_project_program("fw", domain_path="/main"),
        lambda sync: sync.pull_project_program("fw", domain_path="/main"),
        lambda sync: sync.get_version_history("fw", domain_path="/main"),
        lambda sync: sync.get_version_diff("fw", from_version=1, to_version=2, domain_path="/main"),
    ],
)
def test_unversioned_addable_sync_operations_report_required_action(
    monkeypatch: pytest.MonkeyPatch,
    operation,
):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_versioned": False,
            "can_add_to_repository": True,
            "can_checkout": False,
            "can_checkin": False,
            "version": None,
            "latest_version": None,
            "is_latest_version": None,
        }
    )

    with pytest.raises(DomainError) as exc_info:
        operation(sync)

    err = exc_info.value
    assert err.code == ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED
    assert err.details == {
        "required_action": "add_project_program_to_version_control",
        "can_add_to_repository": True,
    }


def test_terminate_checkout_rejects_active_own_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_TerminateCheckoutHandle)
    assert isinstance(handle, _TerminateCheckoutHandle)

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw", checkout_id=7, domain_path="/main")

    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert handle.terminated_checkout_ids == []
    assert handle._status["is_hijacked"] is False  # noqa: SLF001
    assert handle._status["is_versioned"] is True  # noqa: SLF001
    assert core.initialized == []


def test_terminate_checkout_rejects_closed_local_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_TerminateCheckoutHandle)
    assert isinstance(handle, _TerminateCheckoutHandle)
    store.sessions.pop("fw")

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw", checkout_id=7, domain_path="/main")

    assert handle.terminated_checkout_ids == []
    assert handle._status["is_hijacked"] is False  # noqa: SLF001
    assert handle._status["is_versioned"] is True  # noqa: SLF001
    assert core.initialized == []


def test_terminate_checkout_rejects_active_checkout_loaded_by_other_target(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, handle_cls=_TerminateCheckoutHandle)
    assert isinstance(handle, _TerminateCheckoutHandle)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw-shadow", checkout_id=7, domain_path="/main")

    assert store.session_domain_path(store.sessions["fw"]) == "/main"
    assert handle.terminated_checkout_ids == []
    assert handle._status["is_hijacked"] is False  # noqa: SLF001
    assert handle._status["is_versioned"] is True  # noqa: SLF001
    assert core.initialized == []


def test_delete_shared_project_file_deletes_registered_unloaded_versioned_file(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")

    result = sync.delete_shared_project_file(
        "fw",
        domain_path="main",
        confirm="/main",
        expected_latest_version=1,
    )

    assert result == {
        "status": "ok",
        "target": "fw",
        "program": "/main",
        "domain_path": "/main",
        "deleted": True,
        "content_type": "Program",
        "was_versioned": True,
        "version": 1,
        "latest_version": 1,
    }
    assert handle.deleted_domain_files == ["/main"]
    assert "/main" not in handle.program_paths


def test_delete_shared_project_file_requires_confirmation(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)

    with pytest.raises(ValueError, match="confirm must exactly match"):
        sync.delete_shared_project_file("fw", domain_path="main", confirm="main")

    assert handle.deleted_domain_files == []


def test_delete_shared_project_file_rejects_loaded_program(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(DomainError) as exc_info:
        sync.delete_shared_project_file("fw-shadow", domain_path="/main", confirm="/main")

    err = exc_info.value
    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "delete_shared_project_file",
        "target": "fw-shadow",
        "domain_path": "/main",
        "owner_target": "fw",
    }
    assert handle.deleted_domain_files == []
    assert core.initialized == []


def test_delete_shared_project_file_rejects_active_checkouts(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")
    handle._status["checkouts"] = [{"checkout_id": 7}]  # noqa: SLF001

    with pytest.raises(RuntimeError, match="SHARED_FILE_DELETE_BLOCKED"):
        sync.delete_shared_project_file("fw", domain_path="/main", confirm="/main")

    assert handle.deleted_domain_files == []


def test_delete_shared_project_file_rejects_stale_expected_version(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")
    handle._status["latest_version"] = 2  # noqa: SLF001

    with pytest.raises(RuntimeError, match="LATEST_VERSION_MISMATCH"):
        sync.delete_shared_project_file(
            "fw",
            domain_path="/main",
            confirm="/main",
            expected_latest_version=1,
        )

    assert handle.deleted_domain_files == []


def test_delete_shared_project_file_requires_allow_private_for_unversioned_file(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UnversionedAddableHandle)
    store.sessions.pop("fw")

    with pytest.raises(RuntimeError, match="PRIVATE_FILE_DELETE_NOT_ALLOWED"):
        sync.delete_shared_project_file("fw", domain_path="/main", confirm="/main")

    result = sync.delete_shared_project_file(
        "fw",
        domain_path="/main",
        confirm="/main",
        allow_private=True,
    )

    assert result["status"] == "ok"
    assert result["was_versioned"] is False
    assert result["latest_version"] is None
    assert handle.deleted_domain_files == ["/main"]


def test_sync_status_reports_active_checked_out_changes_without_side_effects(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    session = store.sessions["fw"]

    result = sync.get_project_sync_status("fw", domain_path="/main")

    assert result["modified_since_checkout"] is True
    assert result["can_checkin"] is True
    assert handle.project.saved == 0
    assert core.initialized == []
    assert store.sessions["fw"] is session
    assert isinstance(store.sessions["fw"], _DirtyAwareFakeSession)


def test_sync_status_reports_runtime_marked_dirty_without_side_effects(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    session = store.sessions["fw"]
    store.mark_dirty_program("fw", "/main")

    result = sync.get_project_sync_status("fw", domain_path="/main")

    assert result["modified_since_checkout"] is True
    assert result["can_checkin"] is True
    assert handle.project.saved == 0
    assert core.initialized == []
    assert store.sessions["fw"] is session


def test_sync_status_reports_loaded_owner_changes_for_registered_only_target(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.get_project_sync_status("fw-shadow", domain_path="/main")

    assert result["modified_since_checkout"] is True
    assert result["can_checkin"] is True
    assert handle.project.saved == 0
    assert core.initialized == []


def test_commit_refreshes_active_status_before_checkin(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()

    result = sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["new_version"] == 2
    assert handle.project.saved == 2


def test_commit_auto_checkout_registered_only_target_reloads_loaded_owner(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": False,
            "modified_since_checkout": True,
            "can_checkin": True,
        }
    )
    original_session = store.sessions["fw"]
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.commit_project_program("fw-shadow", "rename functions", auto_checkout=True, domain_path="/main")

    assert result["status"] == "ok"
    assert result["new_version"] == 2
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.sessions["fw"] is not original_session


def test_commit_refreshes_runtime_marked_dirty_status_before_checkin(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    store.mark_dirty_program("fw", "/main")

    result = sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert result["status"] == "ok"
    assert result["new_version"] == 2
    assert handle.project.saved == 2


def test_commit_not_modified_active_program_does_not_try_to_save(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailingSaveCleanCheckedOutHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _FailingSaveCleanCheckedOutHandle)

    result = sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert result["status"] == "noop"
    assert result["reason"] == "not_modified"
    assert handle.project.saved == 0


def test_pull_registered_only_target_reopens_loaded_owner(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_DirtyAwareFakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    original_session = store.sessions["fw"]
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.pull_project_program("fw-shadow", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["discarded_local_changes"] is True
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.sessions["fw"] is not original_session


def test_undo_checkout_registered_only_target_reopens_loaded_owner(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = True  # noqa: SLF001
    original_session = store.sessions["fw"]
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    result = sync.undo_checkout_project_program("fw-shadow", discard_local_changes=True, domain_path="/main")

    assert result["status"] == "ok"
    assert result["checked_out"] is False
    assert core.initialized and core.initialized[-1][1] == "fw"
    assert store.sessions["fw"] is not original_session
