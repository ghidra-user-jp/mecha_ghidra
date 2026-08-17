from __future__ import annotations

import threading

import pytest

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.core_execution import RuntimeCoreExecution
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.sync_operations import RuntimeSyncOperations
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.target_lifecycle import RuntimeTargetLifecycle


class _DummyCore:
    def __init__(self) -> None:
        self.initialized: list[tuple[object, str]] = []
        self.removed: list[str] = []
        self.executed: list[tuple[str, dict, str]] = []

    def execute(self, command: str, params: dict, *, key: str):
        self.executed.append((command, params, key))
        return {"status": "ok", "command": command}

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


class _BrokenDomainPathSession(_FakeSession):
    def get_program(self):
        raise RuntimeError("domain path unavailable")


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


class _LiveFailingCloseSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:  # noqa: ARG002
        self.close_saves.append(bool(save))
        raise RuntimeError("PROGRAM_CLOSE_FAILED: close failed while program remains open")


class _FailingCloseReopenedSession(_FakeSession):
    def close(self, *, save: bool = True, remove_program: bool = False) -> None:  # noqa: ARG002
        self.close_saves.append(bool(save))
        raise RuntimeError("reopened close failed")


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

    def save_program(self, program, *, force: bool = False):  # noqa: ANN001
        if not force and not bool(program.isChanged()):
            return False
        self.project.save(program)
        return True

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
        if self._status.get("latest_version") is not None:
            self._status["version"] = self._status["latest_version"]

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


class _CheckoutRefusedHandle(_FakeHandle):
    def checkout_program(self, domain_path: str, *, exclusive: bool = False):  # noqa: ARG002
        self.checkout_calls += 1
        return False


class _SharedIdentityHandle(_FakeHandle):
    def __init__(
        self,
        project_location: str,
        project_name: str,
        *,
        shared_url: str = "ghidra://localhost/mecha_sync_test",
        file_id: str = "shared-file-id-main",
    ) -> None:
        super().__init__(project_location, project_name)
        self._shared_url = shared_url
        self._file_id = file_id

    def get_shared_project_url(self) -> str:
        return self._shared_url

    def get_domain_file_id(self, domain_path: str) -> str:
        assert domain_path == "/main"
        return self._file_id


class _VersionedDomainFile(_FakeDomainFile):
    def __init__(self, path: str, version: int) -> None:
        super().__init__(path)
        self._version = version

    def getVersion(self) -> int:
        return self._version


class _VersionedProgram(_FakeProgram):
    def __init__(self, path: str, version: int) -> None:
        super().__init__(path)
        self._version = version

    def getDomainFile(self):
        return _VersionedDomainFile(self._path, self._version)


class _VersionedSession(_FakeSession):
    def __init__(self, handle, path: str, version: int | None = None):  # noqa: ANN001
        super().__init__(handle, path)
        self._version = int(version if version is not None else handle.loaded_version)

    def get_program(self):
        return _VersionedProgram(self._path, self._version)


class _RemoteAdvanceHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.loaded_version = 1
        self.open_program_calls = 0

    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        super().refresh_project_data(force=force)
        self._status.update(
            {
                "version": 2,
                "latest_version": 2,
                "is_latest_version": True,
            }
        )

    def open_program(self, domain_path: str):
        self.open_program_calls += 1
        self.loaded_version = int(self._status["version"])
        return _VersionedSession(self, domain_path)


class _HijackedRecoveryHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_versioned": False,
                "is_hijacked": True,
                "can_add_to_repository": False,
                "can_checkout": False,
                "can_checkin": False,
                "version": None,
                "latest_version": None,
                "is_latest_version": None,
            }
        )
        self.discarded_hijacks = 0

    def delete_domain_file(self, domain_path: str):
        self.discarded_hijacks += 1
        self._status.update(
            {
                "is_versioned": True,
                "is_hijacked": False,
                "can_checkout": True,
                "version": 4,
                "latest_version": 4,
                "is_latest_version": True,
            }
        )
        return {"domain_path": domain_path, "content_type": "Program"}


class _FailPostCheckoutStatusHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.fail_status = False

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        if self.fail_status:
            raise RuntimeError("repository disconnected after checkout")
        return super().get_sync_status(domain_path)

    def checkout_program(self, domain_path: str, *, exclusive: bool = False):
        result = super().checkout_program(domain_path, exclusive=exclusive)
        self.fail_status = True
        return result


class _FailPostCommitStatusHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.fail_status = False
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": True,
                "can_checkin": True,
            }
        )

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        if self.fail_status:
            raise RuntimeError("repository disconnected after commit")
        return super().get_sync_status(domain_path)

    def commit_program(self, domain_path: str, message: str, *, keep_checked_out: bool = False):
        super().commit_program(domain_path, message, keep_checked_out=keep_checked_out)
        self.fail_status = True


class _FailCommitPrecheckRefreshHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.commit_calls = 0
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": True,
                "can_checkin": True,
            }
        )

    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_project_data_calls += 1
        if self.refresh_project_data_calls == 2:
            raise RuntimeError("repository disconnected before commit")

    def commit_program(self, domain_path: str, message: str, *, keep_checked_out: bool = False):
        self.commit_calls += 1
        return super().commit_program(
            domain_path,
            message,
            keep_checked_out=keep_checked_out,
        )


class _FailPullNoopRefreshHandle(_FakeHandle):
    def refresh_project_data(self, *, force: bool = True):  # noqa: ARG002
        self.refresh_project_data_calls += 1
        if self.refresh_project_data_calls == 2:
            raise RuntimeError("repository disconnected during no-op pull")


class _FailPostUndoStatusHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.fail_status = False
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": True,
            }
        )

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        if self.fail_status:
            raise RuntimeError("repository disconnected after undo checkout")
        return super().get_sync_status(domain_path)

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):
        super().undo_checkout_program(domain_path, keep=keep)
        self.fail_status = True


class _StaleAfterUndoHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "modified_since_checkout": True,
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):
        super().undo_checkout_program(domain_path, keep=keep)
        self._status.update(
            {
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )


class _MergeStateAfterUndoHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "can_merge": True,
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):
        super().undo_checkout_program(domain_path, keep=keep)
        self._status.update(
            {
                "is_checked_out": False,
                "can_merge": True,
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )


class _CheckoutStateAfterUndoHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "is_checked_out": True,
                "can_merge": True,
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):
        super().undo_checkout_program(domain_path, keep=keep)
        self._status.update(
            {
                "is_checked_out": True,
                "can_merge": False,
                "version": 2,
                "latest_version": 2,
                "is_latest_version": True,
            }
        )


class _PersistentlyStaleHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self._status.update(
            {
                "version": 1,
                "latest_version": 2,
                "is_latest_version": False,
            }
        )


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


class _FailPostAddStatusHandle(_UnversionedAddableHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.fail_status = False

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        if self.fail_status:
            raise RuntimeError("repository disconnected after add")
        return super().get_sync_status(domain_path)

    def add_program_to_version_control(self, domain_path: str, comment: str, *, keep_checked_out: bool = False):
        super().add_program_to_version_control(
            domain_path,
            comment,
            keep_checked_out=keep_checked_out,
        )
        self.fail_status = True


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
        self.undo_keep_values: list[bool] = []

    def mark_active_change(self) -> None:
        self._status["is_checked_out"] = True
        self.active_program_changed = True
        self.program_reports_changed = True
        self.saved_before_keep = False
        self.kept_local_changes = False

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False):  # noqa: ARG002
        was_modified_since_checkout = bool(self._status.get("modified_since_checkout"))
        self.undo_keep_values.append(bool(keep))
        super().undo_checkout_program(domain_path, keep=keep)
        self._status["is_checked_out"] = False
        self.kept_local_changes = bool(
            keep
            and (
                was_modified_since_checkout
                or (self.saved_before_keep and self.active_program_changed)
            )
        )
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
        self._status["checkouts"] = [
            item
            for item in self._status.get("checkouts", [])
            if int(item.get("checkout_id")) != int(checkout_id)
        ]
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


class _FailPostTerminateStatusHandle(_TerminateCheckoutHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.fail_status = False

    def get_sync_status(self, domain_path: str):  # noqa: ARG002
        if self.fail_status:
            raise RuntimeError("repository disconnected after terminate")
        return super().get_sync_status(domain_path)

    def terminate_checkout_program(self, domain_path: str, checkout_id: int):
        self.terminated_checkout_ids.append(int(checkout_id))
        self.fail_status = True


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


class _RegisteredOnlyCloseFailureHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.opened_sessions: list[_LiveFailingCloseSession] = []

    def open_program(self, domain_path: str):
        session = _LiveFailingCloseSession(self, domain_path)
        self.opened_sessions.append(session)
        return session


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


class _FailingCloseReopenHandle(_FakeHandle):
    def __init__(self, project_location: str, project_name: str) -> None:
        super().__init__(project_location, project_name)
        self.reopened_sessions: list[_FailingCloseReopenedSession] = []

    def open_program(self, domain_path: str):
        reopened = _FailingCloseReopenedSession(self, domain_path)
        self.reopened_sessions.append(reopened)
        return reopened


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


@pytest.mark.parametrize(
    ("handle_cls", "operation", "expected_operation"),
    [
        (
            _FailPostCheckoutStatusHandle,
            lambda sync: sync.checkout_project_program("fw", domain_path="/main"),
            "checkout_project_program",
        ),
        (
            _FailPostAddStatusHandle,
            lambda sync: sync.add_project_program_to_version_control("fw", "initial", domain_path="/main"),
            "add_project_program_to_version_control",
        ),
        (
            _FailPostCommitStatusHandle,
            lambda sync: sync.commit_project_program(
                "fw",
                "change",
                auto_checkout=False,
                domain_path="/main",
            ),
            "commit_project_program",
        ),
        (
            _FailPostUndoStatusHandle,
            lambda sync: sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main"),
            "pull_project_program.discard_local_changes",
        ),
        (
            _FailPostUndoStatusHandle,
            lambda sync: sync.undo_checkout_project_program("fw", domain_path="/main"),
            "undo_checkout_project_program",
        ),
        (
            _FailPostTerminateStatusHandle,
            lambda sync: sync.terminate_project_program_checkout("fw", checkout_id=4, domain_path="/main"),
            "terminate_project_program_checkout",
        ),
    ],
)
def test_sync_side_effect_postcondition_failure_is_non_retryable_partial_success(
    monkeypatch: pytest.MonkeyPatch,
    handle_cls,
    operation,
    expected_operation: str,
):
    sync, _store, _core, _handle = _build_sync_runtime(monkeypatch, handle_cls=handle_cls)

    with pytest.raises(DomainError) as exc_info:
        operation(sync)

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": expected_operation,
        "operation_completed": True,
        "partial_success": True,
    }


def test_commit_precheck_refresh_failure_is_not_reported_as_completed_commit(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailCommitPrecheckRefreshHandle,
    )
    assert isinstance(handle, _FailCommitPrecheckRefreshHandle)

    with pytest.raises(RuntimeError, match="repository disconnected before commit") as exc_info:
        sync.commit_project_program(
            "fw",
            "change",
            auto_checkout=False,
            domain_path="/main",
        )

    assert not isinstance(exc_info.value, DomainError)
    assert handle.commit_calls == 0


def test_checkout_postcondition_requires_successful_repository_refresh(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)

    def refresh_project_data(*, force: bool = True):  # noqa: ARG001
        handle.refresh_project_data_calls += 1
        if handle.checkout_calls:
            raise RuntimeError("repository disconnected after checkout")

    monkeypatch.setattr(handle, "refresh_project_data", refresh_project_data)

    with pytest.raises(DomainError) as exc_info:
        sync.checkout_project_program("fw", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "checkout_project_program",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.refresh_project_data_calls == 2


def test_auto_checkout_postcondition_mismatch_is_partial_success(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    monkeypatch.setattr(handle, "checkout_program", lambda *_args, **_kwargs: True)

    with pytest.raises(DomainError) as exc_info:
        sync.commit_project_program("fw", "change", auto_checkout=True, domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "commit_project_program.auto_checkout",
        "operation_completed": True,
        "partial_success": True,
    }


def test_auto_checkout_rollback_postcondition_mismatch_is_partial_success(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnReopenHandle,
    )
    monkeypatch.setattr(handle, "undo_checkout_program", lambda *_args, **_kwargs: None)

    with pytest.raises(DomainError) as exc_info:
        sync.commit_project_program("fw", "change", auto_checkout=True, domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "commit_project_program.rollback_auto_checkout",
        "operation_completed": True,
        "partial_success": True,
    }


def test_add_postcondition_rejects_success_without_versioned_state(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_UnversionedAddableHandle,
    )
    monkeypatch.setattr(handle, "add_program_to_version_control", lambda *_args, **_kwargs: None)

    with pytest.raises(DomainError) as exc_info:
        sync.add_project_program_to_version_control("fw", "initial", domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "add_project_program_to_version_control",
        "operation_completed": True,
        "partial_success": True,
    }


def test_commit_postcondition_rejects_success_without_version_advance(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": True,
            "modified_since_checkout": True,
            "can_checkin": True,
        }
    )
    monkeypatch.setattr(handle, "commit_program", lambda *_args, **_kwargs: None)

    with pytest.raises(DomainError) as exc_info:
        sync.commit_project_program("fw", "change", auto_checkout=False, domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "commit_project_program",
        "operation_completed": True,
        "partial_success": True,
    }


def test_undo_postcondition_rejects_success_while_still_checked_out(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status["is_checked_out"] = True  # noqa: SLF001
    monkeypatch.setattr(handle, "undo_checkout_program", lambda *_args, **_kwargs: None)

    with pytest.raises(DomainError) as exc_info:
        sync.undo_checkout_project_program("fw", domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "undo_checkout_project_program",
        "operation_completed": True,
        "partial_success": True,
    }


def test_terminate_postcondition_rejects_success_while_checkout_id_remains(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_TerminateCheckoutHandle,
    )
    store.sessions.pop("fw")
    monkeypatch.setattr(
        handle,
        "terminate_checkout_program",
        lambda _domain_path, checkout_id: handle.terminated_checkout_ids.append(int(checkout_id)),
    )

    with pytest.raises(DomainError) as exc_info:
        sync.terminate_project_program_checkout("fw", checkout_id=4, domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "terminate_project_program_checkout",
        "operation_completed": True,
        "partial_success": True,
    }


def test_delete_postcondition_rejects_unverified_path_removal(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")
    monkeypatch.setattr(
        handle,
        "delete_domain_file",
        lambda domain_path: {
            "domain_path": domain_path,
            "content_type": "Program",
            "deleted_verified": False,
        },
    )

    with pytest.raises(DomainError) as exc_info:
        sync.delete_shared_project_file(
            "fw",
            domain_path="/main",
            confirm="/main",
            expected_latest_version=1,
            allow_non_atomic_versioned_delete=True,
        )

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "delete_shared_project_file",
        "operation_completed": True,
        "partial_success": True,
    }


def test_pull_noop_refresh_failure_is_not_reported_as_completed_operation(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailPullNoopRefreshHandle,
    )
    assert isinstance(handle, _FailPullNoopRefreshHandle)
    store.sessions.pop("fw")

    with pytest.raises(RuntimeError, match="repository disconnected during no-op pull") as exc_info:
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert not isinstance(exc_info.value, DomainError)


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


def test_pull_discard_reopen_failure_exposes_completed_operation_result(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, session_cls=_ClosingSession)
    handle._status["modified_since_checkout"] = True  # noqa: SLF001
    handle.fail_reopen = True

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.details == {
        "operation_completed": True,
        "partial_success": True,
        "operation_result": {
            "discarded_local_changes": True,
            "merged": False,
            "followed_latest": False,
        },
    }
    assert "fw" not in store.sessions
    assert core.removed == ["fw"]


def test_add_to_version_control_reopen_failure_exposes_none_result_completion(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_UnversionedAddableHandle,
        session_cls=_ClosingSession,
    )
    handle.fail_reopen = True

    with pytest.raises(DomainError) as exc_info:
        sync.add_project_program_to_version_control("fw", "initial import", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.details == {"operation_completed": True, "partial_success": True}
    assert "fw" not in store.sessions
    assert core.removed == ["fw"]


def test_partial_operation_error_survives_a_second_reopen_failure(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailPostUndoStatusHandle,
        session_cls=_ClosingSession,
    )
    handle.fail_reopen = True

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.retryable is False
    assert err.details is not None
    assert err.details["operation"] == "pull_project_program.discard_local_changes"
    assert err.details["operation_completed"] is True
    assert err.details["partial_success"] is True
    assert "repository disconnected after undo checkout" in err.details["operation_error"]
    assert handle.undo_checkout_calls == 1
    assert handle._status["is_checked_out"] is False  # noqa: SLF001
    assert "fw" not in store.sessions
    assert core.removed == ["fw"]


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


def test_pull_discard_reports_following_latest_when_local_changes_and_remote_advance_coexist(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": True,
            "modified_since_checkout": True,
            "can_merge": True,
            "is_latest_version": False,
            "latest_version": 2,
        }
    )

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["discarded_local_changes"] is True
    assert result["followed_latest"] is True
    assert result["updated"] is True
    assert handle.undo_checkout_calls == 1


def test_pull_discard_fails_closed_when_undo_does_not_follow_latest(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleAfterUndoHandle,
    )

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "pull_project_program",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.undo_checkout_calls == 1
    assert handle._status["is_checked_out"] is False  # noqa: SLF001


@pytest.mark.parametrize(
    "handle_cls",
    [_MergeStateAfterUndoHandle, _CheckoutStateAfterUndoHandle],
)
def test_pull_fails_closed_when_checkout_drop_postcondition_remains_active(
    monkeypatch: pytest.MonkeyPatch,
    handle_cls,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=handle_cls,
    )

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "pull_project_program.follow_latest",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.undo_checkout_calls == 1


def test_pull_discard_local_changes_preserves_partial_when_merge_state_remains(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_MergeStateAfterUndoHandle,
    )
    handle._status["modified_since_checkout"] = True  # noqa: SLF001

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert exc_info.value.details == {
        "operation": "pull_project_program.discard_local_changes",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.undo_checkout_calls == 1


def test_pull_clean_reload_fails_closed_when_program_remains_stale(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, _handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_PersistentlyStaleHandle,
    )

    with pytest.raises(DomainError) as exc_info:
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "pull_project_program",
        "operation_completed": True,
        "partial_success": True,
    }


def test_pull_unloaded_noop_stale_state_is_retryable_precondition_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, _handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_PersistentlyStaleHandle,
    )
    store.sessions.pop("fw")

    with pytest.raises(DomainError, match="FOLLOW_LATEST_FAILED") as exc_info:
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is True
    assert err.details == {
        "operation": "pull_project_program",
        "operation_completed": False,
        "partial_success": False,
    }


def test_pull_reopens_clean_unchecked_out_program_after_remote_version_advance(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_RemoteAdvanceHandle,
        session_cls=_VersionedSession,
    )
    assert isinstance(handle, _RemoteAdvanceHandle)
    original_session = store.sessions["fw"]

    result = sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert result["status"] == "ok"
    assert result["updated"] is True
    assert result["followed_latest"] is True
    assert result["reloaded"] is True
    assert result["version"] == 2
    assert handle.open_program_calls == 1
    assert store.sessions["fw"] is not original_session
    assert store.sessions["fw"].get_program().getDomainFile().getVersion() == 2
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_pull_hijacked_program_aborts_without_explicit_discard(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_HijackedRecoveryHandle,
    )
    assert isinstance(handle, _HijackedRecoveryHandle)

    with pytest.raises(RuntimeError, match="HIJACKED_PROGRAM"):
        sync.pull_project_program("fw", on_local_changes="abort", domain_path="/main")

    assert handle.discarded_hijacks == 0


def test_pull_hijacked_program_discards_local_shadow_and_reopens_repository_version(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_HijackedRecoveryHandle,
    )
    assert isinstance(handle, _HijackedRecoveryHandle)
    original_session = store.sessions["fw"]

    result = sync.pull_project_program("fw", on_local_changes="discard", domain_path="/main")

    assert result["status"] == "ok"
    assert result["updated"] is True
    assert result["discarded_hijacked_file"] is True
    assert result["discarded_local_changes"] is True
    assert result["followed_latest"] is True
    assert result["version"] == 4
    assert handle.discarded_hijacks == 1
    assert store.sessions["fw"] is not original_session
    assert core.initialized and core.initialized[-1][1] == "fw"


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


def test_commit_rolls_back_auto_checkout_when_conflict_is_detected(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": False,
            "can_checkout": True,
            "can_merge": True,
            "is_latest_version": False,
            "latest_version": 2,
        }
    )

    with pytest.raises(RuntimeError, match="UNSAFE_MERGE_REQUIRED"):
        sync.commit_project_program(
            "fw",
            "rename functions",
            auto_checkout=True,
            domain_path="/main",
        )

    assert handle.checkout_calls == 1
    assert handle.undo_checkout_calls == 1
    assert handle._status["is_checked_out"] is False  # noqa: SLF001


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

    assert result["status"] == "ok"
    assert result["reason"] == "conflict_discarded"
    assert result["committed"] is False
    assert result["conflict_discarded"] is True
    assert result["discarded_local_changes"] is False
    assert result["merged"] is False
    assert handle.undo_checkout_calls == 1
    assert handle.merge_calls == 0


def test_commit_conflict_discard_fails_closed_when_checkout_drop_remains_stale(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleAfterUndoHandle,
    )
    handle._status["can_merge"] = True  # noqa: SLF001

    with pytest.raises(DomainError) as exc_info:
        sync.commit_project_program(
            "fw",
            "rename functions",
            auto_checkout=False,
            on_conflict="discard",
            domain_path="/main",
        )

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "commit_project_program.discard_conflict",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.undo_checkout_calls == 1
    assert handle._status["is_checked_out"] is False  # noqa: SLF001


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

    assert result["status"] == "ok"
    assert result["reason"] == "conflict_discarded"
    assert result["committed"] is False
    assert result["conflict_discarded"] is True
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
    assert handle.undo_keep_values == [False]
    assert not any(path.startswith("/main.keep") for path in handle.program_paths)
    assert core.initialized and core.initialized[-1][1] == "fw"


def test_undo_checkout_keep_reports_preserved_path_for_unloaded_program(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_UndoKeepPathHandle,
    )
    assert isinstance(handle, _UndoKeepPathHandle)
    store.sessions.pop("fw")
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": True,
            "modified_since_checkout": True,
        }
    )

    result = sync.undo_checkout_project_program(
        "fw",
        discard_local_changes=False,
        domain_path="/main",
    )

    assert result["status"] == "ok"
    assert result["checked_out"] is False
    assert result["kept_program"] == "/main.keep"
    assert handle.undo_keep_values == [True]
    assert "/main.keep" in handle.program_paths


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


def test_checkout_reopen_failure_reports_completed_remote_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, session_cls=_ClosingSession)
    handle.fail_reopen = True

    with pytest.raises(DomainError) as exc_info:
        sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "checkout_project_program",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.checkout_calls == 1
    assert handle._status["is_checked_out"] is True  # noqa: SLF001
    assert "fw" not in store.sessions
    assert core.removed == ["fw"]


def test_auto_checkout_reopen_failure_reports_completed_remote_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, session_cls=_ClosingSession)
    handle.fail_reopen = True

    with pytest.raises(DomainError) as exc_info:
        sync.commit_project_program("fw", "rename functions", auto_checkout=True, domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "commit_project_program.auto_checkout",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.checkout_calls == 1
    assert handle._status["is_checked_out"] is True  # noqa: SLF001
    assert handle._status["version"] == 1  # noqa: SLF001
    assert "fw" not in store.sessions
    assert core.removed == ["fw"]


def test_checkout_close_failure_reports_completed_remote_checkout(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        session_cls=_FailingCloseSession,
    )

    with pytest.raises(DomainError) as exc_info:
        sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "checkout_project_program",
        "operation_completed": True,
        "partial_success": True,
    }
    assert handle.checkout_calls == 1
    assert handle._status["is_checked_out"] is True  # noqa: SLF001


def test_checkout_refusal_is_reported_as_error(monkeypatch: pytest.MonkeyPatch):
    sync, _store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_CheckoutRefusedHandle,
    )

    with pytest.raises(RuntimeError, match="CHECKOUT_UNAVAILABLE"):
        sync.checkout_project_program("fw", exclusive=True, domain_path="/main")

    assert handle.checkout_calls == 1
    assert core.initialized == []


def test_checkout_reports_effective_exclusive_state(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, _handle = _build_sync_runtime(monkeypatch)

    result = sync.checkout_project_program("fw", exclusive=True, domain_path="/main")

    assert result["checked_out"] is True
    assert result["exclusive"] is True


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
    assert handle.refresh_project_data_calls == 2
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


def test_sync_status_fails_closed_when_refresh_fails(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_FailingRefreshHandle)

    with pytest.raises(RuntimeError, match="SYNC_REFRESH_FAILED"):
        sync.get_project_sync_status("fw", domain_path="/main")

    assert handle.refresh_project_data_calls == 1


def test_sync_runtime_target_lock_respects_deadline(monkeypatch: pytest.MonkeyPatch):
    import ghidra_mcp.infrastructure.ghidra_adapter.runtime.sync_operations as sync_module
    from ghidra_mcp.infrastructure.locks import acquire_ordered_locks as acquire_with_timeout

    sync, store, _core, _handle = _build_sync_runtime(monkeypatch)
    held = threading.Event()
    release = threading.Event()

    def hold_target_lock() -> None:
        with store.locks["fw"]:
            held.set()
            release.wait(timeout=2)

    holder = threading.Thread(target=hold_target_lock)
    holder.start()
    assert held.wait(timeout=1)
    monkeypatch.setattr(
        sync_module,
        "acquire_ordered_locks",
        lambda locks, **_kwargs: acquire_with_timeout(
            locks,
            timeout=0.02,
            message_prefix="runtime ",
        ),
    )

    try:
        with pytest.raises(DomainError) as exc_info:
            sync.get_project_sync_status("fw", domain_path="/main")
    finally:
        release.set()
        holder.join(timeout=1)

    assert exc_info.value.code == ErrorCode.LOCK_TIMEOUT
    assert exc_info.value.details["lock"] == "target"


def test_mutating_sync_refresh_failure_aborts_before_operation(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_FailingRefreshHandle)

    with pytest.raises(RuntimeError, match="SYNC_REFRESH_FAILED"):
        sync.checkout_project_program("fw", domain_path="/main")

    assert handle.refresh_project_data_calls == 1
    assert handle.checkout_calls == 0


def test_mutating_sync_requires_refresh_capability(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)
    monkeypatch.setattr(handle, "refresh_project_data", None)

    with pytest.raises(RuntimeError, match="SYNC_REFRESH_FAILED"):
        sync.checkout_project_program("fw", domain_path="/main")

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
    ("operation", "expected_refreshes"),
    [
        (
            lambda sync: sync.commit_project_program(
                "fw", "rename functions", auto_checkout=True, domain_path="/main"
            ),
            4,
        ),
        (lambda sync: sync.pull_project_program("fw", domain_path="/main"), 2),
        (lambda sync: sync.get_version_history("fw", domain_path="/main"), 1),
        (
            lambda sync: sync.get_version_diff(
                "fw", from_version=1, to_version=1, domain_path="/main"
            ),
            1,
        ),
    ],
)
def test_versioned_sync_operations_refresh_project_data_after_external_add_to_version_control(
    monkeypatch: pytest.MonkeyPatch,
    operation,
    expected_refreshes: int,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_ExternallyVersionedOnRefreshHandle,
    )

    result = operation(sync)

    assert isinstance(result, dict)
    assert handle.refresh_project_data_calls == expected_refreshes
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
    assert handle.refresh_project_data_calls == 2
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
    assert result["checked_out"] is False
    assert handle.refresh_project_data_calls == 4
    assert handle.open_program_calls == 3
    assert handle.checkout_calls == 1
    assert handle.undo_checkout_calls == 1
    assert store.sessions["fw"] is not original_session
    assert [key for _program, key in core.initialized] == ["fw", "fw", "fw"]


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


def test_cross_target_sync_uses_project_lock_without_nested_active_target_lock(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch, handle_cls=_UnversionedAddableHandle)
    assert isinstance(handle, _UnversionedAddableHandle)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    original_ensure_lock = store.ensure_lock

    def ensure_lock(name: str):
        if name == "fw":
            raise AssertionError("cross-target sync must not take the active target lock after caller lock")
        return original_ensure_lock(name)

    monkeypatch.setattr(store, "ensure_lock", ensure_lock)

    result = sync.add_project_program_to_version_control(
        "fw-shadow",
        "initial import",
        domain_path="/main",
    )

    assert result["status"] == "ok"
    assert handle.add_calls == 1
    assert handle.get_key() in store.project_locks


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


def test_sync_reopen_init_failure_preserves_reopened_session_when_close_fails(monkeypatch: pytest.MonkeyPatch):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_FailingCloseReopenHandle,
        session_cls=_ClosingSession,
    )
    assert isinstance(handle, _FailingCloseReopenHandle)

    def fail_initialize(_program, _key):  # noqa: ANN001
        raise RuntimeError("initialize failed")

    core.initialize = fail_initialize

    with pytest.raises(DomainError) as exc_info:
        sync.checkout_project_program("fw", exclusive=False, domain_path="/main")

    err = exc_info.value
    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.retryable is False
    assert err.details == {
        "operation": "checkout_project_program",
        "operation_completed": True,
        "partial_success": True,
    }
    assert store.sessions["fw"] is handle.reopened_sessions[-1]
    assert "fw" in store.locks
    assert store.target_projects["fw"] == handle.get_key()
    assert core.removed == []


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


def test_reload_registered_only_target_fails_closed_when_loaded_target_inspection_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, session_cls=_BrokenDomainPathSession)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target 'fw'"):
        sync.reload_project_program("fw-shadow", domain_path="/main")

    assert "fw" in store.sessions
    assert core.initialized == []


def test_reload_registered_only_target_preserves_live_session_when_close_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_RegisteredOnlyCloseFailureHandle,
    )
    assert isinstance(handle, _RegisteredOnlyCloseFailureHandle)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(RuntimeError, match="PROGRAM_CLOSE_FAILED"):
        sync.reload_project_program("fw-shadow", domain_path="/shadow")

    leaked_session = handle.opened_sessions[-1]
    assert leaked_session.close_saves == [False]
    assert store.sessions["fw-shadow"] is leaked_session
    assert store.target_projects["fw-shadow"] == handle.get_key()
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


def test_terminate_checkout_fails_closed_for_missing_local_checkout_status(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, _store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_TerminateCheckoutHandle,
    )
    assert isinstance(handle, _TerminateCheckoutHandle)
    handle._status["checkout_status"] = None  # noqa: SLF001

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: inconsistent checkout state"):
        sync.terminate_project_program_checkout("fw", checkout_id=7, domain_path="/main")

    assert handle.terminated_checkout_ids == []
    assert handle._status["is_checked_out"] is True  # noqa: SLF001


def test_terminate_checkout_rejects_active_checkout_loaded_from_another_local_cache(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_TerminateCheckoutHandle,
    )
    assert isinstance(loaded_handle, _TerminateCheckoutHandle)
    loaded_handle.get_shared_project_url = lambda: "ghidra://localhost/mecha_sync_test"  # type: ignore[attr-defined]
    remote_handle = _SharedIdentityHandle("/tmp/cache-b", "sample-b")
    remote_handle._status.update(  # noqa: SLF001
        {
            "checkout_status": None,
            "is_checked_out": False,
            "checkouts": [{"checkout_id": 7, "user": "mecha_ghidra"}],
        }
    )
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw-cache-b", checkout_id=7, domain_path="/main")

    assert loaded_handle.terminated_checkout_ids == []
    assert core.initialized == []


def test_terminate_checkout_rejects_dns_alias_cache_with_matching_file_id(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_TerminateCheckoutHandle,
    )
    assert isinstance(loaded_handle, _TerminateCheckoutHandle)
    loaded_handle.get_shared_project_url = lambda: "ghidra://repo-a.example/mecha_sync_test"  # type: ignore[attr-defined]
    loaded_handle.get_domain_file_id = lambda _path: "stable-repository-file-id"  # type: ignore[attr-defined]

    remote_handle = _SharedIdentityHandle(
        "/tmp/cache-b",
        "sample-b",
        shared_url="ghidra://repo-b.example/mecha_sync_test",
        file_id="stable-repository-file-id",
    )
    remote_handle._status.update(  # noqa: SLF001
        {
            "checkout_status": None,
            "is_checked_out": False,
            "checkouts": [{"checkout_id": 7, "user": "mecha_ghidra"}],
        }
    )
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw-cache-b", checkout_id=7, domain_path="/main")

    assert loaded_handle.terminated_checkout_ids == []
    assert core.initialized == []


def test_terminate_checkout_refreshes_other_local_cache_before_owner_check(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_SharedIdentityHandle,
    )
    loaded_handle._status.update(  # noqa: SLF001
        {
            "checkout_status": None,
            "is_checked_out": False,
        }
    )

    def refresh_loaded(*, force: bool = True):  # noqa: ARG001
        loaded_handle.refresh_project_data_calls += 1
        loaded_handle._status.update(  # noqa: SLF001
            {
                "checkout_status": {"checkout_id": 7},
                "is_checked_out": True,
            }
        )

    monkeypatch.setattr(loaded_handle, "refresh_project_data", refresh_loaded)
    remote_handle = _SharedIdentityHandle("/tmp/cache-b", "sample-b")
    remote_handle._status.update(  # noqa: SLF001
        {
            "checkout_status": None,
            "is_checked_out": False,
            "checkouts": [{"checkout_id": 7, "user": "mecha_ghidra"}],
        }
    )
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        sync.terminate_project_program_checkout("fw-cache-b", checkout_id=7, domain_path="/main")

    assert loaded_handle.refresh_project_data_calls == 1


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
        allow_non_atomic_versioned_delete=True,
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
        "atomic_version_guard": False,
    }
    assert handle.deleted_domain_files == ["/main"]
    assert "/main" not in handle.program_paths


def test_delete_shared_project_file_requires_confirmation(monkeypatch: pytest.MonkeyPatch):
    sync, _store, _core, handle = _build_sync_runtime(monkeypatch)

    with pytest.raises(ValueError, match="confirm must exactly match"):
        sync.delete_shared_project_file("fw", domain_path="main", confirm="main")

    assert handle.deleted_domain_files == []


def test_delete_shared_project_file_refuses_non_atomic_versioned_delete_by_default(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")

    with pytest.raises(RuntimeError, match="UNSAFE_VERSIONED_DELETE"):
        sync.delete_shared_project_file(
            "fw",
            domain_path="/main",
            confirm="/main",
            expected_latest_version=1,
        )

    assert handle.deleted_domain_files == []


def test_delete_shared_project_file_opt_in_requires_expected_version(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")

    with pytest.raises(ValueError, match="expected_latest_version is required"):
        sync.delete_shared_project_file(
            "fw",
            domain_path="/main",
            confirm="/main",
            allow_non_atomic_versioned_delete=True,
        )

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


def test_delete_shared_project_file_rejects_loaded_program_from_another_local_cache(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_SharedIdentityHandle,
    )
    # Host names are case-insensitive and an omitted Ghidra port means 13100.
    # These two cache URLs must therefore identify the same repository.
    loaded_handle._shared_url = "ghidra://LOCALHOST:13100/mecha_sync_test/"  # noqa: SLF001
    remote_handle = _SharedIdentityHandle("/tmp/cache-b", "sample-b")
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(DomainError) as exc_info:
        sync.delete_shared_project_file(
            "fw-cache-b",
            domain_path="/main",
            confirm="/main",
        )

    assert exc_info.value.code == ErrorCode.TARGET_ALREADY_LOADED
    assert exc_info.value.details and exc_info.value.details["owner_target"] == "fw"
    assert remote_handle.deleted_domain_files == []
    assert core.initialized == []


def test_delete_rejects_dns_alias_cache_with_matching_file_id(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_SharedIdentityHandle,
    )
    loaded_handle._shared_url = "ghidra://repo-a.example/mecha_sync_test"  # noqa: SLF001
    loaded_handle._file_id = "stable-repository-file-id"  # noqa: SLF001
    remote_handle = _SharedIdentityHandle(
        "/tmp/cache-b",
        "sample-b",
        shared_url="ghidra://repo-b.example/mecha_sync_test",
        file_id="stable-repository-file-id",
    )
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(DomainError) as exc_info:
        sync.delete_shared_project_file(
            "fw-cache-b",
            domain_path="/main",
            confirm="/main",
        )

    assert exc_info.value.code == ErrorCode.TARGET_ALREADY_LOADED
    assert exc_info.value.details and exc_info.value.details["owner_target"] == "fw"
    assert remote_handle.deleted_domain_files == []
    assert core.initialized == []


@pytest.mark.parametrize(
    ("first_url", "second_url"),
    [
        ("ghidra://LOCALHOST/repository/", "ghidra://localhost:13100/repository"),
        ("ghidra://127.0.0.1/repository", "ghidra://[::1]:13100/repository/"),
        ("GHIDRA://Server.Example./repository", "ghidra://server.example:13100/repository"),
    ],
)
def test_shared_project_identity_canonicalizes_safe_url_aliases(first_url: str, second_url: str):
    first = _SharedIdentityHandle("/tmp/cache-a", "sample-a", shared_url=first_url)
    second = _SharedIdentityHandle("/tmp/cache-b", "sample-b", shared_url=second_url)

    assert RuntimeSyncOperations._handles_share_project_identity(first, second) is True


def test_sync_project_identity_io_does_not_hold_registry_lock(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_SharedIdentityHandle,
    )
    identity_started = threading.Event()
    release_identity = threading.Event()
    registry_read = threading.Event()
    errors: list[BaseException] = []
    original_get_shared_url = handle.get_shared_project_url

    def blocking_get_shared_url():
        identity_started.set()
        if not release_identity.wait(timeout=2):
            raise AssertionError("timed out waiting to release project identity lookup")
        return original_get_shared_url()

    def read_registry() -> None:
        with store.registry_lock.read_lock():
            registry_read.set()

    def run_status() -> None:
        try:
            sync.get_project_sync_status("fw", domain_path="/main")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    monkeypatch.setattr(handle, "get_shared_project_url", blocking_get_shared_url)
    status_thread = threading.Thread(target=run_status)
    reader_thread = threading.Thread(target=read_registry)
    status_thread.start()
    assert identity_started.wait(timeout=1)
    reader_thread.start()

    try:
        assert registry_read.wait(timeout=1)
    finally:
        release_identity.set()
        status_thread.join(timeout=2)
        reader_thread.join(timeout=2)

    assert not status_thread.is_alive()
    assert not reader_thread.is_alive()
    assert errors == []


def test_delete_fails_closed_when_shared_project_identity_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, loaded_handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_SharedIdentityHandle,
    )

    def fail_shared_url():
        raise RuntimeError("SYNC_STATUS_UNAVAILABLE: shared project URL is unavailable")

    monkeypatch.setattr(loaded_handle, "get_shared_project_url", fail_shared_url)
    remote_handle = _SharedIdentityHandle("/tmp/cache-b", "sample-b")
    store.target_projects["fw-cache-b"] = remote_handle.get_key()
    store.locks["fw-cache-b"] = threading.RLock()
    store.project_handles[remote_handle.get_key()] = remote_handle

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE"):
        sync.delete_shared_project_file(
            "fw-cache-b",
            domain_path="/main",
            confirm="/main",
        )

    assert remote_handle.deleted_domain_files == []


def test_delete_blocks_late_session_creation_after_loaded_target_guard(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, _handle = _build_sync_runtime(monkeypatch)
    store.sessions.pop("fw")
    lifecycle = RuntimeTargetLifecycle(store=store)
    guard_reached = threading.Event()
    release_guard = threading.Event()
    create_attempted = threading.Event()
    create_entered = threading.Event()
    errors: list[BaseException] = []

    original_guard = sync._find_loaded_target_across_shared_project_locked  # noqa: SLF001

    def blocking_guard(*, handle, domain_path):  # noqa: ANN001
        guard_reached.set()
        if not release_guard.wait(timeout=2):
            raise AssertionError("timed out waiting to release delete guard")
        return original_guard(handle=handle, domain_path=domain_path)

    def fake_create_session(name, project_location, *, project_name, domain_path):  # noqa: ANN001, ARG001
        create_entered.set()
        return object()

    monkeypatch.setattr(sync, "_find_loaded_target_across_shared_project_locked", blocking_guard)
    monkeypatch.setattr(lifecycle, "_create_session_locked", fake_create_session)

    def run_delete() -> None:
        try:
            sync.delete_shared_project_file(
                "fw",
                domain_path="/main",
                confirm="/main",
                expected_latest_version=1,
                allow_non_atomic_versioned_delete=True,
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def run_create() -> None:
        create_attempted.set()
        try:
            lifecycle.create_session(
                "late-cache",
                "/tmp/cache-b",
                project_name="sample-b",
                domain_path="/main",
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    delete_thread = threading.Thread(target=run_delete)
    create_thread = threading.Thread(target=run_create)
    delete_thread.start()
    assert guard_reached.wait(timeout=2)
    create_thread.start()
    assert create_attempted.wait(timeout=2)
    assert not create_entered.wait(timeout=0.1)

    release_guard.set()
    delete_thread.join(timeout=2)
    create_thread.join(timeout=2)

    assert not delete_thread.is_alive()
    assert not create_thread.is_alive()
    assert errors == []
    assert create_entered.is_set()


def test_terminate_checkout_uses_global_writer_lock(monkeypatch: pytest.MonkeyPatch):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_TerminateCheckoutHandle,
    )
    assert isinstance(handle, _TerminateCheckoutHandle)
    store.sessions.pop("fw")

    class TrackingOperationLock:
        def __init__(self, delegate) -> None:  # noqa: ANN001
            self.delegate = delegate
            self.read_calls = 0
            self.write_calls = 0

        def read_lock(self):
            self.read_calls += 1
            return self.delegate.read_lock()

        def write_lock(self):
            self.write_calls += 1
            return self.delegate.write_lock()

    tracking_lock = TrackingOperationLock(store.operation_lock)
    store.operation_lock = tracking_lock

    result = sync.terminate_project_program_checkout("fw", checkout_id=4, domain_path="/main")

    assert result["status"] == "ok"
    assert handle.terminated_checkout_ids == [4]
    assert tracking_lock.write_calls == 1
    assert tracking_lock.read_calls == 0


def test_delete_shared_project_file_fails_closed_when_loaded_target_inspection_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, core, handle = _build_sync_runtime(monkeypatch, session_cls=_BrokenDomainPathSession)
    store.locks["fw-shadow"] = threading.RLock()
    store.target_projects["fw-shadow"] = handle.get_key()

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target 'fw'"):
        sync.delete_shared_project_file("fw-shadow", domain_path="/main", confirm="/main")

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
            allow_non_atomic_versioned_delete=True,
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
    assert result["atomic_version_guard"] is True
    assert handle.deleted_domain_files == ["/main"]


def test_delete_shared_project_file_refuses_hijacked_file_even_with_allow_private(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_HijackedRecoveryHandle,
    )
    store.sessions.pop("fw")

    with pytest.raises(RuntimeError, match="HIJACKED_PROGRAM"):
        sync.delete_shared_project_file(
            "fw",
            domain_path="/main",
            confirm="/main",
            allow_private=True,
        )

    assert handle.discarded_hijacks == 0


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


@pytest.mark.parametrize(
    ("command", "params"),
    [
        ("set_decompiler_comment", {"address": "0x401000", "comment": "memo"}),
        ("set_disassembly_comment", {"address": "0x401000", "comment": "memo"}),
        (
            "set_function_prototype",
            {"function_address": "0x401000", "prototype": "void FUN_401000(void)"},
        ),
        (
            "add_bookmark",
            {"address": "0x401000", "type": "Info", "category": "Analysis", "comment": "memo"},
        ),
    ],
)
def test_mutating_commands_mark_shared_program_dirty_for_sync_status(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    params: dict,
):
    sync, store, core, handle = _build_sync_runtime(monkeypatch)
    handle._status.update(  # noqa: SLF001
        {
            "is_checked_out": True,
            "modified_since_checkout": False,
            "can_checkin": False,
        }
    )
    execution = RuntimeCoreExecution(
        store=store,
        checkout_required_commands={command},
        normalize_result=lambda value: value,
    )

    execute_result = execution.call(command, params, target="fw")
    status = sync.get_project_sync_status("fw", domain_path="/main")

    assert execute_result == {"status": "ok", "command": command}
    assert core.executed == [(command, params, "fw")]
    assert store.is_dirty_program("fw", "/main")
    assert status["modified_since_checkout"] is True
    assert status["can_checkin"] is True


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


def test_save_then_commit_preserves_runtime_dirty_until_versioned_status_refresh(
    monkeypatch: pytest.MonkeyPatch,
):
    sync, store, _core, handle = _build_sync_runtime(
        monkeypatch,
        handle_cls=_StaleStatusHandle,
        session_cls=_FakeSession,
    )
    assert isinstance(handle, _StaleStatusHandle)
    handle.mark_active_change()
    store.mark_dirty_program("fw", "/main")
    lifecycle = RuntimeTargetLifecycle(store=store)

    save_result = lifecycle.save_project_program("fw", domain_path="/main")
    status_after_save = sync.get_project_sync_status("fw", domain_path="/main")
    commit_result = sync.commit_project_program("fw", "rename functions", auto_checkout=False, domain_path="/main")

    assert save_result == {"status": "ok", "target": "fw", "program": "/main", "saved": True}
    assert status_after_save["modified_since_checkout"] is True
    assert status_after_save["can_checkin"] is True
    assert commit_result["status"] == "ok"
    assert commit_result["new_version"] == 2


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
