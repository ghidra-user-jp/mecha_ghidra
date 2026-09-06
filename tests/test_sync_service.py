from __future__ import annotations

from contextlib import contextmanager

import pytest

from ghidra_mcp.application.services import SyncService
from ghidra_mcp.domain import DomainError, ErrorCode


class DummyLockManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, str | None]] = []

    @contextmanager
    def acquire(self, *, target: str | None = None, project_key: str | None = None, timeout: float = 0.1):  # noqa: ARG002
        self.calls.append((target, project_key))
        yield


class DummyRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.project_keys: dict[str, str] = {"fw": "/tmp/prj::sample"}

    def project_lock_key(self, name: str) -> str | None:
        return self.project_keys.get(name)

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None):
        self.calls.append(("get_project_sync_status", (name,), {"domain_path": domain_path}))
        return {"target": name, "program": domain_path or "/main"}

    def checkout_project_program(self, name: str, *, exclusive: bool = False, domain_path: str | None = None):
        self.calls.append(("checkout_project_program", (name,), {"exclusive": exclusive, "domain_path": domain_path}))
        return {"status": "ok"}

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "add_project_program_to_version_control",
                (name, comment),
                {"keep_checked_out": keep_checked_out, "domain_path": domain_path},
            )
        )
        return {"status": "ok"}

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "commit_project_program",
                (name, message),
                {
                    "keep_checked_out": keep_checked_out,
                    "auto_checkout": auto_checkout,
                    "on_conflict": on_conflict,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok"}

    def pull_project_program(self, name: str, *, on_local_changes: str = "abort", domain_path: str | None = None):
        self.calls.append(
            ("pull_project_program", (name,), {"on_local_changes": on_local_changes, "domain_path": domain_path})
        )
        return {"status": "ok"}

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "undo_checkout_project_program",
                (name,),
                {"discard_local_changes": discard_local_changes, "domain_path": domain_path},
            )
        )
        return {"status": "ok"}

    def terminate_project_program_checkout(self, name: str, *, checkout_id: int, domain_path: str | None = None):
        self.calls.append(
            ("terminate_project_program_checkout", (name,), {"checkout_id": checkout_id, "domain_path": domain_path})
        )
        return {"status": "ok"}

    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
        allow_non_atomic_versioned_delete: bool = False,
    ):
        self.calls.append(
            (
                "delete_shared_project_file",
                (name,),
                {
                    "domain_path": domain_path,
                    "confirm": confirm,
                    "expected_latest_version": expected_latest_version,
                    "allow_private": allow_private,
                    "allow_non_atomic_versioned_delete": allow_non_atomic_versioned_delete,
                },
            )
        )
        return {"status": "ok"}

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None):
        self.calls.append(("get_version_history", (name,), {"limit": limit, "domain_path": domain_path}))
        return {"history": []}

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        include_details: bool = False,
        details_limit: int = 20,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "get_version_diff",
                (name,),
                {
                    "from_version": from_version,
                    "to_version": to_version,
                    "range_limit": range_limit,
                    "include_details": include_details,
                    "details_limit": details_limit,
                    "domain_path": domain_path,
                },
            )
        )
        return {"diffs": []}


def test_sync_service_lifecycle_and_lock_routing():
    runtime = DummyRuntime()
    lock_manager = DummyLockManager()
    service = SyncService(runtime, lock_manager=lock_manager)

    assert service.get_project_sync_status("fw") == {"target": "fw", "program": "/main"}
    assert service.checkout_project_program("fw", exclusive=True) == {"status": "ok"}
    assert service.add_project_program_to_version_control("fw", "init", keep_checked_out=True) == {"status": "ok"}
    assert service.commit_project_program("fw", "msg", keep_checked_out=False, auto_checkout=True) == {"status": "ok"}
    assert service.pull_project_program("fw", on_local_changes="discard") == {"status": "ok"}
    assert service.undo_checkout_project_program("fw", discard_local_changes=False) == {"status": "ok"}
    assert service.terminate_project_program_checkout("fw", checkout_id=1) == {"status": "ok"}
    assert service.delete_shared_project_file("fw", domain_path="/main", confirm="/main") == {"status": "ok"}
    assert service.get_version_history("fw", limit=10) == {"history": []}
    assert service.get_version_diff("fw", from_version=1, to_version=2) == {"diffs": []}

    assert lock_manager.calls == [("fw", "/tmp/prj::sample")] * 10


def test_sync_service_preserves_runtime_domain_error_code():
    class Runtime(DummyRuntime):
        def pull_project_program(self, name: str, *, on_local_changes: str = "abort", domain_path: str | None = None):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.VALIDATION_ERROR,
                message="on_local_changes must be either 'abort' or 'discard'",
                hint="check input",
                retryable=False,
                details={"on_local_changes": on_local_changes},
            )

    service = SyncService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.pull_project_program("fw", on_local_changes="invalid")

    err = exc_info.value
    assert err.code == ErrorCode.VALIDATION_ERROR
    assert err.details == {
        "on_local_changes": "invalid",
        "operation": "pull_project_program",
        "target": "fw",
        "domain_path": None,
    }


@pytest.mark.parametrize(
    "expected",
    [
        ErrorCode.CHECKOUT_REQUIRED,
        ErrorCode.NOT_SHARED_PROJECT,
        ErrorCode.NOT_CHECKED_OUT,
        ErrorCode.LOCAL_CHANGES_EXIST,
        ErrorCode.REOPEN_FAILED,
        ErrorCode.SAVE_FAILED,
    ],
)
def test_sync_service_preserves_runtime_domain_error_codes(expected: ErrorCode):
    class Runtime(DummyRuntime):
        def commit_project_program(
            self,
            name: str,  # noqa: ARG002
            message: str,  # noqa: ARG002
            *,
            keep_checked_out: bool = False,  # noqa: ARG002
            auto_checkout: bool = True,  # noqa: ARG002
            on_conflict: str = "abort",  # noqa: ARG002
            domain_path: str | None = None,  # noqa: ARG002
        ):
            raise DomainError(
                code=expected,
                message=f"{expected.value}: failure",
                hint="check runtime",
                retryable=expected in {ErrorCode.REOPEN_FAILED},
                details={"origin": "runtime"},
            )

    service = SyncService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.commit_project_program("fw", "msg")

    assert exc_info.value.code == expected
    assert exc_info.value.details == {
        "origin": "runtime",
        "operation": "commit_project_program",
        "target": "fw",
        "domain_path": None,
    }


def test_sync_service_fallback_non_domain_error_is_sync_operation_failed():
    class Runtime(DummyRuntime):
        def commit_project_program(
            self,
            name: str,  # noqa: ARG002
            message: str,  # noqa: ARG002
            *,
            keep_checked_out: bool = False,  # noqa: ARG002
            auto_checkout: bool = True,  # noqa: ARG002
            on_conflict: str = "abort",  # noqa: ARG002
            domain_path: str | None = None,  # noqa: ARG002
        ):
            raise RuntimeError("unexpected failure")

    service = SyncService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.commit_project_program("fw", "msg")

    assert exc_info.value.code == ErrorCode.SYNC_OPERATION_FAILED
    assert exc_info.value.details == {
        "operation": "commit_project_program",
        "target": "fw",
        "domain_path": None,
        "cause_type": "RuntimeError",
        "cause_message": "unexpected failure",
    }


def test_sync_service_fallback_non_domain_lock_error_is_project_locked():
    class Runtime(DummyRuntime):
        def commit_project_program(
            self,
            name: str,  # noqa: ARG002
            message: str,  # noqa: ARG002
            *,
            keep_checked_out: bool = False,  # noqa: ARG002
            auto_checkout: bool = True,  # noqa: ARG002
            on_conflict: str = "abort",  # noqa: ARG002
            domain_path: str | None = None,  # noqa: ARG002
        ):
            raise RuntimeError("Unable to lock project! /home/ghidra/shared_ai")

    service = SyncService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.commit_project_program("fw", "msg")

    assert exc_info.value.code == ErrorCode.PROJECT_LOCKED
    assert exc_info.value.retryable is True
    assert exc_info.value.details == {
        "operation": "commit_project_program",
        "target": "fw",
        "domain_path": None,
        "cause_type": "RuntimeError",
        "cause_message": "Unable to lock project! <path>",
    }
