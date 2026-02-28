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
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "commit_project_program",
                (name, message),
                {
                    "keep_checked_out": keep_checked_out,
                    "auto_checkout": auto_checkout,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok"}

    def pull_project_program(self, name: str, *, on_local_changes: str = "abort", domain_path: str | None = None):
        self.calls.append(("pull_project_program", (name,), {"on_local_changes": on_local_changes, "domain_path": domain_path}))
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
        self.calls.append(("terminate_project_program_checkout", (name,), {"checkout_id": checkout_id, "domain_path": domain_path}))
        return {"status": "ok"}

    def reload_project_program(self, name: str, *, domain_path: str | None = None):
        self.calls.append(("reload_project_program", (name,), {"domain_path": domain_path}))
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
                    "domain_path": domain_path,
                },
            )
        )
        return {"diffs": []}


class PullValidationRuntime(DummyRuntime):
    def pull_project_program(self, name: str, *, on_local_changes: str = "abort", domain_path: str | None = None):  # noqa: ARG002
        raise ValueError("on_local_changes は 'abort' または 'discard' を指定してください")


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
    assert service.reload_project_program("fw") == {"status": "ok"}
    assert service.get_version_history("fw", limit=10) == {"history": []}
    assert service.get_version_diff("fw", from_version=1, to_version=2) == {"diffs": []}

    assert lock_manager.calls == [("fw", "/tmp/prj::sample")] * 10


def test_sync_service_maps_validation_error_to_domain_error():
    service = SyncService(PullValidationRuntime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.pull_project_program("fw", on_local_changes="invalid")

    err = exc_info.value
    assert err.code == ErrorCode.VALIDATION_ERROR
    assert err.details == {
        "operation": "pull_project_program",
        "target": "fw",
        "domain_path": None,
    }


@pytest.mark.parametrize(
    ("runtime_message", "expected"),
    [
        ("CHECKOUT_REQUIRED: checkout が必要です", ErrorCode.CHECKOUT_REQUIRED),
        ("NOT_SHARED_PROJECT: shared project ではありません", ErrorCode.NOT_SHARED_PROJECT),
        ("NOT_CHECKED_OUT: checkout されていません", ErrorCode.NOT_CHECKED_OUT),
        ("LOCAL_CHANGES_EXIST: ローカル変更があります", ErrorCode.LOCAL_CHANGES_EXIST),
        ("REOPEN_FAILED: reopen 失敗", ErrorCode.REOPEN_FAILED),
        ("SAVE_FAILED: save 失敗", ErrorCode.SAVE_FAILED),
    ],
)
def test_sync_service_maps_runtime_error_codes(runtime_message: str, expected: ErrorCode):
    class Runtime(DummyRuntime):
        def commit_project_program(
            self,
            name: str,
            commit_message: str,
            *,
            keep_checked_out: bool = False,
            auto_checkout: bool = True,
            domain_path: str | None = None,
        ):  # noqa: ARG002
            raise RuntimeError(runtime_message)

    service = SyncService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.commit_project_program("fw", "msg")

    assert exc_info.value.code == expected
    assert exc_info.value.details == {
        "operation": "commit_project_program",
        "target": "fw",
        "domain_path": None,
    }
