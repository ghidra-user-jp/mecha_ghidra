from __future__ import annotations

from contextlib import contextmanager

import pytest

from ghidra_mcp.application.services import TargetService
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
        self.project_keys: dict[str, str] = {}

    def project_lock_key(self, name: str) -> str | None:
        return self.project_keys.get(name)

    def create_session(self, name: str, project_location: str, *, project_name: str | None = None, domain_path: str | None = None):
        self.calls.append(("create_session", (name, project_location), {"project_name": project_name, "domain_path": domain_path}))
        return {"target": name, "domain_path": domain_path}

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None):
        self.calls.append(("register_target", (name, project_location), {"project_name": project_name}))
        self.project_keys[name] = f"{project_location}::{project_name or ''}"
        return {"target": name}

    def list_targets(self):
        self.calls.append(("list_targets", (), {}))
        return [{"target": "fw"}]

    def list_programs(self, name: str):
        self.calls.append(("list_programs", (name,), {}))
        return []

    def load_program(self, name: str, domain_path: str):
        self.calls.append(("load_program", (name, domain_path), {}))
        return domain_path

    def import_program(self, name: str, binary_path: str, **kwargs):
        self.calls.append(("import_program", (name, binary_path), dict(kwargs)))
        return "/imported.bin"

    def close_session(self, name: str, *, remove_program: bool = False):
        self.calls.append(("close_session", (name,), {"remove_program": remove_program}))

    def close_all(self) -> None:
        self.calls.append(("close_all", (), {}))

    def has_sessions(self) -> bool:
        return True

    def has_targets(self) -> bool:
        return True


def test_target_service_lifecycle_and_lock_routing():
    runtime = DummyRuntime()
    runtime.project_keys["fw"] = "/tmp/prj::sample"
    lock_manager = DummyLockManager()
    service = TargetService(runtime, lock_manager=lock_manager)

    assert service.register_target("fw", "/tmp/prj", project_name="sample") == {"target": "fw"}
    assert service.create_session("fw", "/tmp/prj", project_name="sample", domain_path="/main") == {
        "target": "fw",
        "project_location": "/tmp/prj",
        "project_name": "sample",
        "domain_path": "/main",
    }
    assert service.list_targets() == [{"target": "fw"}]
    assert service.list_programs("fw") == []
    assert service.load_program("fw", "/next") == "/next"
    assert (
        service.import_program(
            "fw",
            "/tmp/a.exe",
            import_mode="raw_binary",
            language_id="x86:LE:32:default",
            base_address="0x401000",
        )
        == "/imported.bin"
    )
    assert service.close_session("fw", remove_program=True) == {
        "closed": True,
        "target": "fw",
        "remove_program": True,
    }

    lock_targets = [target for target, _project in lock_manager.calls]
    assert lock_targets == ["fw", "fw", "fw", "fw", "fw", "fw"]


def test_target_service_preserves_runtime_domain_error_code():
    class Runtime(DummyRuntime):
        def load_program(self, name: str, domain_path: str):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.VALIDATION_ERROR,
                message="domain_path is required",
                hint="check input",
                retryable=False,
                details={"domain_path": domain_path},
            )

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.load_program("fw", "")

    err = exc_info.value
    assert err.code == ErrorCode.VALIDATION_ERROR
    assert err.details == {"domain_path": "", "operation": "load_program", "target": "fw"}


def test_target_service_preserves_session_not_found_domain_error():
    class Runtime(DummyRuntime):
        def list_programs(self, name: str):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.SESSION_NOT_FOUND,
                message="Session 'fw' is not initialized",
                hint="load first",
                retryable=False,
                details={},
            )

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.list_programs("fw")

    assert exc_info.value.code == ErrorCode.SESSION_NOT_FOUND
    assert exc_info.value.details == {"operation": "list_programs", "target": "fw"}


def test_target_service_fallback_non_domain_error_is_operation_failed():
    class Runtime(DummyRuntime):
        def list_programs(self, name: str):  # noqa: ARG002
            raise RuntimeError("unexpected failure")

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.list_programs("fw")

    assert exc_info.value.code == ErrorCode.OPERATION_FAILED
    assert exc_info.value.details == {"operation": "list_programs", "target": "fw"}


def test_target_service_preserves_domain_error_and_merges_details():
    class Runtime(DummyRuntime):
        def import_program(self, name: str, binary_path: str, **kwargs):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.PROGRAM_NOT_FOUND,
                message="program not found",
                hint="check path",
                retryable=False,
                details={"binary_path": binary_path},
            )

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.import_program("fw", "/tmp/missing.exe")

    err = exc_info.value
    assert err.code == ErrorCode.PROGRAM_NOT_FOUND
    assert err.details == {
        "binary_path": "/tmp/missing.exe",
        "operation": "import_program",
        "target": "fw",
    }


def test_target_service_preserves_target_already_loaded_error_details():
    class Runtime(DummyRuntime):
        def load_program(self, name: str, domain_path: str):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.TARGET_ALREADY_LOADED,
                message="TARGET_ALREADY_LOADED: program already loaded: /main",
                hint="Use the existing target directly instead of reloading the same program",
                retryable=False,
                details={"domain_path": domain_path, "owner_target": "fw-primary"},
            )

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.load_program("fw-shadow", "/main")

    err = exc_info.value
    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "domain_path": "/main",
        "owner_target": "fw-primary",
        "operation": "load_program",
        "target": "fw-shadow",
    }


def test_target_service_preserves_program_already_imported_error_details():
    class Runtime(DummyRuntime):
        def import_program(self, name: str, binary_path: str, **kwargs):  # noqa: ARG002
            raise DomainError(
                code=ErrorCode.PROGRAM_ALREADY_IMPORTED,
                message="PROGRAM_ALREADY_IMPORTED: program already exists: /sample.exe",
                hint="Use load_project_program with the existing domain path instead of importing again",
                retryable=False,
                details={
                    "binary_path": binary_path,
                    "existing_domain_path": "/sample.exe",
                },
            )

    service = TargetService(Runtime(), lock_manager=DummyLockManager())

    with pytest.raises(DomainError) as exc_info:
        service.import_program("fw", "/tmp/sample.exe")

    err = exc_info.value
    assert err.code == ErrorCode.PROGRAM_ALREADY_IMPORTED
    assert err.details == {
        "binary_path": "/tmp/sample.exe",
        "existing_domain_path": "/sample.exe",
        "operation": "import_program",
        "target": "fw",
    }
