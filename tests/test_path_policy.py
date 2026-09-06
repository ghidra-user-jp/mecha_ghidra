from __future__ import annotations

import os

import pytest

from ghidra_mcp.application.services.path_policy import UNRESTRICTED_PATH_POLICY, PathPolicy
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.domain import DomainError, ErrorCode


def test_unrestricted_policy_accepts_any_path(tmp_path):
    UNRESTRICTED_PATH_POLICY.validate_import_path(str(tmp_path / "anything.bin"))
    UNRESTRICTED_PATH_POLICY.validate_project_location("/etc/anywhere.gpr")
    assert UNRESTRICTED_PATH_POLICY.is_unrestricted


def test_import_root_accepts_files_below_root_and_rejects_outside(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "nested").mkdir()
    policy = PathPolicy.from_roots(import_roots=[str(samples)])

    policy.validate_import_path(str(samples / "a.bin"))
    policy.validate_import_path(str(samples / "nested" / "b.bin"))
    with pytest.raises(DomainError) as exc_info:
        policy.validate_import_path(str(tmp_path / "outside.bin"))
    assert exc_info.value.code == ErrorCode.PATH_NOT_ALLOWED
    assert exc_info.value.details["allowed_roots"] == [str(samples.resolve())]


def test_dot_dot_traversal_is_rejected(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    (tmp_path / "secret.bin").write_bytes(b"x")
    policy = PathPolicy.from_roots(import_roots=[str(samples)])

    with pytest.raises(DomainError):
        policy.validate_import_path(str(samples / ".." / "secret.bin"))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_escaping_root_is_rejected(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"x")
    (samples / "link").symlink_to(outside)
    policy = PathPolicy.from_roots(import_roots=[str(samples)])

    with pytest.raises(DomainError):
        policy.validate_import_path(str(samples / "link" / "secret.bin"))


def test_project_root_applies_to_gpr_files_and_directories(tmp_path):
    projects = tmp_path / "projects"
    projects.mkdir()
    policy = PathPolicy.from_roots(project_roots=[str(projects)])

    policy.validate_project_location(str(projects / "demo.gpr"))
    policy.validate_project_location(str(projects))
    with pytest.raises(DomainError) as exc_info:
        policy.validate_project_location(str(tmp_path / "elsewhere.gpr"))
    assert exc_info.value.details["kind"] == "project"


def test_missing_root_directory_is_a_configuration_error(tmp_path):
    with pytest.raises(ValueError, match="--allowed-import-root"):
        PathPolicy.from_roots(import_roots=[str(tmp_path / "missing")])


class _RecordingRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    def project_lock_key(self, name):
        return None

    def create_project(self, project_location, *, project_name=None, overwrite=False):
        self.calls.append(("create_project", (project_location,)))
        return {"status": "ok"}

    def create_session(self, name, project_location, *, project_name=None, domain_path=None):
        self.calls.append(("create_session", (name, project_location)))
        return {"project_location": project_location, "project_name": project_name, "domain_path": domain_path}

    def register_target(self, name, project_location, *, project_name=None):
        self.calls.append(("register_target", (name, project_location)))
        return {"target": name}

    def import_program(self, name, binary_path, **kwargs):
        self.calls.append(("import_program", (name, binary_path)))
        return "/prog"


def test_target_service_enforces_policy_before_touching_the_runtime(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    projects = tmp_path / "projects"
    projects.mkdir()
    runtime = _RecordingRuntime()
    service = TargetService(
        runtime,
        path_policy=PathPolicy.from_roots(import_roots=[str(samples)], project_roots=[str(projects)]),
    )

    with pytest.raises(DomainError) as exc_info:
        service.import_program("fw", str(tmp_path / "evil.bin"))
    assert exc_info.value.code == ErrorCode.PATH_NOT_ALLOWED
    assert exc_info.value.details["operation"] == "import_program"

    for call in (
        lambda: service.create_project(str(tmp_path / "x.gpr")),
        lambda: service.create_session("fw", str(tmp_path / "x.gpr"), domain_path="/main"),
        lambda: service.register_target("fw", str(tmp_path / "x.gpr")),
    ):
        with pytest.raises(DomainError) as exc_info:
            call()
        assert exc_info.value.code == ErrorCode.PATH_NOT_ALLOWED
    assert runtime.calls == []

    service.import_program("fw", str(samples / "ok.bin"))
    service.register_target("fw", str(projects / "ok.gpr"))
    assert [name for name, _ in runtime.calls] == ["import_program", "register_target"]


def test_export_root_restricts_output_paths(tmp_path):
    from ghidra_mcp.application.services.path_policy import PathPolicy
    from ghidra_mcp.domain import DomainError, ErrorCode

    root = tmp_path / "exports"
    root.mkdir()
    policy = PathPolicy.from_roots(export_roots=[root])

    assert policy.restricts_exports is True
    assert policy.is_unrestricted is False
    policy.validate_export_path(str(root / "sample.gzf"))
    with pytest.raises(DomainError) as exc_info:
        policy.validate_export_path(str(tmp_path / "elsewhere.gzf"))
    assert exc_info.value.code is ErrorCode.PATH_NOT_ALLOWED
    assert exc_info.value.details["kind"] == "export"


def test_registry_adapter_checks_export_path_before_running_the_core_command(tmp_path):
    from ghidra_mcp.application.services.path_policy import PathPolicy
    from ghidra_mcp.application.services.target_service import TargetService
    from ghidra_mcp.domain import DomainError
    from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter

    class _Core:
        def __init__(self) -> None:
            self.calls = []

        def call(self, command, params, target):
            self.calls.append((command, dict(params), target))
            return {"status": "ok"}

    root = tmp_path / "exports"
    root.mkdir()
    core = _Core()
    target_service = TargetService(object(), path_policy=PathPolicy.from_roots(export_roots=[root]))  # type: ignore[arg-type]
    adapter = ServiceRegistryAdapter(
        core_command_service=core,  # type: ignore[arg-type]
        target_service=target_service,
        sync_service=object(),  # type: ignore[arg-type]
        bsim_service=object(),  # type: ignore[arg-type]
    )

    with pytest.raises(DomainError):
        adapter.export_program("fw", str(tmp_path / "outside.gzf"))
    assert core.calls == []

    adapter.export_program("fw", str(root / "ok.gzf"), format="binary", overwrite=True)
    assert core.calls == [
        ("export_program", {"output_path": str(root / "ok.gzf"), "format": "binary", "overwrite": True}, "fw")
    ]
