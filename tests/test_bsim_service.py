from __future__ import annotations

from typing import Any

import pytest

from ghidra_mcp.application.services.bsim_service import BsimConfig, BsimService


class FakeCoreCommandService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []
        self.responses: dict[str, Any] = {}
        self.errors: dict[str, Exception] = {}

    def call(self, command: str, params: dict[str, Any], target: str):
        self.calls.append((command, dict(params), target))
        if command in self.errors:
            raise self.errors[command]
        if command in self.responses:
            return self.responses[command]
        return {"status": "ok", "target": target, "params": dict(params)}


class FakeTargetService:
    def __init__(self) -> None:
        self.targets: list[dict[str, Any]] = []
        self.created: list[tuple[str, str, dict[str, Any]]] = []

    def list_targets(self):
        return list(self.targets)

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        self.created.append(
            (
                name,
                project_location,
                {
                    "project_name": project_name,
                    "domain_path": domain_path,
                },
            )
        )
        self.targets.append(
            {
                "target": name,
                "project_location": project_location,
                "project_name": project_name,
                "domain_path": domain_path,
            }
        )
        return {
            "target": name,
            "project_location": project_location,
            "project_name": project_name,
            "domain_path": domain_path,
        }


class FakeJavaBackend:
    def get_database_status(self, bsim_url: str):
        return {
            "status": "ok",
            "raw_url": bsim_url,
            "executable_count": 7,
            "postgresql_version": "15.13",
            "database_type": "postgres",
        }

    def get_ghidra_version(self):
        return "12.1"

    def list_categories(self, bsim_url: str):
        return {"items": [], "raw_url": bsim_url}

    def list_executables(self, bsim_url: str, **kwargs):
        return {"items": [], "raw_url": bsim_url, "filters": dict(kwargs)}

    def get_executable(self, bsim_url: str, **kwargs):
        return {"raw_url": bsim_url, "lookup": dict(kwargs)}


def _service(
    *,
    bsim_url: str = "postgresql://user:secret@localhost/bsim",
    bsim_password: str | None = None,
    bsim_password_env: str | None = None,
    ghidra_install_dir: str | None = None,
    target_service: FakeTargetService | None = None,
) -> tuple[BsimService, FakeCoreCommandService, FakeTargetService]:
    core = FakeCoreCommandService()
    target = target_service or FakeTargetService()
    service = BsimService(
        core_command_service=core,
        target_service=target,  # type: ignore[arg-type]
        config=BsimConfig(
            bsim_url=bsim_url,
            bsim_password=bsim_password,
            bsim_password_env=bsim_password_env,
            ghidra_install_dir=ghidra_install_dir,
        ),
        java_backend=FakeJavaBackend(),  # type: ignore[arg-type]
    )
    return service, core, target


def test_bsim_query_function_uses_configured_url_and_masks_response():
    service, core, _target = _service()

    result = service.query_function("fw", address="0x401000", max_results=3)

    assert result["bsim_url"] == "postgresql://***:***@localhost/bsim"
    assert result["query"] == {
        "scope": "function",
        "target": "fw",
        "program": None,
        "bsim_url": "postgresql://***:***@localhost/bsim",
        "similarity_threshold": 0.7,
        "significance_threshold": 0.0,
        "matches_per_function": 10,
        "max_results": 3,
        "address": "0x401000",
    }
    assert core.calls == [
        (
            "bsim_query_function",
            {
                "bsim_url": "postgresql://user:secret@localhost/bsim",
                "query_target": "fw",
                "address": "0x401000",
                "function_name": None,
                "similarity_threshold": 0.7,
                "significance_threshold": 0.0,
                "matches_per_function": 10,
                "max_results": 3,
            },
            "fw",
        )
    ]


def test_bsim_password_is_added_to_configured_url_and_masked():
    service, core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password="secret",
    )

    result = service.query_function("fw", address="0x401000", max_results=3)

    assert result["bsim_url"] == "postgresql://***:***@localhost/bsim"
    assert core.calls[0][1]["bsim_url"] == "postgresql://user:secret@localhost/bsim"


def test_bsim_password_env_is_added_to_configured_url(monkeypatch):
    monkeypatch.setenv("BSIM_TEST_PASSWORD", "secret")
    service, core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password_env="BSIM_TEST_PASSWORD",
    )

    service.query_function("fw", address="0x401000")

    assert core.calls[0][1]["bsim_url"] == "postgresql://user:secret@localhost/bsim"


def test_bsim_password_infers_os_user_when_url_has_no_username(monkeypatch):
    monkeypatch.setattr("ghidra_mcp.application.services.bsim_service.getpass.getuser", lambda: "localuser")
    service, core, _target = _service(
        bsim_url="postgresql://localhost/bsim",
        bsim_password="secret",
    )

    service.query_function("fw", address="0x401000")

    assert core.calls[0][1]["bsim_url"] == "postgresql://localuser:secret@localhost/bsim"


def test_bsim_password_options_are_mutually_exclusive():
    service, _core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password="secret",
        bsim_password_env="BSIM_TEST_PASSWORD",
    )

    with pytest.raises(ValueError, match="cannot be used together"):
        service.query_function("fw", address="0x401000")


def test_bsim_password_env_requires_set_value(monkeypatch):
    monkeypatch.delenv("BSIM_TEST_PASSWORD", raising=False)
    service, _core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password_env="BSIM_TEST_PASSWORD",
    )

    with pytest.raises(ValueError, match="BSIM_TEST_PASSWORD"):
        service.query_function("fw", address="0x401000")


def test_bsim_database_status_includes_client_and_backend_observability():
    service, _core, _target = _service(ghidra_install_dir="/opt/ghidra")

    result = service.get_database_status()

    assert result["bsim_url"] == "postgresql://***:***@localhost/bsim"
    assert result["executable_count"] == 7
    assert result["database_type"] == "postgres"
    assert result["postgresql_version"] == "15.13"
    assert result["ghidra_install_dir"] == "/opt/ghidra"
    assert result["ghidra_version"] == "12.1"


def test_bsim_url_scheme_is_validated():
    service, _core, _target = _service(bsim_url="ftp://localhost/bsim")

    with pytest.raises(ValueError, match="BSIM_URL_INVALID"):
        service.get_database_status()


def test_bsim_postgresql_url_requires_database_name():
    service, _core, _target = _service(bsim_url="postgresql://localhost")

    with pytest.raises(ValueError, match="database name"):
        service.get_database_status()


def test_bsim_elastic_url_scheme_is_accepted():
    service, _core, _target = _service(bsim_url="elastic://user:secret@localhost/bsim")

    result = service.get_database_status()

    assert result["bsim_url"] == "elastic://***:***@localhost/bsim"


def test_bsim_http_url_scheme_is_rejected():
    service, _core, _target = _service(bsim_url="http://localhost/bsim")

    with pytest.raises(ValueError, match="unsupported BSim URL scheme"):
        service.get_database_status()


def test_bsim_elastic_url_requires_database_name():
    service, _core, _target = _service(bsim_url="elastic://localhost")

    with pytest.raises(ValueError, match="database name"):
        service.get_database_status()


def test_bsim_network_url_rejects_extra_path_segments():
    service, _core, _target = _service(bsim_url="https://localhost/bsim/extra")

    with pytest.raises(ValueError, match="one path element"):
        service.get_database_status()


def test_bsim_file_url_requires_absolute_path():
    service, _core, _target = _service(bsim_url="file:relative_bsim")

    with pytest.raises(ValueError, match="absolute database path"):
        service.get_database_status()


def test_bsim_query_parameters_are_validated_before_core_call():
    service, core, _target = _service()

    with pytest.raises(ValueError, match="similarity_threshold"):
        service.query_function("fw", address="0x401000", similarity_threshold=1.1)
    with pytest.raises(ValueError, match="significance_threshold"):
        service.query_function("fw", address="0x401000", significance_threshold=-0.1)
    with pytest.raises(ValueError, match="matches_per_function"):
        service.query_function("fw", address="0x401000", matches_per_function=0)
    with pytest.raises(ValueError, match="max_results"):
        service.query_function("fw", address="0x401000", max_results=0)
    assert core.calls == []


def test_bsim_list_executables_limit_is_validated_before_backend_call():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="limit"):
        service.list_executables(limit=0)


def test_bsim_load_matched_executable_reuses_existing_loaded_target():
    target = FakeTargetService()
    target.targets.append(
        {
            "target": "bsim_deadbeefcafe",
            "project_location": "/tmp/history.gpr",
            "project_name": None,
            "domain_path": "/samples/old.exe",
        }
    )
    service, _core, target = _service(target_service=target)

    result = service.load_matched_executable(
        matched_ref={
            "matched_ref_version": 1,
            "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
            "executable_name": "old.exe",
            "project_location": "/tmp/history.gpr",
            "domain_path": "/samples/old.exe",
            "address": "0x401000",
            "name": "entry",
        }
    )

    assert result == {
        "status": "already_loaded",
        "target": "bsim_deadbeefcafe",
        "program": "/samples/old.exe",
        "matched_function_address": "0x401000",
        "matched_function_name": "entry",
        "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
        "matched_ref_version": 1,
    }
    assert target.created == []


def test_bsim_load_matched_executable_does_not_reuse_same_domain_from_different_project():
    class StrictTargetService(FakeTargetService):
        def create_session(
            self,
            name: str,
            project_location: str,
            *,
            project_name: str | None = None,
            domain_path: str | None = None,
        ):
            if any(item.get("target") == name for item in self.targets):
                raise ValueError(f"Session '{name}' already exists")
            return super().create_session(
                name,
                project_location,
                project_name=project_name,
                domain_path=domain_path,
            )

    target = StrictTargetService()
    target.targets.append(
        {
            "target": "collision",
            "project_location": "/tmp/other.gpr",
            "project_name": None,
            "domain_path": "/samples/old.exe",
        }
    )
    service, _core, target = _service(target_service=target)

    with pytest.raises(ValueError, match="already exists"):
        service.load_matched_executable(
            matched_ref={
                "matched_ref_version": 1,
                "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
                "executable_name": "old.exe",
                "project_location": "/tmp/history.gpr",
                "domain_path": "/samples/old.exe",
                "address": "0x401000",
                "name": "entry",
            },
            target="collision",
        )

    assert target.created == []


def test_bsim_load_matched_executable_creates_once_then_reuses_index():
    service, _core, target = _service()
    matched_ref = {
        "matched_ref_version": 1,
        "executable_md5": "0123456789abcdef0123456789abcdef",
        "executable_name": "old.exe",
        "project_location": "/tmp/history.gpr",
        "domain_path": "/samples/old.exe",
        "address": "0x402000",
        "name": "match_func",
    }

    first = service.load_matched_executable(matched_ref=matched_ref, target="past_sample")
    second = service.load_matched_executable(matched_ref=matched_ref, target="different_request")

    assert first["status"] == "loaded"
    assert first["target"] == "past_sample"
    assert second["status"] == "already_loaded"
    assert second["target"] == "past_sample"
    assert target.created == [
        (
            "past_sample",
            "/tmp/history.gpr",
            {"project_name": None, "domain_path": "/samples/old.exe"},
        )
    ]


def test_bsim_query_target_adds_query_provenance():
    service, core, _target = _service()
    core.responses["bsim_query_target"] = {
        "target": "fw",
        "program": "/query",
        "matches": [],
        "count": 0,
        "truncated": False,
    }

    result = service.query_target(
        "fw",
        similarity_threshold=0.9,
        significance_threshold=2.5,
        matches_per_function=4,
        max_results=12,
    )

    assert result["query"] == {
        "scope": "target",
        "target": "fw",
        "program": "/query",
        "bsim_url": "postgresql://***:***@localhost/bsim",
        "similarity_threshold": 0.9,
        "significance_threshold": 2.5,
        "matches_per_function": 4,
        "max_results": 12,
    }


def test_bsim_load_matched_executable_requires_versioned_ref():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="BSIM_INVALID_MATCHED_REF"):
        service.load_matched_executable(
            matched_ref={
                "executable_md5": "0123456789abcdef0123456789abcdef",
                "executable_name": "old.exe",
                "project_location": "/tmp/history.gpr",
                "domain_path": "/samples/old.exe",
                "address": "0x402000",
                "name": "match_func",
            }
        )


def test_bsim_load_matched_executable_reports_missing_ref_keys():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="missing required keys: executable_name, domain_path, address, name"):
        service.load_matched_executable(
            matched_ref={
                "matched_ref_version": 1,
                "executable_md5": "0123456789abcdef0123456789abcdef",
                "project_location": "/tmp/history.gpr",
            }
        )


def test_bsim_query_function_classifies_function_lookup_errors():
    service, core, _target = _service()
    core.errors["bsim_query_function"] = LookupError("Function not found: missing_func")

    with pytest.raises(LookupError, match="BSIM_FUNCTION_NOT_FOUND"):
        service.query_function("fw", function_name="missing_func")


def test_bsim_database_status_classifies_authentication_errors():
    class AuthFailBackend(FakeJavaBackend):
        def get_database_status(self, bsim_url: str):
            raise RuntimeError("password authentication failed for user")

    core = FakeCoreCommandService()
    target = FakeTargetService()
    service = BsimService(
        core_command_service=core,
        target_service=target,  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://user:secret@localhost/bsim"),
        java_backend=AuthFailBackend(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="BSIM_AUTHENTICATION_FAILED"):
        service.get_database_status()


def test_bsim_url_required_has_error_code():
    service, _core, _target = _service(bsim_url="")

    with pytest.raises(ValueError, match="BSIM_URL_REQUIRED"):
        service.get_database_status()
