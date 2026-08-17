from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from ghidra_mcp.application.services.bsim_service import BsimConfig, BsimService
from ghidra_mcp.domain import DomainError, ErrorCode


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
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.errors: dict[str, Exception] = {}

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

    def add_executable_category(self, bsim_url: str, **kwargs):
        self.calls.append(("add_executable_category", bsim_url, dict(kwargs)))
        if "add_executable_category" in self.errors:
            raise self.errors["add_executable_category"]
        return {
            "status": "created",
            "category": kwargs["category"],
            "items": [kwargs["category"]],
        }

    def list_executables(self, bsim_url: str, **kwargs):
        return {"items": [], "raw_url": bsim_url, "filters": dict(kwargs)}

    def get_executable(self, bsim_url: str, **kwargs):
        return {"raw_url": bsim_url, "lookup": dict(kwargs)}

    def update_executable_metadata(self, bsim_url: str, **kwargs):
        self.calls.append(("update_executable_metadata", bsim_url, dict(kwargs)))
        if "update_executable_metadata" in self.errors:
            raise self.errors["update_executable_metadata"]
        return {
            "status": "updated",
            "categories": dict(kwargs["categories"]),
            "updated_executables": 1,
        }


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
    java_backend = FakeJavaBackend()
    service = BsimService(
        core_command_service=core,
        target_service=target,  # type: ignore[arg-type]
        config=BsimConfig(
            bsim_url=bsim_url,
            bsim_password=bsim_password,
            bsim_password_env=bsim_password_env,
            ghidra_install_dir=ghidra_install_dir,
        ),
        java_backend=java_backend,  # type: ignore[arg-type]
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


def test_bsim_success_payload_masks_all_url_credentials():
    service, _core, _target = _service(
        bsim_url=(
            "postgresql://localhost/bsim?user=alice&password=topsecret&token=opaque&mode=ro"
        )
    )

    result = service.get_database_status()

    expected = "postgresql://localhost/bsim?user=***&password=***&token=***&mode=***"
    assert result["bsim_url"] == expected
    assert result["raw_url"] == expected
    assert "alice" not in str(result)
    assert "topsecret" not in str(result)
    assert "opaque" not in str(result)


def test_bsim_backend_exception_masks_url_credentials_and_raw_cause():
    class CredentialFailBackend(FakeJavaBackend):
        def get_database_status(self, bsim_url: str):
            raise RuntimeError(
                "connection failed for "
                "postgresql://alice:topsecret@host:99999/db?password=second&token=opaque"
            )

    service = BsimService(
        core_command_service=FakeCoreCommandService(),
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://localhost/bsim"),
        java_backend=CredentialFailBackend(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError) as raised:
        service.get_database_status()

    message = str(raised.value)
    assert "postgresql://***:***@host:99999/db?password=***&token=***" in message
    assert "alice" not in message
    assert "topsecret" not in message
    assert "second" not in message
    assert "opaque" not in message
    assert raised.value.__suppress_context__ is True
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None


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


def test_bsim_add_executable_category_uses_configured_url_and_masks_response():
    service, _core, _target = _service()

    result = service.bsim_add_executable_category(category="FAMILY")

    backend = service._java_backend  # type: ignore[attr-defined]
    assert result["bsim_url"] == "postgresql://***:***@localhost/bsim"
    assert result["category"] == "FAMILY"
    assert backend.calls == [
        (
            "add_executable_category",
            "postgresql://user:secret@localhost/bsim",
            {"category": "FAMILY"},
        )
    ]


def test_bsim_add_executable_category_rejects_invalid_category_name():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="BSIM_EXECUTABLE_CATEGORY_INVALID"):
        service.bsim_add_executable_category(category="bad$category")


def test_bsim_update_executable_metadata_normalizes_categories_and_masks_response():
    service, _core, _target = _service()

    result = service.bsim_update_executable_metadata(
        md5="0123456789abcdef0123456789abcdef",
        categories={
            "FAMILY": "Emotet",
            "ACTOR": ["TA542", "TA542", ""],
            "SOURCE": None,
        },
    )

    backend = service._java_backend  # type: ignore[attr-defined]
    assert result["bsim_url"] == "postgresql://***:***@localhost/bsim"
    assert result["categories"] == {
        "FAMILY": ["Emotet"],
        "ACTOR": ["TA542"],
        "SOURCE": [],
    }
    assert backend.calls == [
        (
            "update_executable_metadata",
            "postgresql://user:secret@localhost/bsim",
            {
                "categories": {
                    "FAMILY": ["Emotet"],
                    "ACTOR": ["TA542"],
                    "SOURCE": [],
                },
                "md5": "0123456789abcdef0123456789abcdef",
                "name": None,
            },
        )
    ]


def test_bsim_update_executable_metadata_requires_lookup_key():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="BSIM_EXECUTABLE_LOOKUP_REQUIRED"):
        service.bsim_update_executable_metadata(categories={"FAMILY": "Emotet"})


def test_bsim_update_executable_metadata_rejects_partial_md5():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="BSIM_EXECUTABLE_LOOKUP_INVALID"):
        service.bsim_update_executable_metadata(
            md5="01234567",
            categories={"FAMILY": "Emotet"},
        )


def test_bsim_update_executable_metadata_requires_non_empty_categories():
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="categories must be a non-empty object"):
        service.bsim_update_executable_metadata(
            md5="0123456789abcdef0123456789abcdef",
            categories={},
        )


def test_bsim_update_executable_metadata_classifies_not_found_errors():
    service, _core, _target = _service()
    backend = service._java_backend  # type: ignore[attr-defined]
    backend.errors["update_executable_metadata"] = LookupError("BSIM_EXECUTABLE_NOT_FOUND")

    with pytest.raises(LookupError, match="BSIM_EXECUTABLE_NOT_FOUND"):
        service.bsim_update_executable_metadata(
            md5="0123456789abcdef0123456789abcdef",
            categories={"FAMILY": "Emotet"},
        )


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
    assert service._matched_load_locks.active_count == 0  # noqa: SLF001


def test_bsim_load_matched_executable_serializes_concurrent_check_and_create():
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
    start = threading.Barrier(2)

    def load():
        start.wait(timeout=1)
        return service.load_matched_executable(
            matched_ref=matched_ref,
            target="past_sample",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: load(), range(2)))

    assert sorted(result["status"] for result in results) == [
        "already_loaded",
        "loaded",
    ]
    assert {result["target"] for result in results} == {"past_sample"}
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


def test_bsim_query_function_classifies_runtime_wrapped_lookup_errors():
    # Production wiring never delivers raw headless exceptions here:
    # RuntimeBackend._invoke pre-wraps them as DomainError(OPERATION_FAILED,
    # message=<original headless message>). Classification must still fire.
    service, core, _target = _service()
    core.errors["bsim_query_function"] = DomainError(
        code=ErrorCode.OPERATION_FAILED,
        message="Function not found: missing_func",
    )

    with pytest.raises(LookupError, match="BSIM_FUNCTION_NOT_FOUND"):
        service.query_function("fw", function_name="missing_func")


def test_bsim_register_classifies_runtime_wrapped_connection_errors():
    service, core, _target = _service()
    core.errors["bsim_register_target"] = DomainError(
        code=ErrorCode.OPERATION_FAILED,
        message="BSIM_DATABASE_INIT_FAILED: Connection to localhost:5432 refused",
    )

    with pytest.raises(RuntimeError, match="BSIM_DATABASE_UNREACHABLE"):
        service.register_target("fw")


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


def test_bsim_configured_password_not_injected_into_foreign_per_call_url():
    service, core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password="secret",
    )

    service.query_function(
        "fw",
        bsim_url="postgresql://user@evil.example.com/other",
        address="0x401000",
    )

    # The server password belongs to --bsim-url only; it must not be forwarded to a
    # different host supplied per call.
    assert core.calls[0][1]["bsim_url"] == "postgresql://user@evil.example.com/other"


def test_bsim_per_call_file_url_allowed_when_password_configured():
    service, core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password="secret",
    )

    result = service.list_executables(bsim_url="file:/tmp/local_bsim")

    assert result["bsim_url"] == "file:/tmp/local_bsim"
    assert core.calls == []  # list_executables uses the java backend, not a core command


def test_bsim_per_call_url_keeps_its_own_password():
    service, core, _target = _service(
        bsim_url="postgresql://user@localhost/bsim",
        bsim_password="secret",
    )

    service.query_function(
        "fw",
        bsim_url="postgresql://u2:own@other-host/db2",
        address="0x401000",
    )

    assert core.calls[0][1]["bsim_url"] == "postgresql://u2:own@other-host/db2"


def test_bsim_invalid_port_raises_coded_url_error():
    service, _core, _target = _service(bsim_url="postgresql://user@localhost:5432a/bsim")

    with pytest.raises(ValueError, match="BSIM_URL_INVALID"):
        service.get_database_status()


def test_bsim_unparseable_url_raises_fixed_error_without_credentials():
    service, _core, _target = _service(
        bsim_url="postgresql://alice:topsecret@host／evil/db?password=second"
    )

    with pytest.raises(ValueError) as raised:
        service.get_database_status()

    assert str(raised.value) == "BSIM_URL_INVALID: unable to parse BSim URL"
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None


def test_bsim_status_reclassifies_prefixed_authentication_error():
    class AuthFailBackend(FakeJavaBackend):
        def get_database_status(self, bsim_url: str):
            raise RuntimeError(
                "BSIM_DATABASE_INIT_FAILED: FATAL: password authentication failed for user \"x\""
            )

    core = FakeCoreCommandService()
    service = BsimService(
        core_command_service=core,
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://user:secret@localhost/bsim"),
        java_backend=AuthFailBackend(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="BSIM_AUTHENTICATION_FAILED"):
        service.get_database_status()


def test_bsim_status_reclassifies_prefixed_unreachable_error():
    class UnreachableBackend(FakeJavaBackend):
        def get_database_status(self, bsim_url: str):
            raise RuntimeError("BSIM_DATABASE_INIT_FAILED: Connection to localhost:5432 refused")

    core = FakeCoreCommandService()
    service = BsimService(
        core_command_service=core,
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://user:secret@localhost/bsim"),
        java_backend=UnreachableBackend(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="BSIM_DATABASE_UNREACHABLE"):
        service.get_database_status()


def test_bsim_query_preserves_structured_domain_error():
    service, core, _target = _service()
    core.errors["bsim_query_target"] = DomainError(
        code=ErrorCode.SESSION_NOT_FOUND,
        message="Session 'fw' is not initialized",
    )

    with pytest.raises(DomainError) as excinfo:
        service.query_target("fw")

    assert excinfo.value.code is ErrorCode.SESSION_NOT_FOUND


def test_bsim_query_masks_credentials_in_structured_domain_error():
    service, core, _target = _service()
    raw_url = "postgresql://alice:topsecret@host/db?token=opaque"
    core.errors["bsim_query_target"] = DomainError(
        code=ErrorCode.SESSION_NOT_FOUND,
        message=f"Session failed while using {raw_url}",
        hint=f"Retry without {raw_url}",
        retryable=True,
        details={"connection": raw_url},
    )

    with pytest.raises(DomainError) as excinfo:
        service.query_target("fw")

    error = excinfo.value
    rendered = f"{error} {error.hint} {error.details}"
    assert error.code is ErrorCode.SESSION_NOT_FOUND
    assert error.retryable is True
    assert "postgresql://***:***@host/db?token=***" in rendered
    assert "alice" not in rendered
    assert "topsecret" not in rendered
    assert "opaque" not in rendered
    assert error.__context__ is None
    assert error.__cause__ is None


@pytest.mark.parametrize("version", [1, "1", 1.0, "1.0"])
def test_bsim_load_matched_executable_accepts_integral_version(version):
    service, _core, _target = _service()

    result = service.load_matched_executable(
        matched_ref={
            "matched_ref_version": version,
            "executable_md5": "0123456789abcdef0123456789abcdef",
            "executable_name": "old.exe",
            "project_location": "/tmp/history.gpr",
            "domain_path": "/samples/old.exe",
            "address": "0x402000",
            "name": "match_func",
        }
    )

    assert result["status"] == "loaded"


@pytest.mark.parametrize("version", [1.5, "1.5", "abc", None, True])
def test_bsim_load_matched_executable_rejects_non_version_one(version):
    service, _core, _target = _service()

    with pytest.raises(ValueError, match="BSIM_INVALID_MATCHED_REF"):
        service.load_matched_executable(
            matched_ref={
                "matched_ref_version": version,
                "executable_md5": "0123456789abcdef0123456789abcdef",
                "executable_name": "old.exe",
                "project_location": "/tmp/history.gpr",
                "domain_path": "/samples/old.exe",
                "address": "0x402000",
                "name": "match_func",
            }
        )


class _CategoriesBackend(FakeJavaBackend):
    def __init__(self, items: list[str]) -> None:
        super().__init__()
        self._items = items

    def list_categories(self, bsim_url: str):
        return {"items": list(self._items)}


def test_bsim_set_target_metadata_rejects_unconfigured_category():
    core = FakeCoreCommandService()
    service = BsimService(
        core_command_service=core,
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://user:secret@localhost/bsim"),
        java_backend=_CategoriesBackend(["FAMILY", "SOURCE"]),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED"):
        service.bsim_set_target_metadata("fw", categories={"Famly": "Emotet"})
    assert core.calls == []


def test_bsim_set_target_metadata_allows_configured_category():
    core = FakeCoreCommandService()
    service = BsimService(
        core_command_service=core,
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url="postgresql://user:secret@localhost/bsim"),
        java_backend=_CategoriesBackend(["FAMILY", "SOURCE"]),  # type: ignore[arg-type]
    )

    result = service.bsim_set_target_metadata("fw", categories={"FAMILY": "Emotet"})

    assert result["status"] == "ok"
    assert core.calls == [("bsim_set_target_metadata", {"categories": {"FAMILY": "Emotet"}}, "fw")]


def test_bsim_set_target_metadata_skips_validation_without_url():
    core = FakeCoreCommandService()
    service = BsimService(
        core_command_service=core,
        target_service=FakeTargetService(),  # type: ignore[arg-type]
        config=BsimConfig(bsim_url=""),
        java_backend=FakeJavaBackend(),  # type: ignore[arg-type]
    )

    result = service.bsim_set_target_metadata("fw", categories={"AnyKey": "value"})

    assert result["status"] == "ok"
    assert core.calls == [("bsim_set_target_metadata", {"categories": {"AnyKey": "value"}}, "fw")]


def test_bsim_load_matched_executable_reuses_loaded_remote_ref_target():
    target = FakeTargetService()
    target.targets.append(
        {
            "target": "manual_session",
            "project_location": None,
            "project_name": None,
            "domain_path": "/samples/remote.exe",
        }
    )
    service, _core, target = _service(target_service=target)

    # A matched_ref from a server-ingested corpus carries only a remote ghidra:// URL,
    # so project identity cannot be computed. After the user manually loads the program,
    # a retry must reuse the loaded target instead of failing again.
    result = service.load_matched_executable(
        matched_ref={
            "matched_ref_version": 1,
            "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
            "executable_name": "remote.exe",
            "repository": "ghidra://server/repo",
            "domain_path": "/samples/remote.exe",
            "address": "0x401000",
            "name": "entry",
        },
        target="manual_session",
    )

    assert result["status"] == "already_loaded"
    assert result["target"] == "manual_session"
    assert target.created == []


def test_bsim_load_remote_ref_does_not_reuse_unrelated_same_domain_target():
    target = FakeTargetService()
    target.targets.append(
        {
            "target": "unrelated_session",
            "project_location": "/tmp/unrelated.gpr",
            "project_name": None,
            "domain_path": "/samples/remote.exe",
        }
    )
    service, _core, target = _service(target_service=target)

    with pytest.raises(ValueError, match="BSIM_REMOTE_PROJECT_LOAD_UNSUPPORTED"):
        service.load_matched_executable(
            matched_ref={
                "matched_ref_version": 1,
                "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
                "executable_name": "remote.exe",
                "repository": "ghidra://server/repo",
                "domain_path": "/samples/remote.exe",
                "address": "0x401000",
                "name": "entry",
            }
        )

    assert target.created == []


def test_bsim_load_invalid_non_remote_ref_does_not_use_manual_domain_fallback():
    target = FakeTargetService()
    target.targets.append(
        {
            "target": "manual_session",
            "project_location": None,
            "project_name": None,
            "domain_path": "/samples/remote.exe",
        }
    )
    service, _core, target = _service(target_service=target)

    with pytest.raises(ValueError, match="BSIM_INVALID_MATCHED_REF: unsupported"):
        service.load_matched_executable(
            matched_ref={
                "matched_ref_version": 1,
                "executable_md5": "deadbeefcafebabedeadbeefcafebabe",
                "executable_name": "remote.exe",
                "repository": "https://server/repo",
                "domain_path": "/samples/remote.exe",
                "address": "0x401000",
                "name": "entry",
            },
            target="manual_session",
        )

    assert target.created == []
