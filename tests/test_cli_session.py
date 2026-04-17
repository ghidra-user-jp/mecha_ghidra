from __future__ import annotations

import types

import pytest

from ghidra_mcp import cli
from ghidra_mcp.contracts.tool_spec import get_all_tool_specs


class FakeCoreCommandService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object], str]] = []

    def call(self, command: str, params: dict[str, object], target: str):
        self.calls.append((command, dict(params), target))
        return {"path": "core", "command": command, "target": target}


class FakeTargetService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.closed = False

    def list_targets(self):
        self.calls.append(("list_targets", (), {}))
        return [{"target": "fw"}]

    def list_programs(self, target: str):
        self.calls.append(("list_programs", (target,), {}))
        return ["/main"]

    def register_target(self, target: str, project_location: str, *, project_name: str | None = None):
        self.calls.append(
            (
                "register_target",
                (target, project_location),
                {"project_name": project_name},
            )
        )
        return {"status": "ok", "target": target}

    def load_program(self, target: str, domain_path: str):
        self.calls.append(("load_program", (target, domain_path), {}))
        return domain_path

    def import_program(self, target: str, binary_path: str, **kwargs):
        self.calls.append(("import_program", (target, binary_path), dict(kwargs)))
        return binary_path

    def create_session(
        self,
        target: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "create_session",
                (target, project_location),
                {
                    "project_name": project_name,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok", "target": target}

    def close_session(self, target: str, *, remove_program: bool = False):
        self.calls.append(("close_session", (target,), {"remove_program": remove_program}))
        return {"status": "ok", "target": target}

    def has_targets(self) -> bool:
        return True

    def close_all(self) -> None:
        self.closed = True


class FakeSyncService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def get_project_sync_status(self, target: str, *, domain_path: str | None = None):
        self.calls.append(("get_project_sync_status", (target,), {"domain_path": domain_path}))
        return {"status": "ok"}

    def checkout_project_program(self, target: str, *, exclusive: bool = False, domain_path: str | None = None):
        self.calls.append(
            (
                "checkout_project_program",
                (target,),
                {"exclusive": exclusive, "domain_path": domain_path},
            )
        )
        return {"status": "ok"}

    def add_project_program_to_version_control(
        self,
        target: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "add_project_program_to_version_control",
                (target, comment),
                {
                    "keep_checked_out": keep_checked_out,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok"}

    def commit_project_program(
        self,
        target: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "commit_project_program",
                (target, message),
                {
                    "keep_checked_out": keep_checked_out,
                    "auto_checkout": auto_checkout,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok"}

    def pull_project_program(self, target: str, *, on_local_changes: str = "abort", domain_path: str | None = None):
        self.calls.append(
            (
                "pull_project_program",
                (target,),
                {"on_local_changes": on_local_changes, "domain_path": domain_path},
            )
        )
        return {"status": "ok"}

    def undo_checkout_project_program(
        self,
        target: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "undo_checkout_project_program",
                (target,),
                {
                    "discard_local_changes": discard_local_changes,
                    "domain_path": domain_path,
                },
            )
        )
        return {"status": "ok"}

    def terminate_project_program_checkout(
        self,
        target: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "terminate_project_program_checkout",
                (target,),
                {"checkout_id": checkout_id, "domain_path": domain_path},
            )
        )
        return {"status": "ok"}

    def reload_project_program(self, target: str, *, domain_path: str | None = None):
        self.calls.append(("reload_project_program", (target,), {"domain_path": domain_path}))
        return {"status": "ok"}

    def get_version_history(self, target: str, *, limit: int = 50, domain_path: str | None = None):
        self.calls.append(("get_version_history", (target,), {"limit": limit, "domain_path": domain_path}))
        return {"versions": []}

    def get_version_diff(
        self,
        target: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "get_version_diff",
                (target,),
                {
                    "from_version": from_version,
                    "to_version": to_version,
                    "range_limit": range_limit,
                    "domain_path": domain_path,
                },
            )
        )
        return {"diffs": []}


@pytest.fixture
def adapter() -> tuple[cli.ServiceRegistryAdapter, FakeCoreCommandService, FakeTargetService, FakeSyncService]:
    core = FakeCoreCommandService()
    target = FakeTargetService()
    sync = FakeSyncService()
    return (
        cli.ServiceRegistryAdapter(
            core_command_service=core,
            target_service=target,
            sync_service=sync,
        ),
        core,
        target,
        sync,
    )


def test_parse_session_definition_minimal():
    cfg = cli._parse_session_definition("name=fw,project_location=/tmp/sample.gpr,domain_path=/folder/fw.bin")
    assert cfg == {
        "name": "fw",
        "project_location": "/tmp/sample.gpr",
        "domain_path": "/folder/fw.bin",
    }


@pytest.mark.parametrize(
    "text",
    [
        "name=fw,domain_path=/folder/fw.bin",
        "project_location=/tmp/sample.gpr",
        "name=fw,project_location=/tmp/sample.gpr,broken",
    ],
)
def test_parse_session_definition_invalid(text):
    with pytest.raises(ValueError):
        cli._parse_session_definition(text)


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (
            lambda a: a.call("list_functions", {"offset": 1, "limit": 2}, "fw"),
            {"path": "core", "command": "list_functions", "target": "fw"},
        ),
        (
            lambda a: a.list_targets(),
            [{"target": "fw"}],
        ),
        (
            lambda a: a.list_programs("fw"),
            ["/main"],
        ),
        (
            lambda a: a.register_target("fw", project_location="/tmp/p.gpr", project_name=None),
            {"status": "ok", "target": "fw"},
        ),
        (
            lambda a: a.load_program("fw", "/app"),
            "/app",
        ),
        (
            lambda a: a.import_program(
                "fw",
                "/tmp/a.exe",
                import_mode="raw_binary",
                language_id="x86:LE:32:default",
                entry_offset=0,
            ),
            "/tmp/a.exe",
        ),
        (
            lambda a: a.create_session("fw", "/tmp/p.gpr", project_name="p", domain_path="/app"),
            {"status": "ok", "target": "fw"},
        ),
        (
            lambda a: a.close_session("fw"),
            {"status": "ok", "target": "fw"},
        ),
        (
            lambda a: a.close_session("fw", remove_program=True),
            {"status": "ok", "target": "fw"},
        ),
        (
            lambda a: a.get_project_sync_status("fw", domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.checkout_project_program("fw", exclusive=True, domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.add_project_program_to_version_control(
                "fw",
                comment="init",
                keep_checked_out=True,
                domain_path="/app",
            ),
            {"status": "ok"},
        ),
        (
            lambda a: a.commit_project_program(
                "fw",
                message="msg",
                keep_checked_out=False,
                auto_checkout=False,
                domain_path="/app",
            ),
            {"status": "ok"},
        ),
        (
            lambda a: a.pull_project_program("fw", on_local_changes="discard", domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.undo_checkout_project_program("fw", discard_local_changes=False, domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.terminate_project_program_checkout("fw", checkout_id=7, domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.reload_project_program("fw", domain_path="/app"),
            {"status": "ok"},
        ),
        (
            lambda a: a.get_version_history("fw", limit=5, domain_path="/app"),
            {"versions": []},
        ),
        (
            lambda a: a.get_version_diff("fw", from_version=1, to_version=2, range_limit=30, domain_path="/app"),
            {"diffs": []},
        ),
    ],
)
def test_service_registry_adapter_routes_calls(adapter, call, expected):
    registry, _core, _target, _sync = adapter
    assert call(registry) == expected


def test_service_registry_adapter_requires_domain_path_for_create_session(adapter):
    registry, _core, _target, _sync = adapter
    with pytest.raises(ValueError, match="domain_path is required"):
        registry.create_session("fw", "/tmp/p.gpr", project_name="p")


def test_service_registry_adapter_has_targets_and_close_all(adapter):
    registry, _core, target, _sync = adapter
    assert registry.has_targets() is True
    registry.close_all()
    assert target.closed is True


@pytest.mark.parametrize(
    ("call", "expected_spec", "expected_args"),
    [
        (
            lambda: cli.list_methods(offset=1, limit=2, target="fw"),
            "list_methods",
            {"offset": 1, "limit": 2},
        ),
        (
            lambda: cli.list_classes(offset=3, limit=4, target="fw"),
            "list_classes",
            {"offset": 3, "limit": 4},
        ),
    ],
)
def test_list_methods_and_list_classes_use_dispatcher(monkeypatch, call, expected_spec, expected_args):
    called: dict[str, object] = {}

    def fake_dispatch(spec_name, raw_args, target, *, registry, core_executor=None):
        called["spec_name"] = spec_name
        called["raw_args"] = dict(raw_args)
        called["target"] = target
        called["registry"] = registry
        called["core_executor"] = core_executor
        return {"status": "ok"}

    monkeypatch.setattr(cli, "dispatch_tool", fake_dispatch)

    assert call() == {"status": "ok"}
    assert called["spec_name"] == expected_spec
    assert called["raw_args"] == expected_args
    assert called["target"] == "fw"
    assert called["registry"] is cli._registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (
            lambda: cli.list_methods(offset=0, limit=10, target="fw"),
            "Session 'fw' is not initialized",
        ),
        (
            lambda: cli.list_classes(offset=0, limit=10, target="fw"),
            "Session 'fw' is not initialized",
        ),
    ],
)
def test_list_methods_and_list_classes_error_message_compat(monkeypatch, call, message):
    class DummyRegistry:
        def call(self, command, params, target):  # noqa: ARG002
            raise RuntimeError(f"Session '{target}' is not initialized")

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    with pytest.raises(RuntimeError, match=message):
        call()


def test_register_shared_project_sync_tools_is_idempotent(monkeypatch):
    calls: list[str] = []
    fake_runtime = types.SimpleNamespace(register_shared_sync=lambda: calls.append("register"))

    monkeypatch.setattr(cli, "_runtime", fake_runtime)
    monkeypatch.setattr(cli, "_shared_project_sync_tools_registered", False)

    cli.register_shared_project_sync_tools()
    cli.register_shared_project_sync_tools()

    assert calls == ["register"]


def test_parse_args_accepts_http():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--transport",
            "http",
            "--mcp-host",
            "0.0.0.0",
            "--mcp-port",
            "9090",
            "--mcp-path",
            "/mcp",
        ]
    )

    assert args.transport == "http"
    assert args.mcp_host == "0.0.0.0"
    assert args.mcp_port == 9090
    assert args.mcp_path == "/mcp"


def test_parse_args_rejects_stream_http():
    with pytest.raises(SystemExit):
        cli.parse_args(
            [
                "--project-location",
                "/tmp/sample.gpr",
                "--domain-path",
                "/main",
                "--transport",
                "stream-http",
            ]
        )


def test_parse_args_enable_shared_project_sync():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--enable-shared-project-sync",
        ]
    )
    assert args.enable_shared_project_sync is True


def test_parse_args_ghidra_server_auth_options():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--ghidra-server-user",
            "alice",
            "--ghidra-server-password-env",
            "GHIDRA_SERVER_PASSWORD",
        ]
    )
    assert args.ghidra_server_user == "alice"
    assert args.ghidra_server_password_env == "GHIDRA_SERVER_PASSWORD"


def test_parse_args_ghidra_server_auth_direct_password_option():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--ghidra-server-user",
            "alice",
            "--ghidra-server-password",
            "secret",
        ]
    )
    assert args.ghidra_server_user == "alice"
    assert args.ghidra_server_password == "secret"


def test_normalize_transport_alias():
    assert cli._normalize_transport("http") == "streamable-http"
    assert cli._normalize_transport("sse") == "sse"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mcp", "/mcp"),
        ("/mcp", "/mcp"),
        ("", "/mcp"),
    ],
)
def test_normalize_streamable_http_path(raw, expected):
    assert cli._normalize_streamable_http_path(raw) == expected


def test_configure_mcp_for_streamable_http(monkeypatch):
    fake_mcp = types.SimpleNamespace(
        settings=types.SimpleNamespace(
            log_level="INFO",
            host="127.0.0.1",
            port=8081,
            streamable_http_path="/mcp",
            transport_security=None,
        )
    )
    monkeypatch.setattr(cli, "mcp", fake_mcp)

    args = types.SimpleNamespace(
        log_level="DEBUG",
        mcp_host="0.0.0.0",
        mcp_port=9090,
        mcp_path="custom",
    )
    cli.configure_mcp_for_streamable_http(args)

    assert fake_mcp.settings.log_level == "DEBUG"
    assert fake_mcp.settings.host == "0.0.0.0"
    assert fake_mcp.settings.port == 9090
    assert fake_mcp.settings.streamable_http_path == "/custom"
    assert fake_mcp.settings.transport_security.enable_dns_rebinding_protection is False


def test_configure_mcp_for_streamable_http_with_specific_host_enables_rebinding_protection(monkeypatch):
    fake_mcp = types.SimpleNamespace(
        settings=types.SimpleNamespace(
            log_level="INFO",
            host="127.0.0.1",
            port=8081,
            streamable_http_path="/mcp",
            transport_security=None,
        )
    )
    monkeypatch.setattr(cli, "mcp", fake_mcp)

    args = types.SimpleNamespace(
        log_level="INFO",
        mcp_host="172.16.53.129",
        mcp_port=8081,
        mcp_path="/mcp",
    )
    cli.configure_mcp_for_streamable_http(args)

    security = fake_mcp.settings.transport_security
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == ["172.16.53.129:*"]
    assert security.allowed_origins == ["http://172.16.53.129:*"]


def test_configure_mcp_for_sse_with_loopback_host_keeps_local_security(monkeypatch):
    fake_mcp = types.SimpleNamespace(
        settings=types.SimpleNamespace(
            log_level="INFO",
            host="127.0.0.1",
            port=8081,
            transport_security=None,
        )
    )
    monkeypatch.setattr(cli, "mcp", fake_mcp)

    args = types.SimpleNamespace(
        log_level="INFO",
        mcp_host="127.0.0.1",
        mcp_port=8081,
    )
    cli.configure_mcp_for_sse(args)

    security = fake_mcp.settings.transport_security
    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.allowed_hosts


def test_configure_ghidra_server_auth_sets_client_authenticator_from_env(monkeypatch):
    called = {}

    class FakePasswordAuthenticator:
        def __init__(self, username, password):
            called["constructor"] = (username, password)

    class FakeClientUtil:
        @staticmethod
        def setClientAuthenticator(authenticator):
            called["authenticator"] = authenticator

    monkeypatch.setenv("GHIDRA_SERVER_PASSWORD", "secret")
    monkeypatch.setattr(cli, "_password_client_authenticator_class", lambda: FakePasswordAuthenticator)
    monkeypatch.setattr(cli, "_client_util_class", lambda: FakeClientUtil)

    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password=None,
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    cli.configure_ghidra_server_auth(args)

    assert called["constructor"] == ("alice", "secret")
    assert isinstance(called["authenticator"], FakePasswordAuthenticator)


@pytest.mark.parametrize(
    ("username", "password_arg", "password_env_name"),
    [
        ("alice", None, ""),
        ("", None, "GHIDRA_SERVER_PASSWORD"),
        ("alice", None, None),
        ("", "secret", None),
    ],
)
def test_configure_ghidra_server_auth_requires_user_and_password_source(
    monkeypatch, username, password_arg, password_env_name
):
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    args = types.SimpleNamespace(
        ghidra_server_user=username,
        ghidra_server_password=password_arg,
        ghidra_server_password_env=password_env_name,
    )
    with pytest.raises(ValueError, match="must be set together"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_sets_client_authenticator_from_direct_password(monkeypatch):
    called = {}

    class FakePasswordAuthenticator:
        def __init__(self, username, password):
            called["constructor"] = (username, password)

    class FakeClientUtil:
        @staticmethod
        def setClientAuthenticator(authenticator):
            called["authenticator"] = authenticator

    monkeypatch.setattr(cli, "_password_client_authenticator_class", lambda: FakePasswordAuthenticator)
    monkeypatch.setattr(cli, "_client_util_class", lambda: FakeClientUtil)

    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password="secret",
        ghidra_server_password_env=None,
    )
    cli.configure_ghidra_server_auth(args)

    assert called["constructor"] == ("alice", "secret")
    assert isinstance(called["authenticator"], FakePasswordAuthenticator)


def test_configure_ghidra_server_auth_rejects_both_direct_password_and_env(monkeypatch):
    monkeypatch.setenv("GHIDRA_SERVER_PASSWORD", "secret")
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password="secret",
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    with pytest.raises(ValueError, match="cannot be used together"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_requires_non_empty_direct_password():
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password="",
        ghidra_server_password_env=None,
    )
    with pytest.raises(ValueError, match="is empty"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_requires_non_empty_env_value(monkeypatch):
    monkeypatch.setenv("GHIDRA_SERVER_PASSWORD", "")
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password=None,
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    with pytest.raises(ValueError, match="is empty"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_requires_existing_env(monkeypatch):
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password=None,
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    with pytest.raises(ValueError, match="is not set"):
        cli.configure_ghidra_server_auth(args)


def test_ensure_supported_ghidra_installation_allows_non_arm_linux(monkeypatch, tmp_path):
    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()

    monkeypatch.setattr(cli, "validate_linux_arm64_decompiler_install", lambda _path: None)

    cli._ensure_supported_ghidra_installation(str(install_dir))


def test_ensure_supported_ghidra_installation_raises_for_missing_linux_arm64(monkeypatch):
    def fake_validate(_path: str) -> None:
        raise RuntimeError("Linux ARM64 requires Ghidra native decompiler binaries")

    monkeypatch.setattr(cli, "validate_linux_arm64_decompiler_install", fake_validate)

    with pytest.raises(RuntimeError, match="Linux ARM64 requires Ghidra native decompiler binaries"):
        cli._ensure_supported_ghidra_installation("/tmp/ghidra")


def test_public_tool_functions_match_declared_specs():
    assert set(cli.PUBLIC_TOOL_FUNCTIONS) == set(get_all_tool_specs(include_shared_sync=True))
