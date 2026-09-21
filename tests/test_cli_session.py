from __future__ import annotations

import signal
import types

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware

from cli_support import ToolHarness
from ghidra_mcp import cli
from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_all_tool_specs

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()


@pytest.mark.parametrize(
    "failure",
    ["installation", "jvm", "runtime", "auth", "project", "no_targets", "transport", "termination", "close", None],
)
def test_main_cleans_script_snapshot_on_every_exit(monkeypatch, tmp_path, failure):
    from ghidra_headless.scripts import providers
    from ghidra_mcp.application.services.script_service import ScriptConfig, ScriptService

    source = tmp_path / "scripts"
    source.mkdir()
    (source / "Example.py").write_text("# @runtime PyGhidra\nprint('test')\n")
    snapshot = tmp_path / "snapshot"
    service = ScriptService(None, config=ScriptConfig(roots=[("test", source)], snapshot_base=snapshot))
    events = []

    def step(name):
        def call(*args, **kwargs):
            events.append(name)
            if name == "transport" and failure == "termination":
                handler = signal.getsignal(signal.SIGTERM)
                assert callable(handler)
                handler(signal.SIGTERM, None)
            if name == failure:
                raise RuntimeError(name)

        return call

    registry = types.SimpleNamespace(
        register_target=step("project"), has_targets=lambda: failure != "no_targets", close_all=step("close")
    )
    application = types.SimpleNamespace(registry=registry, script_service=service, mcp=None)
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_ensure_supported_ghidra_installation", step("installation"))
    monkeypatch.setattr(cli, "_start_pyghidra_headless", step("jvm"))
    monkeypatch.setattr(cli, "redirect_java_stdout_to_stderr", lambda: None)
    monkeypatch.setattr(cli, "_prepare_script_runtime", step("runtime"))
    monkeypatch.setattr(cli, "configure_ghidra_server_auth", step("auth"))
    monkeypatch.setattr(cli, "_core", lambda: object())
    monkeypatch.setattr(cli, "run_mcp_server", step("transport"))
    monkeypatch.setattr(providers, "shutdown", step("providers"))
    # main updates this environment variable when --ghidra-path is provided.
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "installation"))
    argv = [
        "--ghidra-path",
        str(tmp_path / "installation"),
        "--project-location",
        str(tmp_path),
        "--project-name",
        "test",
        "--add-category",
        "scripts",
    ]
    original_handler = signal.getsignal(signal.SIGTERM)
    if failure == "termination":
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)
        assert exc_info.value.code == 128 + signal.SIGTERM
    elif failure in {"transport", "close"}:
        with pytest.raises(RuntimeError, match=failure):
            cli.main(argv)
    else:
        # Startup failures (including a JVM that will not start) end with one logged line and exit code 1.
        assert cli.main(argv) == (0 if failure is None else 1)
    # Nothing to close before the JVM exists; closing would import the core without one.
    assert events.count("close") == (0 if failure in {"installation", "jvm"} else 1)
    assert events[-1] == "providers"
    assert not snapshot.exists()
    assert signal.getsignal(signal.SIGTERM) == original_handler


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

    def create_project(self, *, project_location: str, project_name: str | None = None, overwrite: bool = False):
        self.calls.append(
            (
                "create_project",
                (),
                {"project_location": project_location, "project_name": project_name, "overwrite": overwrite},
            )
        )
        return {"status": "ok", "project_location": project_location, "project_name": project_name or "sample"}

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

    def save_project_program(self, target: str, *, domain_path: str | None = None):
        self.calls.append(("save_project_program", (target,), {"domain_path": domain_path}))
        return {"status": "ok", "target": target, "program": domain_path or "/main", "saved": True}

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
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ):
        self.calls.append(
            (
                "commit_project_program",
                (target, message),
                {
                    "keep_checked_out": keep_checked_out,
                    "auto_checkout": auto_checkout,
                    "on_conflict": on_conflict,
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

    def delete_shared_project_file(
        self,
        target: str,
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
                (target,),
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


class FakeBsimService:
    pass


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
            bsim_service=FakeBsimService(),
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
            lambda a: a.create_project(project_location="/tmp/p.gpr", project_name=None),
            {"status": "ok", "project_location": "/tmp/p.gpr", "project_name": "sample"},
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
            lambda a: a.save_project_program("fw", domain_path="/app"),
            {"status": "ok", "target": "fw", "program": "/app", "saved": True},
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
            lambda a: a.delete_shared_project_file("fw", domain_path="/app", confirm="/app"),
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
            lambda: cli_tools.list_namespaces(classes_only=True, offset=3, limit=4, target="fw"),
            "list_namespaces",
            {"classes_only": True, "offset": 3, "limit": 4},
        ),
    ],
)
def test_list_namespaces_use_dispatcher(monkeypatch, call, expected_spec, expected_args):
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
    assert called["registry"] is cli_tools.registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (
            lambda: cli_tools.list_namespaces(classes_only=True, offset=0, limit=10, target="fw"),
            "Session 'fw' is not initialized",
        ),
    ],
)
def test_list_namespaces_error_message_compat(monkeypatch, call, message):
    class DummyRegistry:
        def call(self, command, params, target):  # noqa: ARG002
            raise RuntimeError(f"Session '{target}' is not initialized")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match=message):
        call()


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


def test_parse_args_accepts_tool_filter_options():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--tool-profile",
            "full",
            "--allow-category",
            "shared_sync",
            "--add-category",
            "core",
            "--allow-safety",
            "read_only",
            "--allow-operation-level",
            "advanced",
            "--enable-tool",
            "apply_edits",
            "--disable-tool",
            "set_bytes",
        ]
    )
    assert args.tool_profile == "full"
    assert args.allow_category == ["shared_sync"]
    assert args.add_category == ["core"]
    assert args.allow_safety == ["read_only"]
    assert args.allow_operation_level == ["advanced"]
    assert args.enable_tool == ["apply_edits"]
    assert args.disable_tool == ["set_bytes"]


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
    assert cli._normalize_transport("stdio") == "stdio"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mcp", "/mcp"),
        ("/mcp", "/mcp"),
        ("", "/mcp"),
    ],
)
def test_normalize_streamable_http_path(raw, expected):
    from ghidra_mcp.presentation.transport import normalize_streamable_http_path

    assert normalize_streamable_http_path(raw) == expected


def test_configure_mcp_for_streamable_http():
    args = types.SimpleNamespace(
        log_level="DEBUG",
        mcp_host="0.0.0.0",
        mcp_port=9090,
        mcp_path="custom",
    )
    run_kwargs = cli.configure_mcp_for_streamable_http(args)

    assert run_kwargs["host"] == "0.0.0.0"
    assert run_kwargs["port"] == 9090
    assert run_kwargs["streamable_http_path"] == "/custom"
    assert run_kwargs["stateless_http"] is True
    assert run_kwargs["json_response"] is True
    security = run_kwargs["transport_security"]
    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.allowed_hosts
    assert "http://localhost:*" in security.allowed_origins

    middleware = TransportSecurityMiddleware(security)
    assert middleware._validate_host("127.0.0.1:9090") is True
    assert middleware._validate_origin("http://localhost:9090") is True
    assert middleware._validate_host("attacker.example:9090") is False
    assert middleware._validate_origin("https://attacker.example") is False


def test_configure_mcp_for_streamable_http_with_specific_host_enables_rebinding_protection():
    args = types.SimpleNamespace(
        log_level="INFO",
        mcp_host="172.16.53.129",
        mcp_port=8081,
        mcp_path="/mcp",
    )
    run_kwargs = cli.configure_mcp_for_streamable_http(args)

    security = run_kwargs["transport_security"]
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == ["172.16.53.129", "172.16.53.129:*"]
    assert security.allowed_origins == [
        "http://172.16.53.129",
        "http://172.16.53.129:*",
        "https://172.16.53.129",
        "https://172.16.53.129:*",
    ]


def test_legacy_sse_transport_is_rejected():
    from ghidra_mcp.presentation.transport import run_kwargs_for_transport

    with pytest.raises(SystemExit):
        cli.parse_args(["--transport", "sse"])
    with pytest.raises(ValueError, match="Unsupported transport"):
        run_kwargs_for_transport(transport="sse", args=None, logger=cli.logger)


def test_run_kwargs_for_stdio_transport_are_empty():
    from ghidra_mcp.presentation.transport import run_kwargs_for_transport

    args = types.SimpleNamespace(log_level="INFO", mcp_host="127.0.0.1", mcp_port=None, mcp_path="/mcp")
    assert run_kwargs_for_transport(transport="stdio", args=args, logger=cli.logger) == {}


def test_redirect_java_stdout_to_stderr_swaps_system_out(monkeypatch):
    calls: list[object] = []

    class FakeSystem:
        err = object()

        @staticmethod
        def setOut(stream):
            calls.append(stream)

    monkeypatch.setattr(cli.jpype, "JClass", lambda name: FakeSystem if name == "java.lang.System" else None)
    cli.redirect_java_stdout_to_stderr()
    assert calls == [FakeSystem.err]


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


def test_ensure_supported_ghidra_installation_raises_for_missing_linux_arm64(monkeypatch, tmp_path):
    def fake_validate(_path: str) -> None:
        raise RuntimeError("Linux ARM64 requires Ghidra native decompiler binaries")

    monkeypatch.setattr(cli, "validate_linux_arm64_decompiler_install", fake_validate)
    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()

    with pytest.raises(RuntimeError, match="Linux ARM64 requires Ghidra native decompiler binaries"):
        cli._ensure_supported_ghidra_installation(str(install_dir))


def test_ensure_supported_ghidra_installation_names_a_missing_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "validate_linux_arm64_decompiler_install", lambda _path: pytest.fail("not reached"))

    with pytest.raises(RuntimeError, match="does not exist.*--ghidra-path"):
        cli._ensure_supported_ghidra_installation(str(tmp_path / "missing"))


def test_jvm_start_failure_is_reported_without_a_traceback(monkeypatch, tmp_path, caplog):
    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    application = types.SimpleNamespace(
        registry=types.SimpleNamespace(close_all=lambda: None), script_service=None, mcp=None
    )
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_ensure_supported_ghidra_installation", lambda _path: None)

    def boom(_install_dir):
        raise ValueError("bad Ghidra installation")

    monkeypatch.setattr(cli, "_start_pyghidra_headless", boom)
    with caplog.at_level("ERROR"):
        code = cli.main(["--ghidra-path", str(install_dir), "--project-location", str(tmp_path), "--project-name", "t"])
    assert code == 1
    assert "Failed to start the Ghidra JVM: bad Ghidra installation" in caplog.text


def test_start_pyghidra_headless_delegates_to_shared_launcher(monkeypatch):
    calls: list[object] = []
    monkeypatch.setattr(cli, "start_headless_jvm", lambda install_dir: calls.append(install_dir))
    cli._start_pyghidra_headless("/tmp/ghidra")
    assert calls == ["/tmp/ghidra"]


def test_public_tool_functions_match_declared_specs():
    assert set(cli.PUBLIC_TOOL_FUNCTIONS) == set(get_all_tool_specs())


def test_build_application_keeps_empty_selected_specs(monkeypatch):
    captured: dict[str, object] = {}
    sentinel_registry = object()
    sentinel_mcp = object()

    def fake_create_cli_runtime(
        *,
        registered_specs,
        core_accessor,
        checkout_required_commands,
        bsim_config,
        dispatcher_provider,
        registry_provider,
    ):
        captured["registered_specs"] = dict(registered_specs)
        captured["checkout_required_commands"] = set(checkout_required_commands)
        captured["bsim_config"] = bsim_config
        return types.SimpleNamespace(
            registry=sentinel_registry,
            runtime=types.SimpleNamespace(mcp=sentinel_mcp),
        )

    monkeypatch.setattr(cli, "create_cli_runtime", fake_create_cli_runtime)

    app = cli.build_application({})
    assert app.registry is sentinel_registry
    assert captured["registered_specs"] == {}
    assert captured["checkout_required_commands"] == set()
    assert app.mcp is sentinel_mcp


def test_cli_module_holds_no_server_state_at_import():
    """The CLI keeps no registry, server or tool functions in module state; main() builds a CLIApplication."""
    from mcp.server import Server

    from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter

    module_values = vars(cli).values()
    assert not any(isinstance(value, (Server, ServiceRegistryAdapter, cli.CLIApplication)) for value in module_values)
    assert not any(name in vars(cli) for name in cli.PUBLIC_TOOL_FUNCTIONS)
    assert not hasattr(cli, "_registry") and not hasattr(cli, "mcp")


def test_two_applications_do_not_share_state():
    first = cli.build_application({})
    second = cli.build_application({})
    assert first.registry is not second.registry
    assert first.mcp is not second.mcp
    assert first.script_service is not second.script_service


def test_resolve_tool_specs_from_args_defaults_to_default_profile():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
        ]
    )
    expected = filter_tool_specs(profile=ToolProfile.DEFAULT)
    resolved = cli.resolve_tool_specs_from_args(args)

    assert set(resolved) == set(expected)
    assert "get_project_sync_status" not in resolved


def test_parse_args_accepts_bsim_password_options():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--bsim-url",
            "postgresql://user@localhost/bsim",
            "--bsim-password",
            "secret",
        ]
    )

    assert args.bsim_url == "postgresql://user@localhost/bsim"
    assert args.bsim_password == "secret"
    assert args.bsim_password_env is None

    env_args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--bsim-password-env",
            "BSIM_PASSWORD",
        ]
    )

    assert env_args.bsim_password is None
    assert env_args.bsim_password_env == "BSIM_PASSWORD"


def test_resolve_tool_specs_from_args_explicit_default_matches_no_args():
    implicit_args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
        ]
    )
    explicit_args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--tool-profile",
            "default",
        ]
    )

    assert set(cli.resolve_tool_specs_from_args(implicit_args)) == set(cli.resolve_tool_specs_from_args(explicit_args))


def test_script_queue_timeout_flag_is_validated_and_applied(monkeypatch):
    from ghidra_mcp.domain import get_script_queue_timeout_seconds

    base = ["--project-location", "/tmp/p", "--project-name", "t"]
    assert cli.parse_args(base).script_queue_timeout_seconds == 300.0
    assert cli.parse_args([*base, "--script-queue-timeout-seconds", "42"]).script_queue_timeout_seconds == 42.0
    with pytest.raises(SystemExit):
        cli.parse_args([*base, "--script-queue-timeout-seconds", "0"])
    applied = []
    monkeypatch.setattr(cli, "configure_script_queue_timeout_seconds", applied.append)
    monkeypatch.setattr(cli, "configure_lock_timeout_seconds", lambda _seconds: None)
    monkeypatch.setattr(cli, "configure_exclusive_checkout_default", lambda _flag: None)
    monkeypatch.setattr(cli, "script_config_from_args", lambda *_args: (_ for _ in ()).throw(ValueError("stop")))
    assert cli._run_cli([*base, "--script-queue-timeout-seconds", "42"]) == 2
    assert applied == [42.0]
    assert get_script_queue_timeout_seconds() == 300.0
