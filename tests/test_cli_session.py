from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import types

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware

from cli_support import ToolHarness
from ghidra_mcp import cli
from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_all_tool_specs

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()
# A stand-in for the MCP server of an application whose transport is faked.
_NO_TOOLS = types.SimpleNamespace(bindings={})


def _fake_transport(events, failure=None):
    """Stands in for run_mcp_server: serve, let the background startup finish, then end."""

    def transport(server, *, transport, log_level, startup, **kwargs):
        events.append("transport")
        startup.start()
        assert startup.join(timeout=30)
        if failure in {"termination", "termination+close"}:
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler)
            handler(signal.SIGTERM, None)
        if failure == "transport":
            raise RuntimeError("transport")

    return transport


def _no_jvm_thread_calls(monkeypatch):
    # The startup's JVM thread housekeeping, which needs a real JVM.
    monkeypatch.setattr(cli, "_prepare_event_loop_thread", lambda: None)
    monkeypatch.setattr(cli, "detach_current_thread", lambda: None)
    monkeypatch.setattr(cli, "redirect_java_stdout_to_stderr", lambda: None)


@pytest.mark.parametrize(
    "failure",
    [
        "installation",
        "prepare",
        "jvm",
        "runtime",
        "auth",
        "project",
        "no_targets",
        "transport",
        "termination",
        "close",
        "termination+close",
        None,
    ],
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
            if name == failure or (name == "close" and failure == "termination+close"):
                raise RuntimeError(name)

        return call

    registry = types.SimpleNamespace(
        register_target=step("project"), has_targets=lambda: failure != "no_targets", close_all=step("close")
    )
    application = types.SimpleNamespace(registry=registry, script_service=service, mcp=_NO_TOOLS)
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_ensure_supported_ghidra_installation", step("installation"))
    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", step("prepare"))
    monkeypatch.setattr(cli, "_start_pyghidra_headless", step("jvm"))
    _no_jvm_thread_calls(monkeypatch)
    monkeypatch.setattr(cli, "_prepare_script_runtime", step("runtime"))
    monkeypatch.setattr(cli, "configure_ghidra_server_auth", step("auth"))
    monkeypatch.setattr(cli, "_core", lambda: object())
    monkeypatch.setattr(cli, "run_mcp_server", _fake_transport(events, failure))
    monkeypatch.setattr(providers, "shutdown", step("providers"))
    monkeypatch.setattr(cli.jpype, "isJVMStarted", lambda: "jvm" in events)
    monkeypatch.setattr(cli, "_exit_without_joining_threads", lambda code: events.append(("exit", code)))
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
    elif failure in {"transport", "close", "termination+close"}:
        with pytest.raises(RuntimeError, match="close" if failure == "termination+close" else failure):
            cli.main(argv)
    else:
        # Startup failures (including a JVM that will not start) end with one logged line and exit code 1.
        assert cli.main(argv) == (0 if failure is None else 1)
    # Serving starts before the JVM; the checks that need no JVM ran before serving.
    if "jvm" in events:
        assert events.index("transport") < events.index("jvm")
    # Nothing to close before the JVM exists; closing would import the core without one.
    # A failed startup closes once, and the final cleanup does not close again.
    before_jvm = {"installation", "prepare", "jvm", "project", "no_targets"}
    assert events.count("close") == (0 if failure in before_jvm else 1)
    # After SIGTERM the process ends only once every cleanup step has run, even a failing one.
    exits = [("exit", 128 + signal.SIGTERM)] if failure in {"termination", "termination+close"} else []
    assert events[-1 - len(exits) :] == ["providers", *exits]
    assert not snapshot.exists()
    assert signal.getsignal(signal.SIGTERM) == original_handler


def _signal_name(signum):
    return signal.Signals(signum).name


@pytest.mark.parametrize("signum", cli.SHUTDOWN_SIGNALS, ids=_signal_name)
def test_only_the_first_shutdown_signal_interrupts(monkeypatch, signum):
    repeats = []

    def run_cli(_argv):
        with pytest.raises(SystemExit) as exc_info:
            signal.getsignal(signum)(signum, None)
        assert exc_info.value.code == 128 + signum
        # A process-group signal can arrive twice; a repeat of any shutdown
        # signal must not interrupt the cleanup.
        repeats.extend(signal.getsignal(other)(other, None) for other in cli.SHUTDOWN_SIGNALS)
        return 0

    monkeypatch.setattr(cli, "_run_cli", run_cli)
    assert cli.main([]) == 0
    assert repeats == [None] * len(cli.SHUTDOWN_SIGNALS)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_shutdown_signal_the_parent_ignores_stays_ignored(monkeypatch):
    seen = {}

    def run_cli(_argv):
        seen.update((signum, signal.getsignal(signum)) for signum in cli.SHUTDOWN_SIGNALS)
        return 0

    monkeypatch.setattr(cli, "_run_cli", run_cli)
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        # As under nohup.
        assert cli.main([]) == 0
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, previous)
    assert seen.pop(signal.SIGHUP) is signal.SIG_IGN
    assert all(callable(handler) for handler in seen.values())


@pytest.mark.skipif(not hasattr(signal, "SIGQUIT"), reason="POSIX signals")
def test_sigquit_prints_the_python_stacks_and_the_server_keeps_running():
    script = """
import signal

from ghidra_mcp.presentation import cli


def run_cli(_argv):
    signal.raise_signal(signal.SIGQUIT)
    return 0


cli._run_cli = run_cli
raise SystemExit(cli.main([]))
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "most recent call first" in result.stderr


def test_sigterm_inside_the_event_loop_does_not_interrupt_the_callback_it_lands_in(monkeypatch):
    import asyncio

    delivered = []
    exits = []
    monkeypatch.setattr(cli, "_exit_without_joining_threads", exits.append)

    def run_cli(_argv):
        async def serve():
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            delivered.append(future)

            def deliver():
                # A worker thread's result arrives just as the signal does. Had the
                # handler raised here, the future would never be set and shutdown
                # would wait for its task forever.
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                future.set_result("delivered")

            loop.call_soon(deliver)
            await future
            await asyncio.sleep(10)

        asyncio.run(serve())
        return 0

    monkeypatch.setattr(cli, "_run_cli", run_cli)
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 128 + signal.SIGTERM
    assert delivered[0].result() == "delivered"
    assert exits == [128 + signal.SIGTERM]


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal dispositions")
@pytest.mark.parametrize("signum", cli.SHUTDOWN_SIGNALS, ids=_signal_name)
def test_rearm_takes_a_shutdown_signal_back_from_a_native_handler(signum):
    import ctypes

    libc = ctypes.CDLL(None)
    libc.signal.restype = ctypes.c_void_p
    libc.signal.argtypes = [ctypes.c_int, ctypes.c_void_p]
    received = []
    previous = signal.signal(signum, lambda signum, _frame: received.append(signum))
    try:
        # A JVM started without -Xrs does this: a native handler replaces Python's
        # while signal.getsignal() still reports the Python one. SIG_IGN stands in for it.
        libc.signal(signum, 1)
        signal.raise_signal(signum)
        assert received == []
        cli._rearm_python_signals()
        signal.raise_signal(signum)
        assert received == [signum]
    finally:
        signal.signal(signum, previous)


def test_exit_after_sigterm_runs_exit_handlers_without_joining_threads(tmp_path):
    marker = tmp_path / "exit-handlers"
    script = f"""
import atexit
import pathlib
import threading

from ghidra_mcp.presentation import cli

atexit.register(pathlib.Path({str(marker)!r}).write_text, "ran")
# Stands in for the stdio transport's stdin reader, which never returns while stdin is open.
threading.Thread(target=threading.Event().wait).start()
cli._exit_without_joining_threads(143)
"""
    result = subprocess.run([sys.executable, "-c", script], timeout=60)
    assert result.returncode == 143
    assert marker.read_text() == "ran"


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


def test_bad_installation_is_reported_before_serving(monkeypatch, tmp_path, caplog):
    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install_dir))
    application = types.SimpleNamespace(
        registry=types.SimpleNamespace(close_all=lambda: None), script_service=None, mcp=_NO_TOOLS
    )
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_ensure_supported_ghidra_installation", lambda _path: None)
    monkeypatch.setattr(cli, "run_mcp_server", lambda *args, **kwargs: pytest.fail("served a bad installation"))

    def boom(_install_dir):
        raise ValueError("bad Ghidra installation")

    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", boom)
    with caplog.at_level("ERROR"):
        code = cli.main(["--ghidra-path", str(install_dir), "--project-location", str(tmp_path), "--project-name", "t"])
    assert code == 1
    assert "Failed to start the Ghidra JVM: bad Ghidra installation" in caplog.text


def test_jvm_failure_after_serving_is_the_answer_to_every_tool_call(monkeypatch, tmp_path, caplog):
    import asyncio

    from mcp import Client

    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", lambda _path: None)
    _no_jvm_thread_calls(monkeypatch)

    def no_jdk(_install_dir, _launcher):
        raise ValueError("Java was not found")

    monkeypatch.setattr(cli, "_start_pyghidra_headless", no_jdk)
    seen = {}

    def transport(server, *, transport, log_level, startup, **kwargs):
        startup.start()
        assert startup.join(timeout=30)

        async def check():
            async with Client(server) as client:
                seen["tools"] = len((await client.list_tools()).tools)
                seen["call"] = await client.call_tool("list_targets", {})

        asyncio.run(check())

    monkeypatch.setattr(cli, "run_mcp_server", transport)
    with caplog.at_level("ERROR"):
        code = cli.main(["--project-location", str(tmp_path), "--project-name", "t"])
    assert code == 1
    assert "Failed to start the Ghidra JVM: Java was not found" in caplog.text
    # The catalog is still served, and every call says why nothing can run.
    assert seen["tools"] > 0
    assert seen["call"].is_error
    error = seen["call"].structured_content["error"]
    assert (error["code"], error["retryable"], error["details"]["stage"]) == ("STARTUP_FAILED", False, "jvm")
    assert "Java was not found" in error["message"]


def test_programs_open_in_the_background_after_metadata_targets_are_registered(monkeypatch, tmp_path):
    events = []

    class Registry:
        def register_target(self, name, **_kwargs):
            events.append(("register", name))

        def create_session(self, name, **kwargs):
            events.append(("load", name, kwargs["domain_path"]))

        def has_targets(self):
            return any(event[0] == "register" for event in events)

        def close_all(self):
            events.append(("close",))

    application = types.SimpleNamespace(registry=Registry(), script_service=None, mcp=_NO_TOOLS)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", lambda _path: None)
    monkeypatch.setattr(cli, "_start_pyghidra_headless", lambda *_args: events.append(("jvm",)))
    _no_jvm_thread_calls(monkeypatch)
    monkeypatch.setattr(cli, "_core", lambda: object())

    def transport(server, *, transport, log_level, startup, **kwargs):
        events.append(("transport",))
        startup.start()
        assert startup.join(timeout=30)
        assert startup.gate.state == "ready"

    monkeypatch.setattr(cli, "run_mcp_server", transport)
    argv = [
        "--session",
        f"name=meta,project_location={tmp_path}/meta.gpr",
        "--session",
        f"name=fw,project_location={tmp_path}/fw.gpr,domain_path=/fw",
        "--project-location",
        str(tmp_path),
        "--project-name",
        "p",
        "--domain-path",
        "/main",
    ]
    assert cli.main(argv) == 0
    assert events == [
        ("register", "meta"),
        ("transport",),
        ("jvm",),
        ("load", "fw", "/fw"),
        ("load", "default", "/main"),
        ("close",),
    ]


def test_start_pyghidra_headless_delegates_to_shared_launcher(monkeypatch):
    calls: list[object] = []
    prepared = object()
    monkeypatch.setattr(
        cli, "start_headless_jvm", lambda install_dir, *, launcher=None: calls.append((install_dir, launcher))
    )
    cli._start_pyghidra_headless("/tmp/ghidra", prepared)
    assert calls == [("/tmp/ghidra", prepared)]


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


def test_the_startup_log_counts_every_published_tool(monkeypatch, tmp_path, caplog):
    import asyncio

    served = []
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", lambda _path: None)
    monkeypatch.setattr(cli, "run_mcp_server", lambda server, **_kwargs: served.append(server))
    with caplog.at_level("INFO"):
        cli.main(["--project-location", str(tmp_path), "--project-name", "t"])

    tools = {tool.name for tool in asyncio.run(served[0].list_tools())}
    # The result-retrieval tools come beside the profile's.
    assert {"read_result", "search_result"} <= tools
    assert f"Starting PyGhidra MCP server with {len(tools)} tools" in caplog.text


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_a_signal_while_shutdown_waits_for_the_startup_still_closes_the_projects(monkeypatch, tmp_path):
    import threading

    from ghidra_mcp.application.services.script_service import ScriptConfig, ScriptService

    events = []
    release = threading.Event()

    def step(name):
        return lambda *args, **kwargs: events.append(name)

    def slow_session(*args, **kwargs):
        events.append("project")
        assert release.wait(10)

    def transport(server, *, transport, log_level, startup, **kwargs):
        # The client goes away while Ghidra is still opening the startup session.
        startup.start()
        while "project" not in events:
            time.sleep(0.01)

    original_stop = cli.BackgroundStartup.stop
    timers = []

    def stop(self):
        # SIGTERM arrives while shutdown waits for the step in progress.
        timers.extend([threading.Timer(0.1, os.kill, (os.getpid(), signal.SIGTERM)), threading.Timer(0.5, release.set)])
        for timer in timers:
            timer.start()
        original_stop(self)
        events.append("startup stopped")

    registry = types.SimpleNamespace(create_session=slow_session, has_targets=lambda: True, close_all=step("close"))
    service = ScriptService(None, config=ScriptConfig())
    application = types.SimpleNamespace(registry=registry, script_service=service, mcp=_NO_TOOLS)
    monkeypatch.setattr(cli, "build_application", lambda *args, **kwargs: application)
    monkeypatch.setattr(cli, "_ensure_supported_ghidra_installation", step("installation"))
    monkeypatch.setattr(cli, "_prepare_pyghidra_headless", step("prepare"))
    monkeypatch.setattr(cli, "_start_pyghidra_headless", step("jvm"))
    _no_jvm_thread_calls(monkeypatch)
    monkeypatch.setattr(cli, "configure_ghidra_server_auth", step("auth"))
    monkeypatch.setattr(cli, "_core", lambda: object())
    monkeypatch.setattr(cli, "run_mcp_server", transport)
    monkeypatch.setattr(cli.BackgroundStartup, "stop", stop)
    monkeypatch.setattr(cli.jpype, "isJVMStarted", lambda: "jvm" in events)
    monkeypatch.setattr(cli, "_exit_without_joining_threads", lambda code: events.append(("exit", code)))
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "installation"))
    argv = ["--ghidra-path", str(tmp_path / "installation"), "--project-location", str(tmp_path)]
    # A program opens in the background, so the session is a startup step.
    argv += ["--project-name", "test", "--domain-path", "/main"]
    # main() puts this handler back when it returns: a SIGTERM that comes after that
    # (stop() no longer waiting for the step) fails this test instead of ending pytest.
    stray = []
    previous = signal.signal(signal.SIGTERM, lambda signum, _frame: stray.append(signum))
    try:
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(5)
        release.set()
        signal.signal(signal.SIGTERM, previous)
    assert exc_info.value.code == 128 + signal.SIGTERM and not stray
    # The signal waited for the projects to close.
    assert events[-3:] == ["startup stopped", "close", ("exit", 128 + signal.SIGTERM)]


def test_a_cleanup_failure_is_logged_before_a_deferred_signal_replaces_it(caplog):
    from ghidra_mcp.presentation.cli_runtime import defer_shutdown_signals

    delivered = []
    previous = signal.signal(signal.SIGTERM, lambda signum, _frame: delivered.append(signum))
    try:
        with pytest.raises(RuntimeError, match="close failed"):
            with defer_shutdown_signals():
                # Nested, as close_all inside the CLI's cleanup: the outer block logs once.
                with defer_shutdown_signals():
                    signal.raise_signal(signal.SIGTERM)
                    assert delivered == []
                    raise RuntimeError("close failed")
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert delivered == [signal.SIGTERM]
    assert caplog.text.count("Cleanup failed before the deferred SIGTERM was delivered") == 1
