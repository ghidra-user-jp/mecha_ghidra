"""JVM-free tests for the script execution contract (classification, specs, CLI wiring)."""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.scripts import providers
from ghidra_headless.scripts.execution import (
    OUTCOME_COMMITTED,
    OUTCOME_ROLLED_BACK,
    OUTCOME_UNCHANGED,
    OUTCOME_UNKNOWN,
    classify_transaction,
)
from ghidra_mcp.application.commands import CORE_COMMANDS
from ghidra_mcp.contracts.tool_spec import (
    ExecutorKind,
    ToolCategoryTag,
    ToolProfile,
    ToolSafetyTag,
    filter_tool_specs,
    get_all_tool_specs,
)
from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.domain.error_codes import classify_error_code
from ghidra_mcp.domain.error_mapping import DETAIL_PRESERVING_CODES, to_domain_error
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.error_mapper import _PUBLIC_MESSAGES

SCRIPT_CODES = [
    "SCRIPTS_DISABLED",
    "SCRIPT_NOT_FOUND",
    "AMBIGUOUS_SCRIPT",
    "SCRIPT_RUNTIME_AMBIGUOUS",
    "SCRIPT_RUNTIME_UNAVAILABLE",
    "SCRIPT_COMPILE_FAILED",
    "SCRIPT_LOAD_FAILED",
    "SCRIPT_FAILED",
    "SCRIPT_TIMEOUT",
    "SCRIPT_CANCELLED",
    "TARGET_EXECUTION_INVALID",
    "TARGET_ORPHAN_UNRELEASED",
    "RUNTIME_DEGRADED",
]


class _JythonStubScriptProvider:
    """Stands in for ghidra.app.script.JythonStubScriptProvider (the class, for isinstance)."""

    def getRuntimeEnvironmentName(self):
        return "Jython"


@pytest.mark.parametrize("jython_installed", [False, True])
def test_runtime_availability_ignores_jython_stub(monkeypatch, jython_installed):
    def provider(runtime):
        return SimpleNamespace(getRuntimeEnvironmentName=lambda: runtime)

    java = provider("Java")
    python = provider("PyGhidra")
    stub = _JythonStubScriptProvider()
    jython = provider("Jython")
    # Even if the stub is returned before the real provider, it must not win.
    installed = [java, python, stub] + ([jython] if jython_installed else [])
    monkeypatch.setattr(providers._state, "providers", None)
    monkeypatch.setattr(providers, "_script_util", lambda: SimpleNamespace(getProviders=lambda: installed))
    monkeypatch.setattr(providers.jpype, "JClass", lambda name: _JythonStubScriptProvider)

    assert providers.runtime_availability() == {"Java": True, "PyGhidra": True, "Jython": jython_installed}
    assert providers.provider_for("Java") is java
    assert providers.provider_for("PyGhidra") is python
    if jython_installed:
        assert providers.provider_for("Jython") is jython
    else:
        with pytest.raises(HeadlessError, match="SCRIPT_RUNTIME_UNAVAILABLE") as exc:
            providers.provider_for("Jython")
        assert "Extension" in str(exc.value)


@pytest.mark.parametrize(
    ("java_type", "value", "expected", "success"),
    [
        ("PyNone", None, None, True),
        ("PyInteger", 0, 0, True),
        ("PyInteger", 3, 3, False),
        ("PyBoolean", 0, 0, True),
        ("PyBoolean", 1, 1, False),
        ("PyLong", 0, 0, True),
        ("PyLong", 1099511627776, 1099511627776, False),
        ("PyString", "0", "0", False),
        ("PyString", "failure", "failure", False),
    ],
)
def test_jython_system_exit_uses_public_invocation_and_preserves_code_types(
    monkeypatch, java_type, value, expected, success
):
    from ghidra_headless.scripts import execution

    class JavaValue:
        def __init__(self, value):
            self.value = value

        def getValue(self):
            return self.value

        def __str__(self):
            return str(self.value)

    classes = {
        name: type(f"org.python.core.{name}", (JavaValue,), {})
        for name in ("PyNone", "PyInteger", "PyLong", "PyString")
    }
    classes["PyBoolean"] = type("org.python.core.PyBoolean", (classes["PyInteger"],), {})
    monkeypatch.setattr(execution, "_jclass", lambda name: classes[name.rsplit(".", 1)[1]])
    invocations = []

    def invoke(method, key):
        invocations.append((method, str(key)))
        assert isinstance(key, classes["PyString"])
        return classes[java_type](value)

    # Like JPype's real wrapper, expose invoke, but no __findattr__/__getattr__.
    exception = SimpleNamespace(
        type="<type 'exceptions.SystemExit'>",
        value=SimpleNamespace(invoke=invoke),
        normalize=lambda: None,
        getClass=lambda: SimpleNamespace(getName=lambda: "org.python.core.PyException"),
    )
    details = execution._jython_exception_details(exception)
    assert details["system_exit"] is True
    assert details["exit_code"] == expected
    assert type(details["exit_code"]) is type(expected)
    assert execution._exit_code_is_success(details["exit_code"]) is success
    assert invocations == [("__getattribute__", "code")]


@pytest.mark.parametrize(
    ("commit", "status", "dbc", "leaked", "expected"),
    [
        (True, "COMMITTED", True, False, (OUTCOME_COMMITTED, "valid")),
        (True, "COMMITTED", False, False, (OUTCOME_UNCHANGED, "valid")),
        (False, "ABORTED", False, False, (OUTCOME_ROLLED_BACK, "valid")),
        # A script that aborted its own nested transaction and returned normally.
        (True, "ABORTED", False, False, (OUTCOME_ROLLED_BACK, "valid")),
        (True, "NOT_DONE", False, True, (OUTCOME_UNKNOWN, "invalid")),
        (False, "NOT_DONE_BUT_ABORTED", False, True, (OUTCOME_UNKNOWN, "invalid")),
        (True, "COMMITTED", True, True, (OUTCOME_UNKNOWN, "invalid")),
        (False, "COMMITTED", True, False, (OUTCOME_UNKNOWN, "invalid")),
        (True, "ABORTED", True, False, (OUTCOME_UNKNOWN, "invalid")),
        (True, None, None, False, (OUTCOME_UNKNOWN, "invalid")),
    ],
)
def test_transaction_outcome_table(commit, status, dbc, leaked, expected):
    assert (
        classify_transaction(commit_requested=commit, ended=True, status=status, committed_db=dbc, leaked=leaked)
        == expected
    )


def test_script_error_codes_are_fully_plumbed():
    for code in SCRIPT_CODES:
        enum_member = ErrorCode(code)
        assert classify_error_code(code).code == enum_member
        assert enum_member in _PUBLIC_MESSAGES
        assert enum_member in DETAIL_PRESERVING_CODES
    timeout = classify_error_code("SCRIPT_TIMEOUT")
    assert timeout.retryable is False


def test_headless_script_error_details_survive_domain_mapping():
    exc = HeadlessError(
        "SCRIPT_FAILED: boom",
        details={"transaction_outcome": "rolled_back", "execution_state": "valid", "stdout": {"text": "x"}},
    )
    mapped = to_domain_error(exc, operation="run_script", target="fw")
    assert mapped.code == ErrorCode.SCRIPT_FAILED
    assert mapped.details["transaction_outcome"] == "rolled_back"
    assert mapped.details["stdout"] == {"text": "x"}
    assert mapped.details["target"] == "fw"


def test_scripts_category_specs_and_exposure():
    specs = get_all_tool_specs()
    scripts = {name for name, spec in specs.items() if spec.category_tag == ToolCategoryTag.SCRIPTS}
    assert scripts == {"list_scripts", "get_script_info", "run_script"}
    run = specs["run_script"]
    assert run.executor_kind == ExecutorKind.REGISTRY_METHOD
    assert run.safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE
    assert run.checkout_required is True
    assert "expected_sha256" not in run.input_model.model_fields
    assert "expected_revision" in run.input_model.model_fields
    assert specs["list_scripts"].include_target is False
    assert specs["get_script_info"].include_target is False
    assert "discard_changes" in specs["close_session"].input_model.model_fields
    # Never in the default/readonly profiles; only 'full' or an explicit category flag lists them.
    assert scripts.isdisjoint(filter_tool_specs(profile=ToolProfile.DEFAULT))
    assert scripts.isdisjoint(filter_tool_specs(profile=ToolProfile.READONLY))
    assert scripts <= set(filter_tool_specs(profile=ToolProfile.FULL))
    assert "run_script" in CORE_COMMANDS


def test_cli_script_config_from_args(tmp_path):
    root = tmp_path / "scripts"
    root.mkdir()
    args = cli.parse_args(["--script-root", f"team={root}", "--script-root", "bundled"])
    config = cli.script_config_from_args(args, str(tmp_path / "ghidra"))
    assert config.roots == (("team", root),)
    assert config.include_bundled is True
    assert config.ghidra_install_dir == tmp_path / "ghidra"
    assert config.snapshot_base is None, "created lazily with mkdtemp by ScriptService.initialize"

    disabled = cli.script_config_from_args(cli.parse_args([]), None)
    assert disabled.roots == ()
    assert disabled.include_bundled is False


def test_removed_script_flags_are_gone():
    """Exposure is decided by the profile/category flags; the only script setting is the root."""

    for flag in (
        "--allow-scripts",
        "--scripts-execution-mode",
        "--scripts-versioned-handoff",
        "--python-default-runtime",
    ):
        with pytest.raises(SystemExit):
            cli.parse_args([flag])


def test_scripts_category_follows_the_profile_and_category_flags():
    assert "run_script" not in filter_tool_specs(profile=ToolProfile.DEFAULT)
    assert "run_script" in filter_tool_specs(profile=ToolProfile.FULL)
    assert "run_script" in filter_tool_specs(profile=ToolProfile.DEFAULT, add_categories=[ToolCategoryTag.SCRIPTS])


@pytest.fixture
def java_thread_table(monkeypatch):
    from ghidra_headless.scripts import execution

    active = {}
    info_requests = []

    def get_info(ids, max_depth):
        assert max_depth == 0, "thread observation must not collect stacks"
        info_requests.append(list(ids))
        return [active.get(identity) for identity in ids]

    bean = SimpleNamespace(getAllThreadIds=lambda: list(active), getThreadInfo=get_info)
    factory = SimpleNamespace(getThreadMXBean=lambda: bean)
    monkeypatch.setattr(execution, "_jclass", {"java.lang.management.ManagementFactory": factory}.__getitem__)
    monkeypatch.setattr(execution, "jpype", SimpleNamespace(JArray=lambda _type: list, JLong=int))
    return active, info_requests


def _java_thread_info(name="script-worker", daemon=False):
    return SimpleNamespace(getThreadName=lambda: name, isDaemon=lambda: daemon)


def test_java_thread_tracking_collects_only_new_thread_info_without_stacks(java_thread_table):
    from ghidra_headless.scripts import execution

    active, requests = java_thread_table
    active[41] = _java_thread_info()
    before = execution.snapshot_threads()
    assert before["java"] == {41}
    assert requests == []
    assert execution._live_threads_not_in(before) == []
    assert requests == []
    active[42] = _java_thread_info()
    found = execution._live_threads_not_in(before)
    assert [(item["kind"], item["id"]) for item in found] == [("java", 42)]
    assert requests == [[42]]
    assert execution.alive_threads(found) == found
    del active[42]
    assert execution.alive_threads(found) == []
    assert requests == [[42]], "liveness checks only need thread IDs"


def test_java_thread_that_exits_between_enumeration_and_info_is_ignored(java_thread_table):
    from ghidra_headless.scripts import execution

    active, requests = java_thread_table
    active[42] = None
    assert execution._live_threads_not_in({"java": set()}) == []
    assert requests == [[42]]


# ---- stray-thread detection (fixes 1 and 2) --------------------------------


@pytest.fixture
def fake_java_threads(java_thread_table):
    """A Java thread table with no threads, so only the Python side is under test."""

    return java_thread_table


def _blocked_thread(name: str) -> tuple[threading.Thread, threading.Event]:
    release = threading.Event()
    thread = threading.Thread(target=release.wait, name=name, daemon=True)
    return thread, release


def test_server_worker_threads_started_during_a_run_are_never_stray(fake_java_threads):
    """anyio spawns 'AnyIO worker thread' whenever a message arrives mid-run; that is not script work."""

    from ghidra_headless.scripts import execution

    before = execution.snapshot_threads()
    workers = [
        _blocked_thread(name) for name in ("AnyIO worker thread", "asyncio_3", "uvicorn-1", "ThreadPoolExecutor-0_1")
    ]
    try:
        with execution.ThreadStartRecorder() as recorder:
            for thread, _ in workers:
                thread.start()
        threads = execution.describe_new_threads(before, grace_seconds=0, recorder=recorder)
        assert threads["stray"] == []
        assert recorder.started == []
    finally:
        for _, release in workers:
            release.set()


def test_only_threads_started_inside_the_recorder_window_are_stray(fake_java_threads):
    from ghidra_headless.scripts import execution

    earlier, release_earlier = _blocked_thread("pre-existing-worker")
    earlier.start()
    script_thread, release_script = _blocked_thread("script-worker")
    later, release_later = _blocked_thread("after-the-run")
    try:
        before = execution.snapshot_threads()
        with execution.ThreadStartRecorder() as recorder:
            script_thread.start()
        later.start()
        assert threading.Thread.start is execution._ORIGINAL_THREAD_START, "Thread.start is restored"
        threads = execution.describe_new_threads(before, grace_seconds=0, recorder=recorder)
        assert [(item["kind"], item["name"]) for item in threads["stray"]] == [("python", "script-worker")]
        entry = threads["stray"][0]
        assert set(entry) == {"kind", "id", "name", "daemon", "token"}
        assert entry["id"] == script_thread.ident
        assert entry["daemon"] is True
        # Fix 2: liveness is resolved through the recorded Thread object, not a recycled ident.
        assert execution.alive_threads(threads["stray"]) == threads["stray"]
        release_script.set()
        script_thread.join(5)
        assert execution.alive_threads(threads["stray"]) == []
    finally:
        release_earlier.set()
        release_script.set()
        release_later.set()


def test_recorder_restores_thread_start_even_when_the_script_raises():
    from ghidra_headless.scripts import execution

    original = threading.Thread.start
    with pytest.raises(RuntimeError):
        with execution.ThreadStartRecorder():
            assert threading.Thread.start is not original
            raise RuntimeError("script failed")
    assert threading.Thread.start is original


def test_dummy_threads_are_never_recorded():
    """Java threads calling into Python appear as _DummyThread; they are not script-started threads."""

    from ghidra_headless.scripts import execution

    dummy = object.__new__(threading._DummyThread)  # constructing one would clobber threading._active
    recorder = execution.ThreadStartRecorder()
    recorder.record(dummy)
    assert recorder.started == []


def test_alive_threads_ignores_recycled_idents_and_unknown_tokens(fake_java_threads):
    from ghidra_headless.scripts import execution

    # The main thread's ident is certainly alive; a stale entry must still count as gone.
    stale = {"kind": "python", "id": threading.get_ident(), "name": "old-worker", "daemon": False}
    unknown = {**stale, "token": "no-such-token"}
    assert execution.alive_threads([stale, unknown]) == []


def test_java_stray_entries_keep_their_shape_and_threadid_check(java_thread_table):
    from ghidra_headless.scripts import execution

    active, _requests = java_thread_table
    active[7] = _java_thread_info("script-java")
    before = execution.snapshot_threads()
    active[8] = _java_thread_info("script-java")
    threads = execution.describe_new_threads(before, grace_seconds=0)
    assert threads["stray"] == [{"kind": "java", "id": 8, "name": "script-java", "daemon": False}]
    assert execution.alive_threads(threads["stray"]) == threads["stray"]
    del active[8]
    assert execution.alive_threads(threads["stray"]) == []


# ---- execute_script wiring (fixes 1 and 6) ------------------------------------


class _FakeCapture:
    def __init__(self, _limit):
        self.writer = object()

    def flush(self):
        pass

    def describe(self):
        return {"text": "", "dropped_bytes": 0}


@pytest.fixture
def fake_execution_env(monkeypatch, tmp_path):
    """Everything execute_script touches, without a JVM.  Returns a dict to configure the fake script."""

    from ghidra_headless.scripts import execution, runtime_check

    env = {
        "registered": [],
        "body": lambda: None,
        "load": lambda: None,
        "jython_available": False,
        "interpreters": 0,
        "interpreter_cleanups": 0,
    }
    monkeypatch.setattr(runtime_check, "require_script_runtime_ready", lambda: None)
    monkeypatch.setattr(execution._jython, "instance", None)
    monkeypatch.setattr(providers, "ensure_bundle_host", lambda: None)
    monkeypatch.setattr(providers, "runtime_availability", lambda: {"Jython": env["jython_available"]})
    monkeypatch.setattr(providers, "register_source_root", lambda root: env["registered"].append(str(root)))

    class Interpreter:
        def setOut(self, _writer):
            pass

        def setErr(self, _writer):
            pass

        def cleanup(self):
            env["interpreter_cleanups"] += 1

    def make_interpreter():
        env["interpreters"] += 1
        return Interpreter()

    class State:
        def __init__(self, *_args):
            self.env_vars = {}

        def addEnvironmentVar(self, name, value):
            self.env_vars[name] = value

        def removeEnvironmentVar(self, name):
            self.env_vars.pop(name, None)

    class Script:
        def __init__(self):
            env["load"]()

        def setScriptArgs(self, _args):
            pass

        def execute(self, _state, _controls):
            env["body"]()

    monkeypatch.setattr(
        providers, "provider_for", lambda _runtime: SimpleNamespace(getScriptInstance=lambda *_: Script())
    )
    monkeypatch.setattr(execution, "BoundedCapture", _FakeCapture)
    monitor = SimpleNamespace(finished=lambda: None, didTimeout=lambda: False, isCancelled=lambda: False)

    class ResourceFile:
        def __init__(self, path):
            self.path = str(path)

        def exists(self):
            return os.path.exists(self.path)

    classes = {
        "generic.jar.ResourceFile": ResourceFile,
        "java.io.File": str,
        "ghidra.app.script.GhidraState": State,
        "ghidra.app.script.ScriptControls": lambda *args: object(),
        "ghidra.jython.GhidraJythonInterpreter": SimpleNamespace(get=make_interpreter),
        "ghidra.util.task.TaskMonitor": SimpleNamespace(DUMMY=None),
        "ghidra.util.task.TimeoutTaskMonitor": SimpleNamespace(timeoutIn=lambda *args: monitor),
        "java.util.concurrent.TimeUnit": SimpleNamespace(SECONDS=1),
        "java.lang.management.ManagementFactory": SimpleNamespace(
            getThreadMXBean=lambda: SimpleNamespace(getAllThreadIds=list)
        ),
    }
    monkeypatch.setattr(execution, "_jclass", classes.__getitem__)
    monkeypatch.setattr(
        execution,
        "jpype",
        SimpleNamespace(JArray=lambda _t: list, JString=str, JException=type("JException", (Exception,), {})),
    )
    root = tmp_path / "snap" / "team"
    (root / "sub").mkdir(parents=True)
    env["root"] = root
    return env


@pytest.mark.parametrize("load_fails", [False, True])
def test_execute_script_observes_loading_threads_and_cleans_up_on_failure(fake_execution_env, load_fails):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    env["jython_available"] = True
    source = env["root"] / "Constructor.java"
    source.write_text("// Fake source\n")
    worker, release = _blocked_thread("constructor-python-worker")
    original_start = threading.Thread.start

    def load():
        worker.start()
        if load_fails:
            raise RuntimeError("constructor failure")

    env["load"] = load
    try:
        kwargs = dict(program=object(), project=object(), script_path=str(source), runtime="Java")
        if load_fails:
            with pytest.raises(HeadlessError, match="SCRIPT_LOAD_FAILED") as failed:
                execution.execute_script(**kwargs)
            details = failed.value.details
            assert "constructor failure" in details["exception"]["message"]
        else:
            details = execution.execute_script(**kwargs)
        assert details["stray_threads"] == [execution._python_entry(worker)]
        assert env["interpreter_cleanups"] == 1
        assert threading.Thread.start is original_start
    finally:
        release.set()
        worker.join(5)


def test_execute_script_treats_server_workers_spawned_mid_run_as_ok(fake_execution_env):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    script = env["root"] / "Hello.py"
    script.write_text("# @runtime PyGhidra\n", encoding="utf-8")
    worker, release = _blocked_thread("AnyIO worker thread")
    env["body"] = lambda: worker.start()  # resolved at call time, like a script would
    try:
        result = execution.execute_script(
            program=object(),
            project=object(),
            script_path=str(script),
            runtime="PyGhidra",
            snapshot_roots=[str(env["root"])],
        )
    finally:
        release.set()
    assert result["status"] == "ok"
    assert result["stray_threads"] == []


def test_execute_script_reports_a_thread_the_script_left_running(fake_execution_env):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    script = env["root"] / "Leak.py"
    script.write_text("# @runtime PyGhidra\n", encoding="utf-8")
    worker, release = _blocked_thread("leaked-by-script")
    env["body"] = lambda: worker.start()  # resolved at call time, like a script would
    try:
        result = execution.execute_script(
            program=object(),
            project=object(),
            script_path=str(script),
            runtime="PyGhidra",
            snapshot_roots=[str(env["root"])],
        )
        assert result["status"] == "ok"
        assert [item["name"] for item in result["stray_threads"]] == ["leaked-by-script"]
        assert execution.alive_threads(result["stray_threads"]) == result["stray_threads"]
    finally:
        release.set()
    worker.join(5)
    assert execution.alive_threads(result["stray_threads"]) == []


def test_execute_script_registers_only_roots_never_a_nested_directory(fake_execution_env):
    """root/sub/Foo.java must not become a second, overlapping source bundle."""

    from ghidra_headless.scripts import execution

    env = fake_execution_env
    nested = env["root"] / "sub" / "Foo.java"
    nested.write_text("public class Foo extends GhidraScript {}\n", encoding="utf-8")
    execution.execute_script(
        program=object(), project=object(), script_path=str(nested), runtime="Java", snapshot_roots=[str(env["root"])]
    )
    assert env["registered"] == [str(env["root"])]

    env["registered"].clear()
    inline_dir = env["root"].parent / "inline" / "abc123"
    inline_dir.mkdir(parents=True)
    inline = inline_dir / "Plate.java"
    inline.write_text("public class Plate extends GhidraScript {}\n", encoding="utf-8")
    execution.execute_script(
        program=object(),
        project=object(),
        script_path=str(inline),
        runtime="Java",
        snapshot_roots=[str(env["root"]), str(inline_dir)],
    )
    assert env["registered"] == [str(env["root"]), str(inline_dir)]


def _run_java(env, execution, script, roots):
    return execution.execute_script(
        program=object(), project=object(), script_path=str(script), runtime="Java", snapshot_roots=roots
    )


@pytest.mark.parametrize("nested_child", [False, True])
def test_java_parent_shares_jython_even_without_top_level_python_files(fake_execution_env, nested_child):
    """runScript can load nested children and sources registered during execution."""

    from ghidra_headless.scripts import execution

    env = fake_execution_env
    env["jython_available"] = True
    script = env["root"] / "Only.java"
    script.write_text("public class Only extends GhidraScript {}\n", encoding="utf-8")
    if nested_child:
        (env["root"] / "sub" / "Hidden.py").write_text("# @runtime Jython\n", encoding="utf-8")
    result = _run_java(env, execution, script, [str(env["root"])])
    assert result["status"] == "ok"
    assert env["interpreters"] == 1


def test_shared_jython_interpreter_is_created_when_a_root_holds_a_python_script(fake_execution_env):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    env["jython_available"] = True
    script = env["root"] / "Parent.java"
    script.write_text("public class Parent extends GhidraScript {}\n", encoding="utf-8")
    inline_dir = env["root"].parent / "inline" / "run1"
    inline_dir.mkdir(parents=True)
    (inline_dir / "Child.py").write_text("# @runtime Jython\n", encoding="utf-8")
    # The .py sits in the inline staging root, not the parent's own root.
    result = _run_java(env, execution, script, [str(env["root"]), str(inline_dir)])
    assert result["status"] == "ok"
    assert env["interpreters"] == 1


def test_shared_jython_interpreter_is_created_for_a_jython_run_regardless_of_siblings(fake_execution_env):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    env["jython_available"] = True
    # Simulate a Jython run whose root carries no other .py at all: the
    # script itself is the Jython parent, so the interpreter is still needed.
    script = env["root"] / "Solo.jy"
    script.write_text("# not a .py on purpose\n", encoding="utf-8")
    result = execution.execute_script(
        program=object(), project=object(), script_path=str(script), runtime="Jython", snapshot_roots=[str(env["root"])]
    )
    assert result["status"] == "ok"
    assert env["interpreters"] == 1

    # And never when the extension is missing, whatever the runtime says.
    env["jython_available"] = False
    execution.execute_script(
        program=object(), project=object(), script_path=str(script), runtime="Jython", snapshot_roots=[str(env["root"])]
    )
    assert env["interpreters"] == 1


def test_shared_jython_interpreter_is_reused_across_runs_and_released_at_shutdown(fake_execution_env, monkeypatch):
    from ghidra_headless.scripts import execution

    env = fake_execution_env
    env["jython_available"] = True
    script = env["root"] / "Parent.java"
    script.write_text("public class Parent extends GhidraScript {}\n", encoding="utf-8")
    for _ in range(3):
        assert _run_java(env, execution, script, [str(env["root"])])["status"] == "ok"
    assert env["interpreters"] == 1
    assert env["interpreter_cleanups"] == 0

    # Shutting the script runtimes down disposes it; the next run builds a new one.
    monkeypatch.setattr(providers._state, "bundle_host", None)
    monkeypatch.setattr(providers, "_script_util", lambda: None)
    providers.shutdown()
    assert env["interpreter_cleanups"] == 1
    assert _run_java(env, execution, script, [str(env["root"])])["status"] == "ok"
    assert env["interpreters"] == 2


class _FakeRunContext:
    execution_invalid = None

    def __init__(self):
        self.program = object()
        self.project = object()
        self.decompiler_resets = 0
        self.sentinel_keys = []
        self.invalidations = []

    def reset_decompiler(self):
        self.decompiler_resets += 1

    def arm_transaction_sentinel(self, key):
        self.sentinel_keys.append(key)

    def mark_execution_invalid(self, reason, details):
        self.invalidations.append((reason, details))


@pytest.mark.parametrize(
    "outcome,state,status,revision_after,resets",
    [
        ("unchanged", "valid", "ok", "g:7", 0),
        ("unchanged", "valid", "ok", "g:8", 1),
        ("committed", "valid", "ok", "g:8", 1),
        ("rolled_back", "valid", "ok", "g:7", 1),
        ("unknown", "invalid", "ok", "g:7", 1),
        ("unchanged", "invalid", "ok", "g:7", 1),
        ("unchanged", "valid", "error", "g:7", 1),
    ],
)
def test_run_script_preserves_decompiler_only_on_unchanged_success(
    monkeypatch, tmp_path, outcome, state, status, revision_after, resets
):
    from ghidra_headless.handlers.commands import scripts as scripts_command
    from ghidra_headless.scripts import execution

    ctx = _FakeRunContext()
    revisions = iter(["g:7", revision_after])
    forgotten = []
    monkeypatch.setattr(scripts_command, "program_revision", lambda _ctx: next(revisions))
    monkeypatch.setattr(providers, "unregister_source_root", forgotten.append)
    monkeypatch.setattr(
        execution,
        "run_script_with_transaction",
        lambda **_kwargs: {"transaction_outcome": outcome, "execution_state": state, "status": status},
    )
    params = {"script_path": str(tmp_path / "Inline.java"), "runtime": "Java", "inline": True}
    result = scripts_command.run_script(params, ensure_context=lambda: ctx, current_key=lambda: "key")
    assert result["revision"] == revision_after
    assert result["revision_before"] == "g:7"
    assert ctx.decompiler_resets == resets
    assert forgotten == [str(tmp_path)]
    assert ctx.sentinel_keys == ["key"]


def test_run_script_resets_decompiler_when_revision_cannot_be_read_after_success(monkeypatch, tmp_path):
    from ghidra_headless.handlers.commands import scripts as scripts_command
    from ghidra_headless.scripts import execution

    ctx = _FakeRunContext()
    reads = []

    def revision(_ctx):
        reads.append(True)
        if len(reads) > 1:
            raise RuntimeError("program closed")
        return "g:7"

    monkeypatch.setattr(scripts_command, "program_revision", revision)
    monkeypatch.setattr(
        execution,
        "run_script_with_transaction",
        lambda **_kwargs: {"transaction_outcome": "unchanged", "execution_state": "valid", "status": "ok"},
    )
    params = {"script_path": str(tmp_path / "Read.java"), "runtime": "Java"}
    with pytest.raises(RuntimeError, match="program closed"):
        scripts_command.run_script(params, ensure_context=lambda: ctx, current_key=lambda: "key")
    assert ctx.decompiler_resets == 1
    assert ctx.sentinel_keys == ["key"]


def test_run_script_command_cleans_up_when_the_run_raises_a_plain_exception(monkeypatch, tmp_path):
    """A TerminatedTransactionException (not a HeadlessError) must still drop the inline bundle and arm the sentinel."""

    from ghidra_headless.handlers.commands import scripts as scripts_command
    from ghidra_headless.scripts import execution

    forgotten = []
    monkeypatch.setattr(providers, "unregister_source_root", lambda directory: forgotten.append(directory) or True)
    monkeypatch.setattr(scripts_command, "program_revision", lambda _ctx: 7)

    def boom(**_kwargs):
        raise RuntimeError("java.lang.IllegalStateException: transaction terminated")

    monkeypatch.setattr(execution, "run_script_with_transaction", boom)
    ctx = _FakeRunContext()
    inline_dir = tmp_path / "inline" / "run1"
    inline_dir.mkdir(parents=True)
    params = {"script_path": str(inline_dir / "Plate.java"), "runtime": "Java", "inline": True}
    with pytest.raises(RuntimeError, match="transaction terminated"):
        scripts_command.run_script(params, ensure_context=lambda: ctx, current_key=lambda: "key-1")
    assert forgotten == [str(inline_dir)]
    assert ctx.sentinel_keys == ["key-1"]
    assert ctx.decompiler_resets == 1
    assert ctx.invalidations == []


def test_run_script_command_cleanup_failure_does_not_mask_the_run_error(monkeypatch, tmp_path):
    from ghidra_headless.handlers.commands import scripts as scripts_command
    from ghidra_headless.scripts import execution

    def refuse(_directory):
        raise OSError("bundle host gone")

    monkeypatch.setattr(providers, "unregister_source_root", refuse)
    monkeypatch.setattr(scripts_command, "program_revision", lambda _ctx: 7)

    def fail(**_kwargs):
        raise HeadlessError(
            "SCRIPT_FAILED: boom",
            details={"execution_state": "invalid", "transaction_outcome": "unknown"},
        )

    monkeypatch.setattr(execution, "run_script_with_transaction", fail)
    ctx = _FakeRunContext()
    ctx.reset_decompiler = lambda: (_ for _ in ()).throw(RuntimeError("decompiler gone"))
    params = {"script_path": str(tmp_path / "inline" / "Plate.java"), "runtime": "Java", "inline": True}
    with pytest.raises(HeadlessError, match="SCRIPT_FAILED"):
        scripts_command.run_script(params, ensure_context=lambda: ctx, current_key=lambda: "key-2")
    # Quarantine still happens in the HeadlessError branch, and the sentinel is armed
    # even though the decompiler reset and the bundle cleanup both failed.
    assert ctx.invalidations[0][0] == "script_run"
    assert ctx.sentinel_keys == ["key-2"]


def test_source_roots_for_script_falls_back_to_its_directory_outside_every_root(tmp_path):
    from ghidra_headless.scripts import execution

    root = tmp_path / "root"
    outside = tmp_path / "elsewhere" / "Probe.py"
    assert execution.source_roots_for(str(outside), [str(root)]) == [str(root), str(outside.parent)]
    assert execution.source_roots_for(str(root / "sub" / "X.java"), [str(root)]) == [str(root)]
    assert execution.bundle_root_for(str(root / "sub" / "X.java"), [str(root)]) == str(root)
    assert execution.bundle_root_for(str(outside), [str(root)]) == str(outside.parent)


# ---- providers (fix 4) -------------------------------------------------------


def test_jython_stub_detection_uses_isinstance_and_tolerates_a_missing_class(monkeypatch):
    class JythonStubScriptProvider:
        def getRuntimeEnvironmentName(self):
            return "Jython"

    class JythonScriptProvider:
        def getRuntimeEnvironmentName(self):
            return "Jython"

    class RenamedStub(JythonStubScriptProvider):
        """Subclass of the stub: a class-name compare would miss it, isinstance does not."""

    def jclass(name):
        if name == "ghidra.app.script.JythonStubScriptProvider":
            return JythonStubScriptProvider
        raise TypeError(f"Class {name} is not found")

    monkeypatch.setattr(providers._state, "providers", None)
    monkeypatch.setattr(providers.jpype, "JClass", jclass)
    monkeypatch.setattr(
        providers, "_script_util", lambda: SimpleNamespace(getProviders=lambda: [RenamedStub(), JythonScriptProvider()])
    )
    assert type(providers.index_providers(refresh=True)["Jython"]) is JythonScriptProvider

    # Without the stub class on the classpath, indexing still works and nothing is skipped.
    monkeypatch.setattr(providers.jpype, "JClass", lambda name: (_ for _ in ()).throw(TypeError(name)))
    monkeypatch.setattr(
        providers, "_script_util", lambda: SimpleNamespace(getProviders=lambda: [JythonScriptProvider()])
    )
    assert type(providers.index_providers(refresh=True)["Jython"]) is JythonScriptProvider


def test_bundle_lookups_use_the_silent_getGhidraBundle(monkeypatch):
    calls = []

    class Host:
        def getGhidraBundle(self, root):
            calls.append(("getGhidraBundle", root))
            return None

        def getExistingGhidraBundle(self, root):
            raise AssertionError("getExistingGhidraBundle logs Msg.showError when the bundle is absent")

        def add(self, root, enabled, system):
            calls.append(("add", root, enabled, system))
            return "bundle"

    monkeypatch.setattr(providers, "ensure_bundle_host", Host)
    monkeypatch.setattr(providers.jpype, "JClass", lambda name: str)
    monkeypatch.setattr(providers._state, "registered_roots", set())
    assert providers.register_source_root("/snap/team") == "bundle"
    assert providers.unregister_source_root("/snap/inline/x") is False
    assert providers.source_bundle_for("/snap/team") is None
    assert [call[0] for call in calls] == ["getGhidraBundle", "add", "getGhidraBundle", "getGhidraBundle"]
