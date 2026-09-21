"""Real-Ghidra validation of the scripts tool category (all three runtimes, catalog and inline source).

Run with::

    GHIDRA_RUNTIME_VALIDATION=1 GHIDRA_INSTALL_DIR=... uv run pytest tests/test_runtime_script_commands.py -s
"""

from __future__ import annotations

import contextlib
import itertools
import os
import shutil
import sys
import uuid
from pathlib import Path

import jpype
import pyghidra
import pytest

from cli_support import ToolHarness
from ghidra_headless.launcher import start_headless_jvm
from ghidra_mcp import cli
from ghidra_mcp.application.services.script_service import ScriptConfig
from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()

RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_BINARY = ROOT / "samples" / "hello.bin"


def _cross_runtime_source(runtime, name, body):
    if runtime == "Java":
        return (
            "import ghidra.app.script.GhidraScript;\n"
            f"public class {name} extends GhidraScript {{ public void run() throws Exception {{\n{body}\n}} }}\n"
        )
    return f"# @runtime {runtime}\n{body}\n"


def _cross_runtime_edit(runtime, text):
    return f'setPlateComment(currentProgram.getMinAddress(), "{text}")' + (";" if runtime == "Java" else "")


@pytest.mark.parametrize(
    "parent_runtime,child_runtime,outcome",
    list(
        itertools.product(
            ["Java", "PyGhidra", "Jython"], ["Java", "PyGhidra", "Jython"], ["success", "caught", "uncaught"]
        )
    ),
)
def test_runtime_cross_language_child_output_and_rollback(tmp_path, parent_runtime, child_runtime, outcome):
    parent_file = "CrossParent" + (".java" if parent_runtime == "Java" else ".py")
    child_file = "CrossChild" + (".java" if child_runtime == "Java" else ".py")
    # Use each runtime's script output streams. CPython sys.stderr is the
    # server's process stream; Jython's interpreter owns its sys.stderr.
    output = {
        "Java": '\nprintln("CHILD_EXECUTED");\nprinterr("CHILD_STDERR");',
        "PyGhidra": '\nprint("CHILD_EXECUTED")\nprinterr("CHILD_STDERR")',
        "Jython": '\nprint("CHILD_EXECUTED")\nimport sys\nsys.stderr.write("CHILD_STDERR\\n")',
    }
    child = _cross_runtime_edit(child_runtime, "CHILD_EDIT") + output[child_runtime]
    if outcome != "success":
        child += (
            '\nthrow new RuntimeException("CROSS_CHILD_FAILURE");'
            if child_runtime == "Java"
            else '\nraise RuntimeError("CROSS_CHILD_FAILURE")'
        )
    call = f'runScript("{child_file}")' + (";" if parent_runtime == "Java" else "")
    if outcome == "caught":
        if parent_runtime == "Java":
            call = f'try {{ {call} }} catch (Exception e) {{ println("CHILD_HANDLED"); }}'
        else:
            call = (
                "from java.lang import Exception as JavaException\n"
                f'try:\n    {call}\nexcept (Exception, JavaException):\n    println("CHILD_HANDLED")'
            )
    parent = (
        _cross_runtime_edit(parent_runtime, "PARENT_BEFORE")
        + "\n"
        + call
        + "\n"
        + _cross_runtime_edit(parent_runtime, "PARENT_AFTER")
    )
    sources = {
        parent_file: _cross_runtime_source(parent_runtime, "CrossParent", parent),
        child_file: _cross_runtime_source(child_runtime, "CrossChild", child),
    }
    with _nested_script_project(tmp_path, sources) as (target, address):
        available = _runtimes()
        if not available[parent_runtime] or not available[child_runtime]:
            pytest.skip("requires the Jython extension")
        cli_tools.apply_edits(
            target=target,
            edits=[{"kind": "set_comment", "address": address, "comment": "BASELINE", "comment_type": "plate"}],
        )
        if outcome == "uncaught":
            with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
                _run(target, script_id="t:" + parent_file)
            details = _domain_error(failed.value)["details"]
            assert "sha256" not in details
            assert details["transaction_outcome"] == "rolled_back"
            assert "CHILD_EXECUTED" in details["stdout"]["text"]
            assert "CHILD_STDERR" in details["stderr"]["text"]
            assert _plate(target, address) == "BASELINE"
        else:
            result = _run(target, script_id="t:" + parent_file)
            assert "sha256" not in result
            assert result["transaction_outcome"] == "committed"
            assert result["error"] is None
            assert "CHILD_EXECUTED" in result["stdout"]["text"]
            assert "CHILD_STDERR" in result["stderr"]["text"]
            if outcome == "caught":
                assert "CHILD_HANDLED" in result["stdout"]["text"]
            assert _plate(target, address) == "PARENT_AFTER"


@pytest.mark.parametrize("warmup", [False, True])
@pytest.mark.parametrize("outcome", ["success", "caught", "uncaught"])
def test_java_parent_nested_jython_output_and_transaction(tmp_path, warmup, outcome):
    child = (
        _cross_runtime_edit("Jython", "CHILD_EDIT")
        + '\nprint("NESTED_CHILD_EXECUTED")\nimport sys\nsys.stderr.write("NESTED_CHILD_STDERR\\n")'
    )
    if outcome != "success":
        child += '\nraise RuntimeError("NESTED_CHILD_FAILURE")'
    call = 'runScript("sub/NestedChild.py");'
    if outcome == "caught":
        call = f'try {{ {call} }} catch (Exception e) {{ println("CHILD_HANDLED"); }}'
    parent = (
        _cross_runtime_edit("Java", "PARENT_BEFORE") + "\n" + call + "\n" + _cross_runtime_edit("Java", "PARENT_AFTER")
    )
    sources = {
        "NestedParent.java": _cross_runtime_source("Java", "NestedParent", parent),
        "sub/NestedChild.py": _cross_runtime_source("Jython", "NestedChild", child),
    }
    with _nested_script_project(tmp_path, sources) as (target, address):
        if not _runtimes()["Jython"]:
            pytest.skip("requires the Jython extension")
        if warmup:
            _run(target, source='print("JYTHON_WARMUP")', runtime="Jython")
        cli_tools.apply_edits(
            target=target,
            edits=[{"kind": "set_comment", "address": address, "comment": "BASELINE", "comment_type": "plate"}],
        )
        if outcome == "uncaught":
            with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
                _run(target, script_id="t:NestedParent.java")
            result = _domain_error(failed.value)["details"]
            assert result["transaction_outcome"] == "rolled_back"
            assert "NESTED_CHILD_FAILURE" in result["error"]["message"]
            assert _plate(target, address) == "BASELINE"
        else:
            result = _run(target, script_id="t:NestedParent.java")
            assert result["status"] == "ok"
            assert result["transaction_outcome"] == "committed"
            assert result["error"] is None
            assert _plate(target, address) == "PARENT_AFTER"
            if outcome == "caught":
                assert "CHILD_HANDLED" in result["stdout"]["text"]
        assert result["execution_state"] == "valid"
        assert "NESTED_CHILD_EXECUTED" in result["stdout"]["text"]
        assert "NESTED_CHILD_STDERR" in result["stderr"]["text"]


@pytest.mark.parametrize("expression,success", [("None", True), ("0", True), ("3", False), ('"failure"', False)])
def test_runtime_upstream_pyghidra_system_exit(tmp_path, expression, success):
    with _nested_script_project(tmp_path, {}) as (target, address):
        before = _plate(target, address)
        source = _cross_runtime_edit("PyGhidra", "EXIT_VALIDATION") + f"\nimport sys\nsys.exit({expression})"
        if success:
            result = _run(target, source=source, runtime="PyGhidra")
            assert result["transaction_outcome"] == "committed"
            assert _plate(target, address) == "EXIT_VALIDATION"
        else:
            with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
                _run(target, source=source, runtime="PyGhidra")
            assert _domain_error(failed.value)["details"]["transaction_outcome"] == "rolled_back"
            assert _plate(target, address) == before


def test_runtime_upstream_pyghidra_interrupt_restores_python_state(tmp_path):
    with _nested_script_project(tmp_path, {}) as (target, address):
        before = _plate(target, address)
        argv, path = list(sys.argv), list(sys.path)
        source = (
            _cross_runtime_edit("PyGhidra", "INTERRUPTED")
            + '\nimport sys, types\nsys.modules["mecha_ephemeral_test"] = types.ModuleType("mecha_ephemeral_test")'
            + '\nraise KeyboardInterrupt("expected interrupt")'
        )
        with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
            _run(target, source=source, runtime="PyGhidra")
        assert _domain_error(failed.value)["details"]["transaction_outcome"] == "rolled_back"
        assert _plate(target, address) == before
        assert sys.argv == argv and sys.path == path
        assert "mecha_ephemeral_test" not in sys.modules


def test_runtime_upstream_pyghidra_timeout_rolls_back_and_recovers(tmp_path):
    with _nested_script_project(tmp_path, {}) as (target, address):
        before = _plate(target, address)
        source = (
            _cross_runtime_edit("PyGhidra", "TIMED_OUT")
            + "\nfrom java.lang import Thread\nwhile True:\n    monitor.checkCancelled()\n    Thread.sleep(10)"
        )
        with pytest.raises(Exception, match="SCRIPT_TIMEOUT") as failed:
            _run(target, source=source, runtime="PyGhidra", timeout_seconds=1)
        assert _domain_error(failed.value)["details"]["transaction_outcome"] == "rolled_back"
        assert _plate(target, address) == before
        result = _run(target, source=_cross_runtime_edit("PyGhidra", "RECOVERED"), runtime="PyGhidra")
        assert result["transaction_outcome"] == "committed"
        assert _plate(target, address) == "RECOVERED"


JAVA_ADD_PLATE = """// Adds a plate comment at the program's minimum address.
// @category MechaTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;

public class AddPlate extends GhidraScript {
    @Override
    public void run() throws Exception {
        String text = getScriptArgs().length > 0 ? getScriptArgs()[0] : "plate";
        currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, text);
        println("added " + text);
    }
}
"""

JAVA_FAIL = """// Edits then fails.
// @category MechaTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;

public class FailAfterEdit extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "FAIL");
        printerr("about to fail");
        throw new RuntimeException("boom from java");
    }
}
"""

JAVA_LEAK = """// Leaves a nested transaction open.
// @category MechaTest
import ghidra.app.script.GhidraScript;

public class LeakTransaction extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.startTransaction("leaked by script");
        println("leaked");
    }
}
"""

JAVA_SLEEP = """// Cooperative infinite loop.
// @category MechaTest
import ghidra.app.script.GhidraScript;

public class Sleepy extends GhidraScript {
    @Override
    public void run() throws Exception {
        while (true) {
            monitor.checkCancelled();
            Thread.sleep(50);
        }
    }
}
"""

JAVA_BUSY = """// Non-cooperative infinite loop (never checks the monitor).
// @category MechaTest
import ghidra.app.script.GhidraScript;

public class BusyLoop extends GhidraScript {
    @Override
    public void run() throws Exception {
        long counter = 0;
        while (true) {
            counter++;
            if (counter == Long.MAX_VALUE) {
                counter = 0;
            }
        }
    }
}
"""

JAVA_BROKEN = """// Does not compile.
// @category MechaTest
import ghidra.app.script.GhidraScript;

public class Broken extends GhidraScript {
    @Override
    public void run() throws Exception {
        this is not java
    }
}
"""

PYGHIDRA_ADD_PLATE = """# Adds a plate comment (PyGhidra).
# @category MechaTest
# @runtime PyGhidra
import sys
from ghidra.program.model.listing import CommentType

text = sys.argv[1] if len(sys.argv) > 1 else "plate"
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, text)
print("added", text)
"""

PYGHIDRA_FAIL = """# Edits then fails (PyGhidra).
# @runtime PyGhidra
from ghidra.program.model.listing import CommentType

currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "PYFAIL")
raise RuntimeError("boom from pyghidra")
"""

PYGHIDRA_EXIT0 = """# Edits then exits 0 (PyGhidra).
# @runtime PyGhidra
import sys
from ghidra.program.model.listing import CommentType

currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "EXIT0")
sys.exit(0)
"""

PYGHIDRA_EXIT3 = """# Edits then exits 3 (PyGhidra).
# @runtime PyGhidra
import sys
from ghidra.program.model.listing import CommentType

currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "EXIT3")
sys.exit(3)
"""

JYTHON_ADD_PLATE = """# Adds a plate comment (Jython).
# @category MechaTest
# @runtime Jython
from ghidra.program.model.listing import CommentType

text = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "plate"
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, text)
print "added " + text
"""

JYTHON_FAIL = """# Edits then fails (Jython).
# @runtime Jython
from ghidra.program.model.listing import CommentType

currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "JYFAIL")
raise RuntimeError("boom from jython")
"""

SCRIPTS = {
    "AddPlate.java": JAVA_ADD_PLATE,
    "FailAfterEdit.java": JAVA_FAIL,
    "LeakTransaction.java": JAVA_LEAK,
    "Sleepy.java": JAVA_SLEEP,
    "BusyLoop.java": JAVA_BUSY,
    "Broken.java": JAVA_BROKEN,
    "add_plate_py.py": PYGHIDRA_ADD_PLATE,
    "fail_py.py": PYGHIDRA_FAIL,
    "exit0_py.py": PYGHIDRA_EXIT0,
    "exit3_py.py": PYGHIDRA_EXIT3,
    "add_plate_jy.py": JYTHON_ADD_PLATE,
    "fail_jy.py": JYTHON_FAIL,
}


def _resolve_ghidra_install_dir() -> str:
    explicit = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [explicit]
    candidates.extend(str(path) for path in sorted((Path.home() / "ghidra").glob("ghidra_*_PUBLIC"), reverse=True))
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    pytest.fail("Cannot continue runtime tests because GHIDRA_INSTALL_DIR was not found")


def _start_pyghidra_if_needed() -> str:
    install_dir = _resolve_ghidra_install_dir()
    os.environ["GHIDRA_INSTALL_DIR"] = install_dir
    if not pyghidra.started():
        if shutil.which("java") is None:
            pytest.fail("java command not found (required for runtime tests)")
        start_headless_jvm(install_dir)
    return install_dir


def _ensure_project_created(project_dir: Path, project_name: str) -> None:
    if (project_dir / f"{project_name}.gpr").exists():
        return
    project_dir.mkdir(parents=True, exist_ok=True)
    ghidra_project = jpype.JClass("ghidra.base.project.GhidraProject")
    project = ghidra_project.createProject(str(project_dir), project_name, False)
    project.close()


def _write_scripts(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in SCRIPTS.items():
        (root / name).write_text(text, encoding="utf-8")


def _registry_with_scripts(tmp_path: Path, *, root: Path, install_dir: str):
    specs = filter_tool_specs(profile=ToolProfile.FULL)
    config = ScriptConfig(roots=(("t", root),), snapshot_base=tmp_path / "snap", ghidra_install_dir=Path(install_dir))
    registry = cli_tools.configure(specs, script_config=config)
    cli_tools.app.script_service.initialize()
    cli._prepare_script_runtime(cli_tools.app.script_service)
    return registry


def _domain_error(exc: Exception) -> dict:
    payload = getattr(exc, "domain_error", None)
    assert payload is not None, f"no domain_error on {exc!r}"
    print(f"[runtime] domain_error: {payload}")
    return payload


def _run(target: str, **kwargs):
    try:
        return cli_tools.run_script(target=target, **kwargs)
    except Exception as exc:  # noqa: BLE001 - re-raised after logging the details
        print(f"[runtime] run_script failed: {exc}: {getattr(exc, 'domain_error', None)}")
        cause = exc.__cause__ or exc.__context__
        if cause is not None and not str(cause).startswith(("SCRIPT_", "PROJECT_", "TARGET_", "OPERATION_")):
            import traceback

            print("".join(traceback.format_exception(type(cause), cause, cause.__traceback__))[-3000:])
        raise


def _plate(target: str, address: str):
    return cli_tools.get_comments(address=address, target=target)["plate"]


def _load_sample(target: str, project_dir: Path, project_name: str) -> str:
    cli_tools.register_target(target=target, project_location=str(project_dir), project_name=project_name)
    imported = cli_tools.import_program(target=target, binary_path=str(SAMPLE_BINARY))
    domain_path = imported["program"]
    cli_tools.load_project_program(target=target, domain_path=domain_path)
    return domain_path


def _release_script_runtime() -> None:
    from ghidra_headless.scripts import providers

    providers.shutdown()


def _runtimes() -> dict[str, bool]:
    from ghidra_headless.scripts import providers

    available = providers.runtime_availability()
    if os.environ.get("GHIDRA_JYTHON_RUNTIME_VALIDATION") == "1":
        assert available["Jython"], "Jython validation requested, but its Ghidra extension is not loaded"
    return available


@contextlib.contextmanager
def _nested_script_project(tmp_path: Path, sources: dict[str, str]):
    install_dir = _start_pyghidra_if_needed()
    root = tmp_path / "scripts"
    root.mkdir(parents=True, exist_ok=True)
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    project_dir = tmp_path / "proj"
    _ensure_project_created(project_dir, "nested")
    registry = _registry_with_scripts(tmp_path, root=root, install_dir=install_dir)
    try:
        target = f"nested_{uuid.uuid4().hex[:6]}"
        _load_sample(target, project_dir, "nested")
        yield target, cli_tools.get_program_info(target=target)["min_address"]
    finally:
        try:
            registry.close_all()
        finally:
            cli_tools.app.script_service.shutdown()
            _release_script_runtime()


@pytest.mark.parametrize("holder", ["reader", "writer"])
def test_runtime_queued_script_times_out_without_executing_and_can_be_retried(tmp_path, holder):
    import threading

    from ghidra_mcp.application.locks import SCRIPT_BARRIER
    from ghidra_mcp.domain import configure_script_queue_timeout_seconds, get_script_queue_timeout_seconds

    source = '# @runtime PyGhidra\nsetPlateComment(currentProgram.getMinAddress(), "RETRY_SUCCEEDED")\n'
    with _nested_script_project(tmp_path, {}) as (target, address):
        # Cache provider availability before another operation owns the barrier:
        # the queued request must time out at the execution writer itself.
        cli_tools.app.script_service.list_scripts()
        before = _plate(target, address)
        done = threading.Event()
        results = []
        errors = []

        def run():
            try:
                results.append(_run(target, source=source))
            except Exception as exc:
                errors.append(exc)
            finally:
                done.set()

        thread = threading.Thread(target=run, name="AnyIO worker thread", daemon=True)
        original_timeout = get_script_queue_timeout_seconds()
        configure_script_queue_timeout_seconds(0.05)
        try:
            held_lock = SCRIPT_BARRIER.read_lock() if holder == "reader" else SCRIPT_BARRIER.write_lock()
            with held_lock:
                thread.start()
                assert done.wait(2), "queued script ignored the configured lock timeout"
            thread.join(5)
            assert not thread.is_alive()
            assert results == []
            assert len(errors) == 1
            error = _domain_error(errors[0])
            assert error["code"] == "LOCK_TIMEOUT"
            assert error["retryable"] is True
            assert error["details"]["lock"] == "script_barrier"
            assert _plate(target, address) == before
            assert list((cli_tools.app.script_service.snapshot_base / "inline").iterdir()) == []
            result = _run(target, source=source)
            assert result["transaction_outcome"] == "committed"
            assert _plate(target, address) == "RETRY_SUCCEEDED"
        finally:
            configure_script_queue_timeout_seconds(original_timeout)
            thread.join(5)


@pytest.mark.parametrize("inline", [False, True])
def test_runtime_snapshot_still_isolates_parent_and_child_from_operator_edits(tmp_path, inline):
    parent = '# @runtime PyGhidra\nrunScript("sub/SnapshotChild.py")\n'
    child = '# @runtime PyGhidra\nsetPlateComment(currentProgram.getMinAddress(), "SNAPSHOT_CHILD")\n'
    with _nested_script_project(tmp_path, {"SnapshotParent.py": parent, "sub/SnapshotChild.py": child}) as (
        target,
        address,
    ):
        # These edits affect only the operator's original files, after startup copied them.
        changed = '# @runtime PyGhidra\nraise RuntimeError("SOURCE_DIRECTORY_WAS_USED")\n'
        (tmp_path / "scripts" / "SnapshotParent.py").write_text(changed)
        (tmp_path / "scripts" / "sub" / "SnapshotChild.py").write_text(changed)
        info = cli_tools.get_script_info(script_id="t:SnapshotParent.py", include_source=True)
        assert info["source"] == parent
        assert "sha256" not in info
        assert info["catalog_revision"]
        revision = cli_tools.get_program_info(target=target)["revision"]
        kwargs = {"source": parent} if inline else {"script_id": "t:SnapshotParent.py"}
        result = _run(target, **kwargs, expected_revision=revision)
        assert result["transaction_outcome"] == "committed"
        assert "sha256" not in result
        assert _plate(target, address) == "SNAPSHOT_CHILD"
        with pytest.raises(Exception, match="SESSION_CHANGED"):
            _run(target, **kwargs, expected_revision=revision)


@pytest.mark.parametrize("runtime", ["PyGhidra", "Jython"])
def test_runtime_python_subscript_without_prior_java_run(tmp_path, runtime):
    child = JYTHON_ADD_PLATE if runtime == "Jython" else PYGHIDRA_ADD_PLATE
    parent = f'# @runtime {runtime}\nrunScript("NestedChild.py")\n'
    # Only the root is a source bundle (as in the Script Manager); runScript resolves the child through it.
    sources = {"NestedParent.py": parent, "NestedChild.py": child}
    with _nested_script_project(tmp_path, sources) as (target, address):
        if not _runtimes().get(runtime):
            pytest.skip(f"{runtime} runtime not installed")
        for _ in range(2):
            result = _run(target, script_id="t:NestedParent.py")
            assert result["status"] == "ok"
            assert "added plate" in result["stdout"]["text"]
            assert _plate(target, address) == "plate"


@pytest.mark.parametrize("parent_runtime", ["PyGhidra", "Java", "Jython"])
def test_runtime_handled_python_subscript_exception_keeps_parent_edits(tmp_path, parent_runtime):
    if parent_runtime in {"PyGhidra", "Jython"}:
        parent_name = "HandleChild.py"
        parent = f"""# @runtime {parent_runtime}
from ghidra.program.model.listing import CommentType
try:
    runScript("NestedFailure.py")
except Exception:
    print("handled child error")
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "RECOVERED")
"""
    else:
        parent_name = "HandleChild.java"
        parent = """import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
public class HandleChild extends GhidraScript {
    public void run() throws Exception {
        try {
            runScript("NestedFailure.py");
        } catch (Exception e) {
            println("handled child error");
        }
        currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "RECOVERED");
    }
}
"""
    child = JYTHON_FAIL if parent_runtime == "Jython" else PYGHIDRA_FAIL
    with _nested_script_project(tmp_path, {parent_name: parent, "NestedFailure.py": child}) as (
        target,
        address,
    ):
        if not _runtimes().get(parent_runtime):
            pytest.skip(f"{parent_runtime} runtime not installed")
        result = _run(target, script_id=f"t:{parent_name}")
        assert result["transaction_outcome"] == "committed"
        assert result["error"] is None
        assert "handled child error" in result["stdout"]["text"]
        assert _plate(target, address) == "RECOVERED"


@pytest.mark.parametrize("runtime", ["PyGhidra", "Jython"])
def test_runtime_unhandled_python_subscript_exception_rolls_back(tmp_path, runtime):
    parent = f'# @runtime {runtime}\nrunScript("NestedFailure.py")\n'
    child = JYTHON_FAIL if runtime == "Jython" else PYGHIDRA_FAIL
    with _nested_script_project(tmp_path, {"Unhandled.py": parent, "NestedFailure.py": child}) as (
        target,
        address,
    ):
        if not _runtimes().get(runtime):
            pytest.skip(f"{runtime} runtime not installed")
        before = _plate(target, address)
        with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
            _run(target, script_id="t:Unhandled.py")
        details = _domain_error(failed.value)["details"]
        assert details["transaction_outcome"] == "rolled_back"
        assert f"boom from {runtime.lower()}" in details["error"]["message"]
        assert _plate(target, address) == before


def test_runtime_jython_cooperative_timeout_rolls_back_and_allows_next_script(tmp_path):
    source = """# @runtime Jython
from java.lang import Thread
from ghidra.program.model.listing import CommentType
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "TIMEOUT")
while True:
    monitor.checkCancelled()
    Thread.sleep(10)
"""
    with _nested_script_project(tmp_path, {"Timeout.py": source, "Success.py": JYTHON_ADD_PLATE}) as (
        target,
        address,
    ):
        if not _runtimes()["Jython"]:
            pytest.skip("Jython runtime not installed")
        before = _plate(target, address)
        with pytest.raises(Exception, match="SCRIPT_TIMEOUT") as failed:
            _run(target, script_id="t:Timeout.py", timeout_seconds=1)
        details = _domain_error(failed.value)["details"]
        assert details["timed_out"] is True
        assert details["transaction_outcome"] == "rolled_back"
        assert details["execution_state"] == "valid"
        assert _plate(target, address) == before
        recovered = _run(target, script_id="t:Success.py", args=["recovered"])
        assert recovered["transaction_outcome"] == "committed"
        assert _plate(target, address) == "recovered"


@pytest.mark.parametrize(
    ("expression", "exit_code", "success"),
    [
        ("None", None, True),
        ("0", 0, True),
        ("3", 3, False),
        ("False", 0, True),
        ("True", 1, False),
        ("0L", 0, True),
        ("1099511627776L", 1099511627776, False),
        ("'0'", "0", False),
        ("'failure'", "failure", False),
    ],
)
def test_runtime_jython_system_exit_preserves_transaction_semantics(tmp_path, expression, exit_code, success):
    source = f"""# @runtime Jython
import sys
from ghidra.program.model.listing import CommentType
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "EXIT")
sys.exit({expression})
"""
    with _nested_script_project(tmp_path, {"Exit.py": source}) as (target, address):
        if not _runtimes()["Jython"]:
            pytest.skip("Jython runtime not installed")
        before = _plate(target, address)
        if success:
            result = _run(target, script_id="t:Exit.py")
            assert result["transaction_outcome"] == "committed"
            assert result["error"] is None
            assert _plate(target, address) == "EXIT"
        else:
            with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
                _run(target, script_id="t:Exit.py")
            details = _domain_error(failed.value)["details"]
            assert details["transaction_outcome"] == "rolled_back"
            assert details["error"]["kind"] == "jython"
            assert details["error"]["exit_code"] == exit_code
            assert _plate(target, address) == before


def test_runtime_scripts(tmp_path):
    install_dir = _start_pyghidra_if_needed()
    root = tmp_path / "scripts"
    _write_scripts(root)
    project_dir = tmp_path / "proj"
    project_name = "scripts_inprocess"
    _ensure_project_created(project_dir, project_name)
    _registry_with_scripts(tmp_path, root=root, install_dir=install_dir)
    runtimes = _runtimes()
    print(f"[runtime] script runtimes: {runtimes}")
    target = f"scripts_ip_{uuid.uuid4().hex[:6]}"
    try:
        domain_path = _load_sample(target, project_dir, project_name)
        info = cli_tools.get_program_info(target=target)
        address = info["min_address"]

        listing = cli_tools.list_scripts(limit=100)
        ids = {item["script_id"] for item in listing["items"]}
        assert {"t:AddPlate.java", "t:add_plate_py.py", "t:add_plate_jy.py"} <= ids
        jython_entry = next(item for item in listing["items"] if item["script_id"] == "t:add_plate_jy.py")
        assert jython_entry["available"] is runtimes["Jython"]
        if not runtimes["Jython"]:
            assert jython_entry["unavailable_reason"] == "runtime_unavailable:Jython"
        detail = cli_tools.get_script_info(script_id="t:AddPlate.java", include_source=True)
        assert detail["runtime"] == "Java"
        assert "AddPlate" in detail["source"]

        # --- Java ---
        result = _run(target, script_id="AddPlate", args=["JAVA"])
        print(f"[runtime] java ok: {result['transaction_outcome']} stdout={result['stdout']['text']!r}")
        assert result["transaction_outcome"] == "committed"
        assert "added JAVA" in result["stdout"]["text"]
        assert _plate(target, address) == "JAVA"
        # Saving a script's edits (and editing afterwards) is normal use, not a stray transaction.
        assert cli_tools.save_project_program(target=target)["saved"] is True
        cli_tools.apply_edits(
            target=target,
            edits=[{"kind": "set_comment", "address": address, "comment": "after save", "comment_type": "eol"}],
        )
        cli_tools.save_project_program(target=target)

        with pytest.raises(Exception, match="SCRIPT_FAILED") as failed:
            _run(target, script_id="FailAfterEdit")
        payload = _domain_error(failed.value)
        assert payload["details"]["transaction_outcome"] == "rolled_back"
        assert "boom from java" in payload["details"]["error"]["message"]
        assert _plate(target, address) == "JAVA", "failed script's edit must be rolled back"

        with pytest.raises(Exception, match="SCRIPT_COMPILE_FAILED"):
            _run(target, script_id="Broken")

        with pytest.raises(Exception, match="SCRIPT_TIMEOUT") as timed_out:
            _run(target, script_id="Sleepy", timeout_seconds=2)
        assert _domain_error(timed_out.value)["details"]["transaction_outcome"] == "rolled_back"

        # --- PyGhidra ---
        if runtimes.get("PyGhidra"):
            result = _run(target, script_id="t:add_plate_py.py", args=["PY"])
            assert result["transaction_outcome"] == "committed"
            assert "added PY" in result["stdout"]["text"]
            assert _plate(target, address) == "PY"
            with pytest.raises(Exception, match="SCRIPT_FAILED") as py_failed:
                _run(target, script_id="t:fail_py.py")
            assert _domain_error(py_failed.value)["details"]["transaction_outcome"] == "rolled_back"
            assert _plate(target, address) == "PY", "PyGhidra exception must propagate and roll back"
            result = _run(target, script_id="t:exit0_py.py")
            assert result["transaction_outcome"] == "committed"
            assert _plate(target, address) == "EXIT0"
            with pytest.raises(Exception, match="SCRIPT_FAILED"):
                _run(target, script_id="t:exit3_py.py")
            assert _plate(target, address) == "EXIT0"

        # --- Jython ---
        if runtimes.get("Jython"):
            result = _run(target, script_id="t:add_plate_jy.py", args=["JY"])
            print(f"[runtime] jython ok: stdout={result['stdout']['text']!r}")
            assert result["transaction_outcome"] == "committed"
            assert _plate(target, address) == "JY"
            with pytest.raises(Exception, match="SCRIPT_FAILED") as jy_failed:
                _run(target, script_id="t:fail_jy.py")
            assert _domain_error(jy_failed.value)["details"]["transaction_outcome"] == "rolled_back"
            assert _plate(target, address) == "JY", "Jython exception must propagate and roll back"
        else:
            with pytest.raises(Exception, match="SCRIPT_RUNTIME_UNAVAILABLE"):
                _run(target, script_id="t:add_plate_jy.py")

        # --- leaked transaction -> quarantine -> discard-close recovery ---
        with pytest.raises(Exception, match="SCRIPT_FAILED") as leaked:
            _run(target, script_id="LeakTransaction")
        leak_details = _domain_error(leaked.value)["details"]
        assert leak_details["execution_state"] == "invalid"
        assert leak_details["transaction_outcome"] == "unknown"
        with pytest.raises(Exception, match="TARGET_EXECUTION_INVALID"):
            cli_tools.apply_edits(
                target=target,
                edits=[{"kind": "set_comment", "address": address, "comment": "x", "comment_type": "eol"}],
            )
        with pytest.raises(Exception, match="TARGET_EXECUTION_INVALID"):
            cli_tools.close_session(target=target)
        closed = cli_tools.close_session(target=target, discard_changes=True)
        assert closed["status"] == "ok"
        cli_tools.load_project_program(target=target, domain_path=domain_path)
        assert cli_tools.get_program_info(target=target)["min_address"] == address

        # --- inline source (what an AI client sends): Java inferred from the class, PyGhidra from the header ---
        result = cli_tools.run_script(
            target=target, source=JAVA_ADD_PLATE.replace("AddPlate", "InlinePlate"), args=["INLINE"]
        )
        print(f"[runtime] inline java: {result['transaction_outcome']} {result['script_id']}")
        assert result["inline"] is True and result["transaction_outcome"] == "committed"
        assert result["script_id"] == "inline:InlinePlate.java"
        assert _plate(target, address) == "INLINE"
        with pytest.raises(Exception, match="SCRIPT_COMPILE_FAILED") as broken:
            cli_tools.run_script(target=target, source=JAVA_BROKEN.replace("Broken", "InlineBroken"))
        assert _domain_error(broken.value)["details"]["script_errors"]
        assert _plate(target, address) == "INLINE"
        if runtimes.get("PyGhidra"):
            result = cli_tools.run_script(target=target, source=PYGHIDRA_ADD_PLATE, args=["INLINEPY"])
            assert result["inline"] is True and result["transaction_outcome"] == "committed"
            assert _plate(target, address) == "INLINEPY"
            with pytest.raises(Exception, match="SCRIPT_FAILED"):
                cli_tools.run_script(target=target, source=PYGHIDRA_FAIL)
            assert _plate(target, address) == "INLINEPY", "a failing inline script is rolled back"
    finally:
        try:
            cli_tools.close_session(target=target, discard_changes=True)
        except Exception:  # noqa: BLE001
            pass
        _release_script_runtime()


def test_runtime_large_script_failure_keeps_rollback_and_retrievable_diagnostics(tmp_path):
    import asyncio
    import json

    from ghidra_mcp.presentation.result_compaction import _call_tool_result_wire_chars

    source = """# @runtime PyGhidra
from ghidra.program.model.listing import CommentType
currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "TRANSIENT")
print("ordinary diagnostic line\\n" * 2000)
raise RuntimeError("expected diagnostic test failure")
"""
    with _nested_script_project(tmp_path, {"LargeDiagnostic.py": source}) as (target, address):
        before = _plate(target, address)
        result = asyncio.run(
            cli_tools.app.mcp.call_tool("run_script", {"target": target, "script_id": "t:LargeDiagnostic.py"})
        )
        assert result.is_error
        assert result.structured_content["error"]["code"] == "SCRIPT_FAILED"
        assert result.structured_content["error"]["details"]["transaction_outcome"] == "rolled_back"
        assert _call_tool_result_wire_chars(result) <= 12000
        resource = asyncio.run(cli_tools.app.mcp.read_resource(result.structured_content["resource_uri"]))
        details = json.loads(resource[0].content)["error"]["details"]
        assert details["stdout"]["text"].count("ordinary diagnostic line") == 2000
        assert details["execution_state"] == "valid"
        assert details["transaction_outcome"] == "rolled_back"
        assert _plate(target, address) == before
