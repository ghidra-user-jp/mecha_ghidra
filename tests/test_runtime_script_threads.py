"""Real-Ghidra coverage of worker tracking through loading, quarantine and recovery."""

import contextlib
import os
import uuid

import jpype
import pytest

from test_runtime_script_commands import _domain_error, _nested_script_project, _run, cli_tools

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


@contextlib.contextmanager
def _worker_signals(target, key):
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    props = jpype.JClass("java.lang.System").getProperties()
    latch = jpype.JClass("java.util.concurrent.CountDownLatch")
    signals = {name: latch(1) for name in ("go", "edited", "stop")}
    for name, value in signals.items():
        props.put(key + "." + name, value)
    try:
        yield props, signals
    finally:
        signals["go"].countDown()
        signals["stop"].countDown()
        worker = props.get(key + ".thread")
        if worker is not None:
            worker.join(10000)
            assert not worker.isAlive(), "the regression worker must be reclaimed"
        try:
            if target in _CONTEXTS:
                cli_tools.close_session(target=target, discard_changes=True)
        finally:
            for name in (*signals, "thread"):
                props.remove(key + "." + name)


BACKGROUND = """import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.util.concurrent.CountDownLatch;
public class Background extends GhidraScript {
    public void run() {
        String key = getScriptArgs()[0];
        Program program = currentProgram;
        CountDownLatch go = (CountDownLatch) System.getProperties().get(key + ".go");
        CountDownLatch edited = (CountDownLatch) System.getProperties().get(key + ".edited");
        CountDownLatch stop = (CountDownLatch) System.getProperties().get(key + ".stop");
        Thread worker = new Thread(() -> {
            try {
                go.await();
                int tx = program.startTransaction("Background transaction after quarantine");
                program.endTransaction(tx, true);
                edited.countDown();
                stop.await();
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }, "script-background-worker");
        worker.setDaemon(true);
        System.getProperties().put(key + ".thread", worker);
        worker.start();
    }
}
"""


def test_runtime_quarantine_retains_live_threads_after_later_transaction(tmp_path):
    with _nested_script_project(tmp_path, {"Background.java": BACKGROUND}) as (target, _):
        from ghidra_headless.handlers.core_runtime import _CONTEXTS

        key = "mecha-thread-test-" + uuid.uuid4().hex
        with _worker_signals(target, key) as (props, signals):
            with pytest.raises(Exception, match="SCRIPT_FAILED"):
                _run(target, script_id="t:Background.java", args=[key])
            ctx = _CONTEXTS[target]
            before = dict(ctx.execution_invalid)
            assert before["stray_threads"]
            worker = props.get(key + ".thread")
            with pytest.raises(Exception, match="RUNTIME_DEGRADED"):
                cli_tools.close_session(target=target, discard_changes=True)
            signals["go"].countDown()
            seconds = jpype.JClass("java.util.concurrent.TimeUnit").SECONDS
            assert signals["edited"].await_(10, seconds)
            assert ctx.execution_invalid["reason"] == "stray_transaction"
            assert ctx.execution_invalid["stray_threads"] == before["stray_threads"]
            assert worker.isAlive()
            with pytest.raises(Exception, match="RUNTIME_DEGRADED"):
                cli_tools.close_session(target=target, discard_changes=True)
            assert not ctx.program.isClosed()
            signals["stop"].countDown()
            worker.join(10000)
            assert not worker.isAlive()
            assert cli_tools.close_session(target=target, discard_changes=True)["closed"]
            assert ctx.program.isClosed()


@pytest.mark.parametrize(
    "initializer,load_fails,join_in_run",
    [
        ("constructor", False, False),
        ("static", False, False),
        ("constructor", True, False),
        ("static", True, False),
        ("constructor", False, True),
    ],
)
def test_runtime_tracks_workers_started_while_loading(tmp_path, initializer, load_fails, join_in_run):
    key = "mecha-loader-test-" + uuid.uuid4().hex
    declaration = "static" if initializer == "static" else "public LoaderWorker()"
    fail = 'if (Boolean.parseBoolean("true")) throw new RuntimeException("LOADER_FAILURE");' if load_fails else ""
    finish = (
        f'((CountDownLatch) System.getProperties().get("{key}.stop")).countDown();\n'
        f'((Thread) System.getProperties().get("{key}.thread")).join();'
        if join_in_run
        else ""
    )
    # A lambda in a failed static initializer calls back into the erroneous
    # outer class and dies. The separate Runnable must survive that failure.
    source = f"""import ghidra.app.script.GhidraScript;
import java.util.concurrent.CountDownLatch;
public class LoaderWorker extends GhidraScript {{
    {declaration} {{
        CountDownLatch stop = (CountDownLatch) System.getProperties().get("{key}.stop");
        Thread worker = new Thread(new Runnable() {{
            public void run() {{
                try {{ stop.await(); }}
                catch (InterruptedException e) {{ Thread.currentThread().interrupt(); }}
            }}
        }}, "script-loader-worker");
        worker.setDaemon(true);
        System.getProperties().put("{key}.thread", worker);
        worker.start();
        {fail}
    }}
    public void run() throws Exception {{ {finish} println("RUN_COMPLETED"); }}
}}
"""
    with _nested_script_project(tmp_path, {"LoaderWorker.java": source}) as (target, _):
        from ghidra_headless.handlers.core_runtime import _CONTEXTS

        with _worker_signals(target, key) as (props, signals):
            ctx = _CONTEXTS[target]
            if join_in_run:
                result = _run(target, script_id="t:LoaderWorker.java")
                assert result["execution_state"] == "valid"
                assert result["stray_threads"] == []
                assert ctx.execution_invalid is None
                assert not props.get(key + ".thread").isAlive()
                return
            with pytest.raises(Exception) as failed:
                _run(target, script_id="t:LoaderWorker.java")
            error = _domain_error(failed.value)
            details = error["details"]
            assert error["code"] == ("SCRIPT_LOAD_FAILED" if load_fails else "SCRIPT_FAILED")
            if load_fails:
                assert "LOADER_FAILURE" in str(details["exception"])
                assert details["transaction_outcome"] == "rolled_back"
            assert details["execution_state"] == "invalid"
            worker = props.get(key + ".thread")
            assert worker.isAlive()
            assert any(entry["id"] == int(worker.threadId()) for entry in details["stray_threads"])
            assert ctx.execution_invalid["stray_threads"] == details["stray_threads"]
            with pytest.raises(Exception, match="RUNTIME_DEGRADED"):
                cli_tools.close_session(target=target, discard_changes=True)
            assert not ctx.program.isClosed()
            signals["stop"].countDown()
            worker.join(10000)
            assert not worker.isAlive()
            assert cli_tools.close_session(target=target, discard_changes=True)["closed"]
            assert ctx.program.isClosed()
