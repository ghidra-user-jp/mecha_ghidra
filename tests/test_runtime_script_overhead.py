"""Real-Ghidra regressions for script catalog, decompiler reuse and bounded observation."""

import os

import jpype
import pytest

from test_runtime_script_commands import (
    _cross_runtime_source,
    _domain_error,
    _nested_script_project,
    _plate,
    _run,
    _runtimes,
    _start_pyghidra_if_needed,
    cli_tools,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)

MANIFEST = (
    "Manifest-Version: 1.0\nBundle-ManifestVersion: 2\n"
    "Bundle-SymbolicName: mecha.test.manifest\nBundle-Version: 1.0.0\n"
    "Import-Package: ghidra.app.script\n\n"
)


@pytest.mark.parametrize("runtime", ["Java", "PyGhidra", "Jython"])
def test_runtime_manifest_root_is_listed_and_executable(tmp_path, runtime):
    filename = "ManifestScript" + (".java" if runtime == "Java" else ".py")
    body = 'println("MANIFEST_SCRIPT_OK")' + (";" if runtime == "Java" else "")
    source = _cross_runtime_source(runtime, "ManifestScript", body)
    with _nested_script_project(tmp_path, {filename: source, "META-INF/MANIFEST.MF": MANIFEST}) as (target, _):
        if not _runtimes()[runtime]:
            pytest.skip(f"{runtime} provider unavailable")
        script_id = "t:" + filename
        assert script_id in {entry["script_id"] for entry in cli_tools.list_scripts()["items"]}
        result = _run(target, script_id=script_id)
        assert result["status"] == "ok"
        assert result["execution_state"] == "valid"
        assert "MANIFEST_SCRIPT_OK" in result["stdout"]["text"]


def test_runtime_unresolved_manifest_dependency_returns_native_diagnostic(tmp_path):
    source = _cross_runtime_source("Java", "MissingDependency", 'println("UNEXPECTED_RUN");')
    manifest = MANIFEST.replace("ghidra.app.script\n", "ghidra.app.script,mecha.test.missing.package\n")
    with _nested_script_project(tmp_path, {"MissingDependency.java": source, "META-INF/MANIFEST.MF": manifest}) as (
        target,
        _,
    ):
        with pytest.raises(Exception) as exc_info:
            _run(target, script_id="t:MissingDependency.java")
        error = _domain_error(exc_info.value)
        assert error["code"] in {"SCRIPT_LOAD_FAILED", "SCRIPT_COMPILE_FAILED"}
        assert "mecha.test.missing.package" in str(error["details"])
        assert error["details"]["execution_state"] == "valid"


def _warm_decompiler(target):
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    function = cli_tools.list_functions(target=target, offset=0, limit=1)[0]
    selector = {"target": target, "name": function["name"]}
    cli_tools.decompile_function(**selector)
    ctx = _CONTEXTS[target]
    assert ctx._decompiler is not None
    return ctx, selector


@pytest.mark.parametrize("runtime", ["Java", "PyGhidra", "Jython"])
def test_runtime_unchanged_script_preserves_shared_decompiler(tmp_path, runtime):
    with _nested_script_project(tmp_path, {}) as (target, _):
        if not _runtimes()[runtime]:
            pytest.skip(f"{runtime} provider unavailable")
        ctx, selector = _warm_decompiler(target)
        interface = ctx._decompiler
        body = 'println("NO_CHANGE")' + (";" if runtime == "Java" else "")
        result = _run(target, source=_cross_runtime_source(runtime, "ReadOnly", body))
        assert result["transaction_outcome"] == "unchanged"
        assert result["revision_before"] == result["revision"]
        assert ctx._decompiler is interface
        cli_tools.decompile_function(**selector)
        assert ctx._decompiler is interface
        assert ctx.execution_invalid is None


def test_runtime_edits_and_rollback_still_invalidate_shared_decompiler(tmp_path):
    with _nested_script_project(tmp_path, {}) as (target, address):
        ctx, selector = _warm_decompiler(target)
        previous = ctx._decompiler
        source = '# @runtime PyGhidra\nsetPlateComment(currentProgram.getMinAddress(), "KEPT")\n'
        result = _run(target, source=source)
        assert result["transaction_outcome"] == "committed"
        assert ctx._decompiler is None
        cli_tools.decompile_function(**selector)
        assert ctx._decompiler is not previous
        assert _plate(target, address) == "KEPT"
        previous = ctx._decompiler
        with pytest.raises(Exception) as exc_info:
            _run(target, source=source.replace("KEPT", "ROLLED_BACK") + 'raise RuntimeError("EXPECTED_FAILURE")\n')
        error = _domain_error(exc_info.value)
        assert error["code"] == "SCRIPT_FAILED"
        assert error["details"]["transaction_outcome"] == "rolled_back"
        assert ctx._decompiler is None
        cli_tools.decompile_function(**selector)
        assert ctx._decompiler is not previous
        assert _plate(target, address) == "KEPT"
        assert ctx.execution_invalid is None


@pytest.mark.parametrize("daemon", [False, True])
def test_runtime_java_thread_observation_retains_identity_and_liveness(daemon):
    from ghidra_headless.scripts import execution

    _start_pyghidra_if_needed()
    thread_cls = jpype.JClass("java.lang.Thread")
    latch = jpype.JClass("java.util.concurrent.CountDownLatch")(1)
    runnable = jpype.JProxy("java.lang.Runnable", dict(run=lambda: latch.await_()))
    thread = thread_cls(runnable, "mecha-script-worker")
    thread.setDaemon(daemon)
    before = execution.snapshot_threads()
    assert int(thread_cls.currentThread().threadId()) in before["java"]
    try:
        thread.start()
        result = execution.describe_new_threads(before, grace_seconds=0)
        entries = [entry for entry in result["stray"] if entry["id"] == int(thread.threadId())]
        assert entries == [
            {"kind": "java", "id": int(thread.threadId()), "name": "mecha-script-worker", "daemon": daemon}
        ]
        assert execution.alive_threads(entries) == entries
    finally:
        latch.countDown()
        thread.join(5000)
    assert not thread.isAlive()
    assert execution.alive_threads(entries) == []


@pytest.mark.parametrize("buffer_kind", ["heap", "direct", "read_only"])
def test_runtime_capture_consumes_only_buffer_slice_with_exact_byte_limit(buffer_kind):
    from ghidra_headless.scripts.capture import _bounded_channel_class

    _start_pyghidra_if_needed()
    byte_buffer = jpype.JClass("java.nio.ByteBuffer")
    payload = "-あいう-".encode()
    if buffer_kind == "direct":
        buffer = byte_buffer.allocateDirect(len(payload))
        buffer.put(jpype.JArray(jpype.JByte)(payload))
    else:
        buffer = byte_buffer.wrap(jpype.JArray(jpype.JByte)(payload))
    buffer.position(1)
    buffer.limit(len(payload) - 1)
    if buffer_kind == "read_only":
        buffer = buffer.asReadOnlyBuffer()
    channel = _bounded_channel_class()(4)
    assert channel.write(buffer) == 9
    assert buffer.remaining() == 0
    buffer.position(1)
    assert channel.write(buffer) == 9
    assert buffer.remaining() == 0
    assert channel.snapshot() == ("あいう".encode()[:4], 14)


def test_runtime_capture_print_writer_preserves_utf8_truncation_and_counts():
    from ghidra_headless.scripts.capture import BoundedCapture

    _start_pyghidra_if_needed()
    capture = BoundedCapture(4)
    try:
        capture.writer.write("あいう")
        capture.flush()
        capture.writer.write("more")
        assert capture.describe() == {"text": "あ�", "truncated": True, "dropped_bytes": 9, "limit_bytes": 4}
    finally:
        capture.writer.close()
