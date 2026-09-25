from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import anyio
import pytest

from ghidra_mcp.application.locks import SCRIPT_BARRIER
from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.contracts.tool_spec import filter_tool_specs, get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.policies import configure_lock_timeout_seconds, get_lock_timeout_seconds
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.doc_resources import tool_docs_detail
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from import_operation_support import make_bundle
from test_import_operations import wait_terminal, wait_until


def _input(bundle, name="sample.bin"):
    return str(Path(bundle.runtime_backend._store.target_projects["default"][0]) / name)


@pytest.fixture
def runtime(tmp_path):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def import_body(binary_path, **options):
        calls.append((binary_path, options))
        entered.set()
        assert release.wait(5)
        path = "/" + Path(binary_path).name
        file = SimpleNamespace(getPathname=lambda: path)
        files[path] = file
        return file

    bundle, files, closes = make_bundle(tmp_path, import_body)
    old_timeout = get_lock_timeout_seconds()
    configure_lock_timeout_seconds(0.03)
    try:
        yield bundle, entered, release, calls, closes
    finally:
        release.set()
        bundle.registry.close_all()
        configure_lock_timeout_seconds(old_timeout)


async def _until(predicate, timeout=2):
    with anyio.fail_after(timeout):
        while not predicate():
            await asyncio.sleep(0.001)


def test_mcp_record_lookup_and_replay_bypass_shared_thread_limiter(runtime):
    bundle, entered, release, calls, _ = runtime
    mcp = bundle.runtime.mcp
    args = {
        "target": "default",
        "binary_path": _input(bundle),
        "request_id": str(uuid4()),
        "analyze_imported": True,
        "wait_seconds": 0,
    }

    async def scenario():
        # Occupy the only ordinary synchronous tool slot in another task.
        limiter = anyio.to_thread.current_default_thread_limiter()
        previous = limiter.total_tokens
        limiter.total_tokens = 1
        occupied = threading.Event()
        unblock = threading.Event()

        def occupy():
            occupied.set()
            assert unblock.wait(5)

        task = asyncio.create_task(anyio.to_thread.run_sync(occupy))
        try:
            await _until(occupied.is_set)
            with anyio.fail_after(2):
                accepted = await mcp.call_tool("import_program", args)
                assert not accepted.is_error
                operation_id = accepted.structured_content["result"]["operation_id"]
                await _until(entered.is_set)
                status = await mcp.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 0})
                replay = await mcp.call_tool("import_program", args)
            assert status.structured_content["result"]["state"] == "running"
            assert replay.structured_content["result"]["operation_id"] == operation_id
            assert replay.structured_content["result"]["replayed"]
            assert len(calls) == 1
        finally:
            unblock.set()
            await task
            limiter.total_tokens = previous
        # The job holds the target and project locks; list_targets does not wait for them.
        with anyio.fail_after(1):
            targets = await mcp.call_tool("list_targets", {})
        assert not targets.is_error
        release.set()
        with anyio.fail_after(5):
            done = await mcp.call_tool("get_operation", {"request_id": args["request_id"], "wait_seconds": 5})
        record = done.structured_content["result"]
        assert record["state"] == "succeeded" and record["result"] == {"program": "/sample.bin"}
        # Small compaction limits must not turn job records into LRU resource references.
        assert "result_id" not in done.structured_content
        with anyio.fail_after(5):
            again = await mcp.call_tool("import_program", {**args, "request_id": str(uuid4()), "wait_seconds": 5})
        assert not again.is_error  # The job failed; the call itself succeeded.
        error = again.structured_content["result"]["operation_error"]
        assert error["code"] == "PROGRAM_ALREADY_IMPORTED"
        assert error["hint"].startswith("Use load_project_program")
        assert error["details"]["existing_domain_path"] == "/sample.bin"
        assert error["details"]["output_state"] == "absent"
        assert len(calls) == 1

    asyncio.run(scenario())


def test_server_side_wait_replies_when_the_job_finishes(runtime):
    bundle, entered, release, _, _ = runtime
    mcp = bundle.runtime.mcp

    async def scenario():
        with anyio.fail_after(5):
            pending = await mcp.call_tool(
                "import_program", {"target": "default", "binary_path": _input(bundle), "wait_seconds": 1}
            )
        record = pending.structured_content["result"]
        # Still running after the full wait: the client may ask again at once.
        assert (record["state"], record["poll_after_ms"]) == ("running", 0)
        threading.Timer(0.2, release.set).start()
        started = time.monotonic()
        with anyio.fail_after(5):
            done = await mcp.call_tool("get_operation", {"operation_id": record["operation_id"]})
        assert done.structured_content["result"]["state"] == "succeeded"
        assert time.monotonic() - started < 3

    asyncio.run(scenario())


def test_one_call_is_enough_when_the_import_is_quick(runtime):
    bundle, _, release, _, _ = runtime
    release.set()
    record = bundle.runtime.tools["import_program"](target="default", binary_path=_input(bundle))
    assert record["state"] == "succeeded" and record["result"]["program"] == "/sample.bin"
    assert record["poll_after_ms"] == 0 and record["replayed"] is False


def test_resend_without_request_id_returns_the_same_job(runtime):
    bundle, entered, release, calls, _ = runtime
    mcp = bundle.runtime.mcp
    args = {"target": "default", "binary_path": _input(bundle), "wait_seconds": 0}

    async def scenario():
        first = (await mcp.call_tool("import_program", args)).structured_content["result"]
        await _until(entered.is_set)
        second = (await mcp.call_tool("import_program", args)).structured_content["result"]
        assert second["operation_id"] == first["operation_id"] and second["replayed"]
        release.set()
        with anyio.fail_after(5):
            done = await mcp.call_tool("get_operation", {"operation_id": first["operation_id"], "wait_seconds": 5})
        assert done.structured_content["result"]["state"] == "succeeded"

    asyncio.run(scenario())
    assert len(calls) == 1


def test_script_writer_keeps_the_job_waiting_instead_of_failing(runtime):
    bundle, _, release, calls, _ = runtime
    manager = bundle.registry.operations
    mcp = bundle.runtime.mcp
    args = {"target": "default", "binary_path": _input(bundle), "request_id": str(uuid4()), "wait_seconds": 0}

    async def scenario():
        with SCRIPT_BARRIER.write_lock():
            with anyio.fail_after(1):
                accepted = await mcp.call_tool("import_program", args)
                lookup = await mcp.call_tool("get_operation", {"request_id": args["request_id"], "wait_seconds": 0})
                replay = await mcp.call_tool("import_program", args)
            assert not accepted.is_error and not lookup.is_error
            assert replay.structured_content["result"]["replayed"]
            # Many 30 ms lock timeouts later the job still waits behind the writer.
            await asyncio.sleep(0.3)
            waiting = manager.get(request_id=args["request_id"])
            assert (waiting["state"], waiting["phase"]) == ("running", "waiting_for_lock")
            assert not calls
        release.set()
        with anyio.fail_after(5):
            done = await mcp.call_tool("get_operation", {"request_id": args["request_id"], "wait_seconds": 5})
        assert done.structured_content["result"]["state"] == "succeeded"
        assert len(calls) == 1

    asyncio.run(scenario())


def test_queued_rebind_never_imports_into_new_project(runtime):
    bundle, entered, release, calls, _ = runtime
    api = bundle.runtime.tools
    manager = bundle.registry.operations
    first = api["import_program"](target="default", binary_path=_input(bundle, "a.bin"), wait_seconds=0)
    assert entered.wait(1)
    store = bundle.runtime_backend._store
    # Register a second target before queueing; no project open is needed.
    bundle.registry.register_target("other", "/project-A", project_name="a")
    queued = api["import_program"](target="other", binary_path=_input(bundle, "b.bin"), wait_seconds=0)
    bundle.registry.register_target("other", "/project-B", project_name="b")
    release.set()
    assert wait_terminal(manager, first)["state"] == "succeeded"
    result = wait_terminal(manager, queued)
    assert result["operation_error"]["code"] == "TARGET_REBOUND"
    assert result["operation_error"]["details"]["output_state"] == "absent"
    assert len(calls) == 1 and ("/project-B", "b") not in store.project_handles


def test_alias_reservation_and_close_order(runtime, tmp_path):
    bundle, entered, release, calls, closes = runtime
    manager = bundle.registry.operations
    key = bundle.runtime_backend._store.target_projects["default"]
    bundle.registry.register_target("alias", key[0], project_name=key[1])
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "a.bin").write_bytes(b"\xc3")
    receipt = bundle.runtime.tools["import_program"](
        target="default", binary_path=_input(bundle, "a.bin"), wait_seconds=0
    )
    assert entered.wait(1)
    with pytest.raises(RuntimeError) as duplicate:
        bundle.runtime.tools["import_program"](
            target="alias", binary_path=str(tmp_path / "other" / "a.bin"), wait_seconds=0
        )
    assert duplicate.value.domain_error["code"] == "IMPORT_IN_PROGRESS"
    assert duplicate.value.domain_error["details"]["operation_id"] == receipt["operation_id"]
    closing = threading.Thread(target=bundle.registry.close_all)
    closing.start()
    try:
        wait_until(lambda: manager._stopping)
        assert closes == [] and closing.is_alive()
        release.set()
        closing.join(2)
        assert not closing.is_alive() and closes == ["closed"]
        assert wait_terminal(manager, receipt)["state"] == "succeeded"
    finally:
        release.set()
        closing.join(2)


def test_tool_filters_keep_the_lookup():
    for selection in (
        {"allow_safety": ["write"]},
        {"allow_operation_levels": ["advanced"]},
        {"allow_operation_levels": ["standard", "advanced"]},
        {"allow_categories": ["bsim"], "enable_tools": ["import_program"]},
    ):
        selected = filter_tool_specs(**selection)
        assert "import_program" in selected and "get_operation" in selected, selection
    unpublished = filter_tool_specs(disable_tools=["get_operation", "import_program", "analyze_program"])
    assert "import_program" not in unpublished and "analyze_program" not in unpublished
    with pytest.raises(ValueError, match="analyze_program reports jobs through get_operation"):
        filter_tool_specs(disable_tools=["get_operation", "import_program"])
    with pytest.raises(ValueError, match="keep get_operation enabled"):
        filter_tool_specs(disable_tools=["get_operation"])
    with pytest.raises(ValueError, match="get_operation"):
        create_mcp_server(
            specs={"import_program": get_tool_spec("import_program")},
            registry_provider=object,
            dispatcher_provider=lambda: None,
        )
    # A conflicting filter is a usage error (exit 2), not a traceback.
    with pytest.raises(SystemExit) as usage:
        cli.parse_args(["--disable-tool", "get_operation"])
    assert usage.value.code == 2


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"operation_id": "bad"},
        {"request_id": "bad"},
        {"request_id": "+" + "1" * 31},
        {"operation_id": " " + "1" * 31},
        {"operation_id": str(uuid4()), "request_id": str(uuid4())},
    ],
)
def test_lookup_rejects_ambiguous_or_invalid_ids(runtime, args):
    bundle, *_ = runtime
    result = asyncio.run(
        bundle.runtime.mcp.handle_call_tool(None, SimpleNamespace(name="get_operation", arguments=args))
    )
    assert result.is_error


def test_missing_input_is_rejected_at_admission(runtime, tmp_path):
    bundle, _, release, calls, _ = runtime
    api = bundle.runtime.tools
    request_id = str(uuid4())
    with pytest.raises(RuntimeError) as missing:
        api["import_program"](
            target="default", binary_path=str(tmp_path / "missing" / "sample.bin"), request_id=request_id
        )
    error = missing.value.domain_error
    assert error["code"] == "VALIDATION_ERROR" and "binary_path" in error["hint"]
    assert str(tmp_path) not in str(missing.value)
    with pytest.raises(RuntimeError) as lookup:
        api["get_operation"](request_id=request_id, wait_seconds=0)
    assert lookup.value.domain_error["code"] == "OPERATION_NOT_FOUND"
    release.set()
    fixed = api["import_program"](target="default", binary_path=_input(bundle), wait_seconds=5)
    assert fixed["state"] == "succeeded" and len(calls) == 1


def test_existing_program_is_reported_even_if_the_input_vanished(runtime, tmp_path):
    bundle, entered, release, _, _ = runtime
    api = bundle.runtime.tools
    manager = bundle.registry.operations
    release.set()
    assert api["import_program"](target="default", binary_path=_input(bundle, "a.bin"), wait_seconds=5)["state"] == (
        "succeeded"
    )
    release.clear()
    entered.clear()
    gate = api["import_program"](target="default", binary_path=_input(bundle, "b.bin"), wait_seconds=0)
    assert entered.wait(1)
    again = api["import_program"](target="default", binary_path=_input(bundle, "a.bin"), wait_seconds=0)
    (tmp_path / "a.bin").unlink()
    release.set()
    assert wait_terminal(manager, gate)["state"] == "succeeded"
    error = wait_terminal(manager, again)["operation_error"]
    assert error["code"] == "PROGRAM_ALREADY_IMPORTED"
    assert error["details"]["existing_domain_path"] == "/a.bin"


def test_loader_without_output_can_retry_and_uses_public_error(runtime):
    from ghidra_mcp.presentation.error_mapper import operation_error_payload

    bundle, _, release, _, _ = runtime
    store = bundle.runtime_backend._store
    handle = store.project_handles[store.target_projects["default"]]
    original = handle.import_program
    failure = DomainError(ErrorCode.IMPORT_FAILED, "PRIVATE internal loader diagnostic")
    handle.import_program = lambda *_args, **_kwargs: (_ for _ in ()).throw(failure)
    api = bundle.runtime.tools
    result = api["import_program"](target="default", binary_path=_input(bundle), wait_seconds=5)
    error = result["operation_error"]
    assert error["details"]["output_created"] is False and error["details"]["output_state"] == "absent"
    assert error["message"] == operation_error_payload(failure)["message"]
    assert "PRIVATE" not in error["message"]
    handle.import_program = original
    release.set()
    retry = api["import_program"](target="default", binary_path=_input(bundle), wait_seconds=5)
    assert retry["state"] == "succeeded"


def test_slow_new_admissions_do_not_block_lookup_or_accepted_replay(runtime, monkeypatch):
    bundle, entered, release, *_ = runtime
    api = bundle.runtime.tools
    args = dict(target="default", binary_path=_input(bundle), request_id=str(uuid4()), wait_seconds=0)
    receipt = api["import_program"](**args)
    assert entered.wait(1)
    prepare_entered = threading.Barrier(3)
    prepare_release = threading.Event()
    original = bundle.target_service.prepare_import

    def slow_prepare(*args):
        prepare_entered.wait(timeout=3)
        assert prepare_release.wait(5)
        return original(*args)

    monkeypatch.setattr(bundle.target_service, "prepare_import", slow_prepare)

    async def scenario():
        tasks = [
            asyncio.create_task(
                bundle.runtime.mcp.call_tool(
                    "import_program",
                    {**args, "binary_path": _input(bundle, f"new{i}.bin"), "request_id": str(uuid4())},
                )
            )
            for i in range(2)
        ]
        try:
            await anyio.to_thread.run_sync(lambda: prepare_entered.wait(timeout=3))
            with anyio.fail_after(1):
                status = await bundle.runtime.mcp.call_tool(
                    "get_operation", {"operation_id": receipt["operation_id"], "wait_seconds": 0}
                )
                replay = await bundle.runtime.mcp.call_tool("import_program", args)
            assert status.structured_content["result"]["state"] == "running"
            assert replay.structured_content["result"]["replayed"]
        finally:
            prepare_release.set()
            await asyncio.gather(*tasks)
            release.set()

    asyncio.run(scenario())


def test_import_root_is_enforced_at_admission_and_before_execution(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "inside.bin").write_bytes(b"\xc3")
    calls = []

    def import_body(binary_path, **_options):
        calls.append(binary_path)
        path = "/" + Path(binary_path).name
        return SimpleNamespace(getPathname=lambda: path)

    bundle, _, _ = make_bundle(tmp_path, import_body, path_policy=PathPolicy.from_roots(import_roots=[str(allowed)]))
    api = bundle.runtime.tools
    try:
        with pytest.raises(RuntimeError) as outside:
            api["import_program"](target="default", binary_path=str(tmp_path / "sample.bin"), wait_seconds=0)
        assert outside.value.domain_error["code"] == "PATH_NOT_ALLOWED"
        # Even if admission were bypassed, the worker re-checks the policy
        # before the loader runs.
        key = bundle.target_service._project_key("default")
        monkeypatch.setattr(bundle.target_service, "prepare_import", lambda _target, path: (path, key))
        leaked = api["import_program"](target="default", binary_path=str(tmp_path / "a.bin"), wait_seconds=5)
        assert leaked["operation_error"]["code"] == "PATH_NOT_ALLOWED" and not calls
        inside = api["import_program"](target="default", binary_path=str(allowed / "inside.bin"), wait_seconds=5)
        assert inside["state"] == "succeeded" and calls == [str(allowed / "inside.bin")]
    finally:
        bundle.registry.close_all()


class _GatedPolicy:
    """Pauses the worker at its first step, before any lock or project access."""

    def __init__(self, policy):
        self._policy = policy
        self.reached, self.resume = threading.Event(), threading.Event()

    def __getattr__(self, name):
        return getattr(self._policy, name)

    def validate_import_path(self, path):
        if threading.current_thread().name == "ghidra-jobs":
            self.reached.set()
            assert self.resume.wait(5)
        return self._policy.validate_import_path(path)


def test_shutdown_after_admission_stops_before_the_project_opens(runtime, monkeypatch):
    bundle, _, _, calls, _ = runtime
    manager = bundle.registry.operations
    store = bundle.runtime_backend._store
    gate = _GatedPolicy(bundle.target_service.path_policy)
    monkeypatch.setattr(bundle.target_service, "_path_policy", gate)
    opened = []
    original = store.get_target_handle
    monkeypatch.setattr(store, "get_target_handle", lambda name: opened.append(name) or original(name))
    receipt = bundle.runtime.tools["import_program"](target="default", binary_path=_input(bundle), wait_seconds=0)
    assert gate.reached.wait(2)
    closing = threading.Thread(target=bundle.registry.close_all)
    closing.start()
    wait_until(lambda: manager._stopping)
    gate.resume.set()
    closing.join(5)
    assert not closing.is_alive()
    error = manager.get(operation_id=receipt["operation_id"])["operation_error"]
    assert error["code"] == "OPERATION_SHUTDOWN" and error["details"]["output_state"] == "absent"
    assert not opened and not calls


def test_shutdown_just_before_loading_cancels_and_skips_the_loader(runtime):
    bundle, _, _, calls, _ = runtime
    manager = bundle.registry.operations
    store = bundle.runtime_backend._store
    handle = store.project_handles[store.target_projects["default"]]
    reached, resume = threading.Event(), threading.Event()
    original = handle.create_cancellable_monitor

    def gated():
        reached.set()
        assert resume.wait(5)
        return original()

    handle.create_cancellable_monitor = gated
    receipt = bundle.runtime.tools["import_program"](target="default", binary_path=_input(bundle), wait_seconds=0)
    assert reached.wait(2)
    closing = threading.Thread(target=bundle.registry.close_all)
    closing.start()
    wait_until(lambda: manager._stopping)
    resume.set()
    closing.join(5)
    assert not closing.is_alive()
    error = manager.get(operation_id=receipt["operation_id"])["operation_error"]
    assert error["code"] == "OPERATION_SHUTDOWN" and error["details"]["output_state"] == "absent"
    assert "cancelled" not in error["details"]
    assert not calls
    assert handle.monitors[-1].isCancelled(), "a cancellation requested earlier applies once bound"


def test_loader_options_reach_the_handle(runtime):
    bundle, _, release, calls, _ = runtime
    release.set()
    record = bundle.runtime.tools["import_program"](
        target="default",
        binary_path=_input(bundle),
        import_mode="raw_binary",
        language_id="x86:LE:32:default",
        compiler_spec_id="gcc",
        base_address="4096",
        file_offset=1,
        length=2,
        block_name="ram",
        overlay=True,
        entry_offset=0,
        analyze_imported=False,
        wait_seconds=5,
    )
    assert record["state"] == "succeeded"
    ((binary_path, options),) = calls
    monitor = options.pop("monitor")
    assert callable(monitor.cancel) and not monitor.isCancelled()
    assert binary_path == _input(bundle)
    assert options == {
        "import_mode": "raw_binary",
        "language_id": "x86:LE:32:default",
        "compiler_spec_id": "gcc",
        "base_address": "0x1000",
        "file_offset": 1,
        "length": 2,
        "block_name": "ram",
        "overlay": True,
        "entry_offset": 0,
        "analyze_imported": False,
    }


def test_create_project_during_an_import_fails_fast_without_stalling_other_calls(runtime, tmp_path, monkeypatch):
    from ghidra_mcp.infrastructure.ghidra_adapter.runtime import target_lifecycle

    bundle, entered, release, _, _ = runtime
    created = []
    monkeypatch.setattr(
        target_lifecycle.ProjectHandle,
        "create_project",
        staticmethod(lambda location, name, overwrite=False: created.append(name) or {"project_name": name}),
    )
    configure_lock_timeout_seconds(0.5)
    record = bundle.runtime.tools["import_program"](target="default", binary_path=_input(bundle), wait_seconds=0)
    assert entered.wait(1)
    outcome = {}

    def create():
        try:
            bundle.registry.create_project(str(tmp_path / "second"), project_name="second")
        except DomainError as exc:
            outcome["error"] = exc

    creating = threading.Thread(target=create)
    creating.start()
    try:
        time.sleep(0.1)
        # The waiting create_project must not queue ahead of ordinary calls.
        started = time.monotonic()
        bundle.registry.register_target("other", str(tmp_path / "third"), project_name="third")
        assert time.monotonic() - started < 0.4
        creating.join(2)
        assert not creating.is_alive()
        error = outcome["error"]
        assert error.code == ErrorCode.LOCK_TIMEOUT and error.retryable
        assert error.details["lock"] == "runtime" and not created
    finally:
        release.set()
        creating.join(2)
    assert wait_terminal(bundle.registry.operations, record)["state"] == "succeeded"
    bundle.registry.create_project(str(tmp_path / "second"), project_name="second")
    assert created == ["second"]


def test_auto_import_analyzes_by_default(runtime):
    bundle, _, release, calls, _ = runtime
    release.set()
    record = bundle.runtime.tools["import_program"](target="default", binary_path=_input(bundle), wait_seconds=5)
    assert record["state"] == "succeeded"
    ((_, options),) = calls
    # Analysis runs inside the job, so a later load has nothing left to analyze.
    assert options["import_mode"] == "auto" and options["analyze_imported"] is True


@pytest.mark.parametrize("binary_path", ["~nonexistent-user-zz/x.bin", "a\x00b.bin", "/" + "x" * 17_000])
def test_admission_errors_are_coded(runtime, binary_path):
    bundle, *_ = runtime
    with pytest.raises(RuntimeError) as failure:
        bundle.runtime.tools["import_program"](target="default", binary_path=binary_path, wait_seconds=0)
    assert failure.value.domain_error["code"] == "VALIDATION_ERROR"


def test_symlink_loop_under_an_import_root_is_a_validation_error(tmp_path):
    loop = tmp_path / "loop"
    try:
        loop.symlink_to(loop)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this host")
    service = TargetService(
        SimpleNamespace(project_lock_key=lambda _name: "key"),
        path_policy=PathPolicy.from_roots(import_roots=[str(tmp_path)]),
    )
    with pytest.raises(DomainError) as failure:
        service.prepare_import("fw", str(loop / "x.bin"))
    assert failure.value.code == ErrorCode.VALIDATION_ERROR
    assert failure.value.details["operation"] == "import_program"


def test_symlink_parent_path_is_not_lexically_collapsed(runtime, tmp_path):
    bundle, _, release, calls, _ = runtime
    samples, other = tmp_path / "samples", tmp_path / "other"
    samples.mkdir()
    (other / "dir").mkdir(parents=True)
    try:
        (samples / "link").symlink_to(other / "dir", target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this host")
    (samples / "x.bin").write_bytes(b"wrong")
    (other / "x.bin").write_bytes(b"intended")
    release.set()
    record = bundle.runtime.tools["import_program"](
        target="default", binary_path=str(samples / "link" / ".." / "x.bin"), wait_seconds=5
    )
    assert record["state"] == "succeeded"
    assert Path(calls[0][0]).read_bytes() == b"intended"


def test_operation_tools_publish_no_stored_result_variants(runtime):
    bundle, *_ = runtime
    tools = {tool.name: tool for tool in asyncio.run(bundle.runtime.mcp.list_tools())}

    def notices(name):
        # tools/list's short form of the stored-result notices (see wire_output_schema).
        return [variant for variant in tools[name].output_schema["anyOf"] if variant.get("required") == ["truncated"]]

    for name in ("import_program", "get_operation"):
        schema = json.dumps(tools[name].output_schema)
        assert "result_id" not in schema and "resource_uri" not in schema, name
        assert not notices(name), name
        assert "large_result_output_schema" not in tool_docs_detail(get_tool_spec(name))
    assert notices("list_targets")
    assert "result_id" in json.dumps(tool_docs_detail(get_tool_spec("list_targets"))["structured_output_schema"])
