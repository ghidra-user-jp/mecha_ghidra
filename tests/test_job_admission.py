"""A job's response deadline covers admission, without accepting work after a refusal."""

from __future__ import annotations

import asyncio
import threading
import time
from uuid import uuid4

import anyio
import pytest

from ghidra_mcp.application.services.job_admission import JobAdmission
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation import mcp_server
from ghidra_mcp.presentation.startup import StartupGate
from test_analysis_operations import AnalysisService
from test_mcp_import_operations import _input, _until
from test_mcp_import_operations import runtime as _runtime
from test_script_operations import Scripts

runtime = _runtime


def _arguments(bundle, name="sample.bin"):
    return {"target": "default", "binary_path": _input(bundle, name), "wait_seconds": 0, "request_id": str(uuid4())}


def _assert_expired(reply):
    assert reply.is_error
    error = reply.structured_content["error"]
    assert (error["code"], error["retryable"]) == ("LOCK_TIMEOUT", True)
    assert error["details"] == {"lock": "admission", "output_state": "absent"}


@pytest.mark.parametrize("startup_delay", [0, 0.2])
def test_admission_and_startup_count_against_the_job_wait(runtime, monkeypatch, startup_delay):
    bundle, *_ = runtime
    original = bundle.target_service.prepare_import
    remaining = []

    def prepare(*args):
        time.sleep(0.3)
        return original(*args)

    async def wait(_manager, _operation_id, timeout):
        remaining.append(timeout)

    monkeypatch.setattr(bundle.target_service, "prepare_import", prepare)
    monkeypatch.setattr(mcp_server, "wait_while_pending", wait)
    monkeypatch.setattr(mcp_server, "get_lock_timeout_seconds", lambda: 2)
    server = bundle.runtime.mcp

    async def scenario():
        if startup_delay:
            server.startup_gate = StartupGate()
            asyncio.get_running_loop().call_later(startup_delay, server.startup_gate.mark_ready)
        reply = await server.call_tool("import_program", {**_arguments(bundle), "wait_seconds": 1})
        assert not reply.is_error

    asyncio.run(scenario())
    assert len(remaining) == 1 and 0 < remaining[0] <= 0.75 - startup_delay


def test_an_expired_admission_never_starts_later_and_can_be_retried(runtime, monkeypatch):
    bundle, _, release, calls, _ = runtime
    preparing, resume = threading.Event(), threading.Event()
    original = bundle.target_service.prepare_import
    server = bundle.runtime.mcp
    server.deferred_calls.defer_after = 0.05
    args = _arguments(bundle)

    def prepare(*args):
        preparing.set()
        assert resume.wait(3)
        return original(*args)

    monkeypatch.setattr(bundle.target_service, "prepare_import", prepare)

    async def scenario():
        try:
            with anyio.fail_after(1):
                reply = await server.call_tool("import_program", args)
            _assert_expired(reply)
            assert preparing.is_set() and calls == []
            assert not bundle.registry.operations.has_request(args["request_id"])
        finally:
            resume.set()
        await _until(lambda: bundle.registry.operations._calls_in_flight == 0)
        assert calls == [] and not bundle.registry.operations.has_request(args["request_id"])
        release.set()
        retry = await server.call_tool("import_program", {**args, "wait_seconds": 1})
        assert retry.structured_content["result"]["state"] == "succeeded"
        assert len(calls) == 1

    asyncio.run(scenario())


def test_admission_slots_stay_occupied_until_timed_out_workers_finish(runtime, monkeypatch):
    bundle, _, _, calls, _ = runtime
    resume = threading.Event()
    preparing = []
    original = bundle.target_service.prepare_import
    server = bundle.runtime.mcp
    server.deferred_calls.defer_after = 0.1

    def prepare(*args):
        preparing.append(args)
        assert resume.wait(3)
        return original(*args)

    monkeypatch.setattr(bundle.target_service, "prepare_import", prepare)

    async def scenario():
        try:
            replies = await asyncio.gather(
                server.call_tool("import_program", _arguments(bundle, "a.bin")),
                server.call_tool("import_program", _arguments(bundle, "b.bin")),
            )
            for reply in replies:
                _assert_expired(reply)
            assert len(preparing) == 2
            _assert_expired(await server.call_tool("import_program", _arguments(bundle)))
            assert len(preparing) == 2, "the refused workers still own both admission slots"
        finally:
            resume.set()
        await _until(lambda: bundle.registry.operations._calls_in_flight == 0)
        assert len(preparing) == 2 and calls == []

    asyncio.run(scenario())


def test_timeout_after_admission_returns_the_receipt_and_replays_it(runtime, monkeypatch):
    bundle, _, release, calls, _ = runtime
    resume = threading.Event()
    receipts = []
    original = bundle.registry.operations.submit_import
    server = bundle.runtime.mcp
    server.deferred_calls.defer_after = 0.1
    args = _arguments(bundle)

    def submit(*args, **kwargs):
        receipt = original(*args, **kwargs)
        receipts.append(receipt)
        assert resume.wait(3)
        return receipt

    monkeypatch.setattr(bundle.registry.operations, "submit_import", submit)

    async def scenario():
        try:
            with anyio.fail_after(1):
                reply = await server.call_tool("import_program", args)
            assert not reply.is_error and len(receipts) == 1
            receipt = reply.structured_content["result"]
            assert receipt["operation_id"] == receipts[0]["operation_id"]
        finally:
            resume.set()
        await _until(lambda: bundle.registry.operations._calls_in_flight == 0)
        release.set()
        replay = await server.call_tool("import_program", {**args, "wait_seconds": 1})
        assert replay.structured_content["result"]["operation_id"] == receipt["operation_id"]
        assert replay.structured_content["result"]["replayed"] is True
        assert len(calls) == 1

    asyncio.run(scenario())


def test_shutdown_waits_for_an_admission_worker_that_outlived_its_reply(runtime, monkeypatch):
    bundle, _, _, calls, closes = runtime
    preparing, resume = threading.Event(), threading.Event()
    original = bundle.target_service.prepare_import
    server = bundle.runtime.mcp
    server.deferred_calls.defer_after = 0.05
    closing = threading.Thread(target=bundle.registry.close_all)

    def prepare(*args):
        preparing.set()
        assert resume.wait(3)
        return original(*args)

    monkeypatch.setattr(bundle.target_service, "prepare_import", prepare)

    async def scenario():
        try:
            _assert_expired(await server.call_tool("import_program", _arguments(bundle)))
            assert preparing.is_set()
            closing.start()
            await _until(lambda: bundle.registry.operations._stopping)
            assert closing.is_alive() and closes == []
        finally:
            resume.set()
            await anyio.to_thread.run_sync(lambda: closing.join(2))
        assert not closing.is_alive() and calls == [] and closes == ["closed"]

    asyncio.run(scenario())


@pytest.mark.parametrize("expired", [False, True])
def test_a_cancelled_request_keeps_its_admission_deadline(runtime, monkeypatch, expired):
    bundle, _, release, calls, _ = runtime
    preparing, resume = threading.Event(), threading.Event()
    original = bundle.target_service.prepare_import
    server = bundle.runtime.mcp
    server.deferred_calls.defer_after = 0.05 if expired else 40
    args = _arguments(bundle)

    def prepare(*args):
        preparing.set()
        assert resume.wait(3)
        return original(*args)

    monkeypatch.setattr(bundle.target_service, "prepare_import", prepare)

    async def scenario():
        request = asyncio.create_task(server.call_tool("import_program", args))
        try:
            await _until(preparing.is_set)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            if expired:
                await asyncio.sleep(0.1)
        finally:
            resume.set()
            release.set()
        await _until(lambda: bundle.registry.operations._calls_in_flight == 0)
        assert bundle.registry.operations.has_request(args["request_id"]) is not expired
        if expired:
            assert calls == []
        else:
            # A lost reply can still be recovered using the same request ID.
            reply = await server.call_tool("import_program", {**args, "wait_seconds": 1})
            record = reply.structured_content["result"]
            assert record["state"] == "succeeded" and record["replayed"] is True
            assert len(calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["import", "analysis", "script"])
def test_each_kind_checks_the_deadline_after_preparation(monkeypatch, kind):
    targets, scripts = AnalysisService(), Scripts()
    jobs = OperationManager(targets, script_service=scripts)
    admission = JobAdmission(time.monotonic() + 2)
    request_id = str(uuid4())
    if kind == "import":
        service, method = targets, "prepare_import"
        submit = lambda: jobs.submit_import("default", binary_path="/sample.bin", request_id=request_id)
    elif kind == "analysis":
        service, method = targets, "prepare_analysis"
        submit = lambda: jobs.submit_analysis("default", request_id=request_id)
    else:
        service, method = scripts, "prepare_run"
        submit = lambda: jobs.submit_script("default", source="print(1)", request_id=request_id)
    original = getattr(service, method)

    def prepare(*args, **kwargs):
        admission.expire()
        return original(*args, **kwargs)

    monkeypatch.setattr(service, method, prepare)
    try:
        with pytest.raises(DomainError) as caught:
            admission.run(submit)
        assert caught.value.code is ErrorCode.LOCK_TIMEOUT
        assert not jobs.has_request(request_id)
        assert targets.calls == scripts.calls == []
    finally:
        targets.release.set()
        scripts.release.set()
        jobs.shutdown()
