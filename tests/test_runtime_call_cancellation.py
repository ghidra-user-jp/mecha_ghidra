"""A read whose request is cancelled stops in real Ghidra, and the next read still works."""

import json
import os
import threading

import pytest

from ghidra_mcp.application.cancellation import CallCancellation, bound
from test_runtime_resource_safety import runtime as _runtime

runtime = _runtime
TARGET = "resource_safety"
pytestmark = [
    pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra"),
    pytest.mark.parametrize(
        "runtime",
        [bytes.fromhex("e8 0b 00 00 00 83 c0 01 c3") + b"\x90" * 7 + bytes.fromhex("b8 2a 00 00 00 c3")],
        indirect=True,
    ),
]


def test_a_read_cancelled_as_it_starts_stops_the_decompiler_and_the_next_read_works(runtime, monkeypatch):
    from ghidra_headless.handlers import core

    original = core.execute
    cancellation = CallCancellation()
    monitors = []

    def cancel_as_the_read_starts(command, params, key="default", **kwargs):
        monitors.append(kwargs["task_monitor"])
        cancellation.cancel()  # the request goes away: the read's Ghidra monitor is cancelled
        return original(command, params, key, **kwargs)

    monkeypatch.setattr(core, "execute", cancel_as_the_read_starts)
    with bound(cancellation), pytest.raises(Exception) as stopped:
        runtime["decompile_function"](target=TARGET, address="0x1000")
    assert monitors[0].isCancelled(), "the read ran with the monitor its request cancelled"
    assert "FUN_00001000" not in str(stopped.value), "a stopped decompile returns no code"
    monkeypatch.setattr(core, "execute", original)
    assert "FUN_00001000" in runtime["decompile_function"](target=TARGET, address="0x1000")


def test_a_read_cancelled_before_it_runs_does_not_run(runtime, monkeypatch):
    from ghidra_headless.handlers import core

    original = core.execute
    calls = []
    monkeypatch.setattr(core, "execute", lambda *args, **kwargs: calls.append(args) or original(*args, **kwargs))
    cancellation = CallCancellation()
    cancellation.cancel()
    with bound(cancellation), pytest.raises(Exception, match="OPERATION_CANCELLED"):
        runtime["decompile_function"](target=TARGET, address="0x1000")
    assert calls == []


def test_a_batch_cancelled_while_it_decompiles_stops_and_the_next_read_works(runtime, monkeypatch):
    from ghidra_headless.handlers import core

    original = core.execute
    cancellation = CallCancellation()

    def cancel_soon(command, params, key="default", **kwargs):
        threading.Timer(0.01, cancellation.cancel).start()  # during the first decompile, which starts the decompiler
        return original(command, params, key, **kwargs)

    monkeypatch.setattr(core, "execute", cancel_soon)
    requests = [{"id": str(i), "tool": "decompile_function", "arguments": {"address": "0x1000"}} for i in range(5)]
    with bound(cancellation), pytest.raises(Exception, match="OPERATION_CANCELLED"):
        runtime["batch_read"](target=TARGET, requests=requests, timeout_seconds=30)
    monkeypatch.setattr(core, "execute", original)
    # The decompiler a cancelled read killed is replaced, and a whole batch runs after it.
    again = runtime["batch_read"](target=TARGET, requests=requests[:2], timeout_seconds=30)
    assert json.loads(again.content[0].text)["succeeded_count"] == 2
    assert "FUN_00001000" in runtime["decompile_function"](target=TARGET, address="0x1000")
