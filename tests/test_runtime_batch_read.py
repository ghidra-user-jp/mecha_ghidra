"""Batch reads against an isolated real Ghidra project."""

import json
import os

import pytest

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


def test_native_batch_matches_five_individual_reads_and_enters_core_once(runtime, monkeypatch):
    from ghidra_headless.handlers import core

    runtime["create_struct"](
        target=TARGET, name="Header", category="/batch", members=[{"name": "magic", "type": "int"}]
    )
    requests = [
        {"id": "function", "tool": "get_function", "arguments": {"address": "0x1000"}},
        {"id": "comments", "tool": "get_comments", "arguments": {"address": "0x1000"}},
        {"id": "type", "tool": "get_data_type", "arguments": {"path": "/batch/Header"}},
        {"id": "refs", "tool": "get_xrefs", "arguments": {"address": "0x1010"}},
        {"id": "calls", "tool": "get_call_edges", "arguments": {"address": "0x1000"}},
    ]
    expected = [runtime[item["tool"]](target=TARGET, **item["arguments"]) for item in requests]
    original = core.execute
    calls = []

    def execute(command, params, key="default"):
        calls.append(command)
        return original(command, params, key)

    monkeypatch.setattr(core, "execute", execute)
    response = runtime["batch_read"](target=TARGET, requests=requests)
    payload = json.loads(response.content[0].text)
    assert not response.is_error and payload["succeeded_count"] == 5
    assert [item["data"] for item in payload["items"]] == expected
    assert calls == ["batch_read"]


def test_native_partial_failure_and_stale_revision(runtime):
    requests = [
        {"id": "missing", "tool": "get_function", "arguments": {"address": "0xffff"}},
        {"id": "valid", "tool": "get_comments", "arguments": {"address": "0x1000"}},
    ]
    response = runtime["batch_read"](target=TARGET, requests=requests)
    payload = json.loads(response.content[0].text)
    assert not response.is_error and payload["status"] == "partial"
    assert payload["items"][0]["error"]["code"] == "NOT_FOUND"
    runtime["apply_edits"](
        target=TARGET, edits=[{"kind": "set_comment", "address": "0x1000", "comment_type": "pre", "comment": "changed"}]
    )
    with pytest.raises(Exception, match="SESSION_CHANGED"):
        runtime["batch_read"](target=TARGET, requests=requests, expected_revision=payload["revision"])


def test_native_edit_during_read_invalidates_all_results(runtime, monkeypatch):
    from ghidra.program.model.listing import CommentType

    from ghidra_headless.handlers import core
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    original = core.SUPPORTED_COMMANDS["get_comments"]

    def read_and_edit(params):
        value = original(params)
        program = _CONTEXTS[TARGET].program
        tx = program.startTransaction("simulate external edit during read")
        try:
            program.getListing().setComment(program.getAddressFactory().getAddress("1000"), CommentType.PRE, "changed")
        finally:
            program.endTransaction(tx, True)
        return value

    monkeypatch.setitem(core.SUPPORTED_COMMANDS, "get_comments", read_and_edit)
    with pytest.raises(Exception, match="SESSION_CHANGED"):
        runtime["batch_read"](
            target=TARGET, requests=[{"id": "a", "tool": "get_comments", "arguments": {"address": "0x1000"}}]
        )
