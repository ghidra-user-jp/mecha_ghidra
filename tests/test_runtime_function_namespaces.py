"""Function namespace edits against disposable real-Ghidra programs."""

import os

import pytest

from test_runtime_readonly_commands import _unwrap_runtime_result
from test_runtime_resource_safety import runtime as _runtime

runtime = _runtime
pytestmark = [
    pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra"),
    pytest.mark.parametrize(
        "runtime",
        [bytes.fromhex("e8 0b 00 00 00 83 c0 01 c3") + b"\x90" * 7 + bytes.fromhex("b8 2a 00 00 00 c3")],
        indirect=True,
    ),
]
TARGET = "resource_safety"


def _rename(runtime, *, address="0x1000", **fields):
    return runtime["apply_edits"](target=TARGET, edits=[{"kind": "rename_function", "address": address, **fields}])


def _function(runtime, address="0x1000"):
    return runtime["get_function"](target=TARGET, address=address)


def _namespaces(runtime):
    return {n["name"] for n in _unwrap_runtime_result(runtime["list_namespaces"](target=TARGET))}


def test_namespace_only_preserves_function_name_source_body_and_references(runtime):
    before = _function(runtime)
    edges = runtime["get_call_edges"](target=TARGET, address="0x1000")["items"]
    result = _rename(runtime, namespace_path="AI::config", create_namespace=True)
    assert result["status"] == "applied", result
    item = result["results"][0]
    assert item["created_namespaces"] == ["AI", "AI::config"]
    assert item["before"]["function"]["namespace"] == ""
    assert item["after"]["function"]["namespace"] == "AI::config"
    after = _function(runtime)
    for key in ("name", "name_source", "entry", "parameters", "local_variables", "body", "return_type"):
        assert after[key] == before[key], key
    assert after["full_name"] == "AI::config::" + before["name"]
    after_edges = runtime["get_call_edges"](target=TARGET, address="0x1000")["items"]
    assert [e["call_site"] for e in after_edges] == [e["call_site"] for e in edges]
    assert [e["callee"] for e in after_edges] == [e["callee"] for e in edges]
    revision = runtime["get_program_info"](target=TARGET)["revision"]
    same = _rename(runtime, namespace_path="AI::config", create_namespace=True)
    assert same["results"][0]["changed"] is False
    assert same["results"][0]["created_namespaces"] == []
    assert same["revision"] == revision
    assert _rename(runtime, namespace_path="")["status"] == "applied"
    restored = _function(runtime)
    assert restored["full_name"] == before["full_name"]
    assert restored["name_source"] == before["name_source"]


def test_rename_and_move_persist_and_name_only_keeps_namespace(runtime):
    result = _rename(runtime, new_name="decrypt_config", namespace_path="AI", create_namespace=True)
    assert result["status"] == "applied", result
    assert _function(runtime)["full_name"] == "AI::decrypt_config"
    result = _rename(runtime, new_name="decode_config")
    assert result["status"] == "applied", result
    assert _function(runtime)["full_name"] == "AI::decode_config"
    assert _function(runtime)["name_source"] == "USER_DEFINED"
    runtime["save_project_program"](target=TARGET)
    runtime["close_session"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    assert _function(runtime)["full_name"] == "AI::decode_config"
    assert "decode_config" in runtime["decompile_function"](target=TARGET, address="0x1000")


def test_namespace_preview_and_failed_batch_remove_created_namespaces(runtime):
    before = _function(runtime)
    edit = {
        "kind": "rename_function",
        "address": "0x1000",
        "new_name": "decode_config",
        "namespace_path": "AI::config",
        "create_namespace": True,
    }
    preview = runtime["apply_edits"](target=TARGET, edits=[edit], dry_run=True)
    assert preview["status"] == "dry_run", preview
    assert preview["results"][0]["after"]["function"]["name"] == "AI::config::decode_config"
    assert preview["results"][0]["status"] == "simulated"
    assert not {"AI", "AI::config"} & _namespaces(runtime)
    assert _function(runtime)["full_name"] == before["full_name"]
    failed = runtime["apply_edits"](
        target=TARGET, edits=[edit, {"kind": "rename_function", "address": "0x9999", "namespace_path": "AI"}]
    )
    assert failed["status"] == "rolled_back", failed
    assert not {"AI", "AI::config"} & _namespaces(runtime)
    assert _function(runtime)["full_name"] == before["full_name"]
    assert _function(runtime)["name_source"] == before["name_source"]


def test_namespace_lookup_is_explicit_and_reuses_existing_namespaces(runtime):
    before = _function(runtime)
    missing = _rename(runtime, namespace_path="AI::config")
    assert missing["results"][0]["error"]["code"] == "NAMESPACE_NOT_FOUND", missing
    assert not {"AI", "AI::config"} & _namespaces(runtime)
    assert _function(runtime)["full_name"] == before["full_name"]
    assert _rename(runtime, namespace_path="AI::config", create_namespace=True)["status"] == "applied"
    reused = _rename(runtime, address="0x1010", namespace_path="AI::config")
    assert reused["status"] == "applied", reused
    assert reused["results"][0]["created_namespaces"] == []
    assert _function(runtime, "0x1010")["namespace"] == "AI::config"


def test_namespace_type_conflict_and_function_scopes(runtime):
    from ghidra.program.model.symbol import SourceType

    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    program = _CONTEXTS[TARGET].program
    tx = program.startTransaction("class fixture")
    try:
        program.getSymbolTable().createClass(program.getGlobalNamespace(), "AI", SourceType.USER_DEFINED)
    finally:
        program.endTransaction(tx, True)
    failed = _rename(runtime, namespace_path="AI::config", create_namespace=True)
    assert failed["results"][0]["error"]["code"] == "INVALID_NAMESPACE_TYPE", failed
    assert "AI::config" not in _namespaces(runtime)
    # A function's local scope is not an ordinary namespace. Creating an
    # ordinary namespace alongside that function remains legal in Ghidra.
    assert _rename(runtime, new_name="config")["status"] == "applied"
    missing = _rename(runtime, address="0x1010", namespace_path="config")
    assert missing["results"][0]["error"]["code"] == "NAMESPACE_NOT_FOUND"
    assert _rename(runtime, address="0x1010", namespace_path="config", create_namespace=True)["status"] == "applied"
    assert _function(runtime, "0x1010")["namespace"] == "config"


def test_same_named_functions_remain_addressable_after_namespace_moves(runtime):
    for address in ("0x1000", "0x1010"):
        result = _rename(runtime, address=address, new_name="decode", namespace_path="AI", create_namespace=True)
        assert result["status"] == "applied", result
    assert _function(runtime)["full_name"] == _function(runtime, "0x1010")["full_name"] == "AI::decode"
    result = _rename(runtime, address="0x1010", namespace_path="AI::config", create_namespace=True)
    assert result["status"] == "applied", result
    assert _function(runtime)["full_name"] == "AI::decode"
    assert _function(runtime, "0x1010")["full_name"] == "AI::config::decode"


def test_namespace_only_keeps_default_function_name_and_source(runtime):
    before = _function(runtime, "0x1010")
    assert before["name"].startswith("FUN_") and before["name_source"] == "DEFAULT"
    result = _rename(runtime, address="0x1010", namespace_path="AI", create_namespace=True)
    assert result["status"] == "applied", result
    after = _function(runtime, "0x1010")
    assert after["name"] == before["name"]
    assert after["name_source"] == "DEFAULT"
    assert after["full_name"] == "AI::" + before["name"]


def test_failed_rename_removes_its_new_namespaces_in_nonatomic_batch(runtime):
    before = _function(runtime, "0x1010")
    result = runtime["apply_edits"](
        target=TARGET,
        atomic=False,
        edits=[
            {"kind": "rename_function", "address": "0x1000", "new_name": "keep"},
            {
                "kind": "rename_function",
                "address": "0x1010",
                "new_name": "bad name",
                "namespace_path": "Failed::nested",
                "create_namespace": True,
            },
            {"kind": "rename_function", "address": "0x1000", "namespace_path": "Kept", "create_namespace": True},
        ],
    )
    assert result["status"] == "partial" and result["applied_count"] == 2, result
    assert result["results"][1]["status"] == "failed"
    assert not {"Failed", "Failed::nested"} & _namespaces(runtime)
    assert _function(runtime, "0x1010")["full_name"] == before["full_name"]
    assert _function(runtime)["full_name"] == "Kept::keep"


def test_default_thunk_namespace_move_never_reports_false_success(runtime):
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    program = _CONTEXTS[TARGET].program
    address = program.getAddressFactory().getAddress
    tx = program.startTransaction("default thunk fixture")
    try:
        destination = program.getFunctionManager().getFunctionAt(address("1000"))
        program.getFunctionManager().getFunctionAt(address("1010")).setThunkedFunction(destination)
    finally:
        program.endTransaction(tx, True)
    before = _function(runtime, "0x1010")
    destination_before = _function(runtime)
    assert before["name_source"] == "DEFAULT"
    result = _rename(runtime, address="0x1010", namespace_path="AI", create_namespace=True)
    assert result["status"] == "rolled_back", result
    assert result["results"][0]["error"]["code"] == "FUNCTION_RENAME_FAILED", result
    assert "AI" not in _namespaces(runtime)
    assert _function(runtime, "0x1010")["full_name"] == before["full_name"]
    assert _function(runtime, "0x1010")["name_source"] == "DEFAULT"
    # Explicitly naming the thunk, even with its current displayed name,
    # permits a distinct namespace without renaming the destination function.
    result = _rename(runtime, address="0x1010", new_name=before["name"], namespace_path="AI", create_namespace=True)
    assert result["status"] == "applied", result
    assert _function(runtime, "0x1010")["full_name"] == "AI::" + before["name"]
    assert _function(runtime)["full_name"] == destination_before["full_name"]
