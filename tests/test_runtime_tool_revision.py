"""Small native regressions for the v1 tool contract."""

import os

import pytest

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


def test_all_comment_types_round_trip_clear_and_disassemble(runtime):
    kinds = ("pre", "eol", "post", "plate", "repeatable")
    edits = [
        {"kind": "set_comment", "address": "0x1000", "comment_type": kind, "comment": f"comment-{kind}"}
        for kind in kinds
    ]
    result = runtime["apply_edits"](target=TARGET, edits=edits)
    assert result["status"] == "applied"
    comments = runtime["get_comments"](target=TARGET, address="0x1000")
    assert {kind: comments[kind] for kind in kinds} == {kind: f"comment-{kind}" for kind in kinds}
    listing = runtime["disassemble"](target=TARGET, address="0x1000", limit=1)
    assert listing["items"][0]["comment"] == "comment-eol"
    result = runtime["apply_edits"](target=TARGET, edits=[{**edit, "comment": ""} for edit in edits])
    assert result["status"] == "applied"
    assert all(item["after"]["comment"] == "" for item in result["results"])
    comments = runtime["get_comments"](target=TARGET, address="0x1000")
    # Ghidra can retain an empty string after a clear; an unset slot returns None.
    assert all(comments[kind] in (None, "") for kind in kinds), comments


def test_explicit_type_category_and_empty_removal(runtime):
    runtime["create_struct"](target=TARGET, name="Header", category="/keep", members=[{"name": "magic", "type": "int"}])
    for name, extra in [("delete_data_type", {}), ("rename_data_type", {"new_name": "changed"})]:
        with pytest.raises(Exception, match="not found"):
            runtime[name](target=TARGET, name="Header", category="/missing", **extra)
    result = runtime["remove_struct_members"](target=TARGET, struct_name="Header", category="/keep", members=[])
    assert [m["name"] for m in result["members"]] == ["magic"]
    with pytest.raises(Exception, match="VALIDATION_ERROR"):
        runtime["remove_struct_members"](target=TARGET, struct_name="Header", category="/keep")
    result = runtime["remove_struct_members"](target=TARGET, struct_name="Header", category="/keep", clear_all=True)
    assert result["members"] == []


def test_duplicate_functions_require_qualification(runtime):
    from ghidra.program.model.symbol import SourceType

    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    p = _CONTEXTS[TARGET].program
    tx = p.startTransaction("namespaces")
    try:
        for namespace, address in [("A", "1000"), ("B", "1010")]:
            ns = p.getSymbolTable().createNameSpace(p.getGlobalNamespace(), namespace, SourceType.USER_DEFINED)
            fn = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress(address))
            fn.setParentNamespace(ns)
            fn.setName("init", SourceType.USER_DEFINED)
    finally:
        p.endTransaction(tx, True)
    runtime["save_project_program"](target=TARGET)
    with pytest.raises(Exception, match="AMBIGUOUS_FUNCTION"):
        runtime["get_function"](target=TARGET, name="init")
    qualified = runtime["get_function"](target=TARGET, name="B::init")
    runtime["apply_edits"](
        target=TARGET, edits=[{"kind": "rename_function", "address": qualified["entry"], "new_name": "changed"}]
    )
    assert runtime["get_function"](target=TARGET, address="0x1000")["full_name"] == "A::init"
    assert runtime["get_function"](target=TARGET, address="0x1010")["full_name"] == "B::changed"


def test_thunk_reports_its_direct_destination(runtime):
    from ghidra.program.model.symbol import SourceType

    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    p = _CONTEXTS[TARGET].program
    tx = p.startTransaction("thunk")
    try:
        ext = p.getExternalManager().addExtFunction("TEST", "external_api", None, SourceType.USER_DEFINED)
        p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("1010")).setThunkedFunction(
            ext.getFunction()
        )
    finally:
        p.endTransaction(tx, True)
    edges = runtime["get_call_edges"](target=TARGET, address="0x1010")["items"]
    assert edges[0]["callee"]["name"] == "TEST::external_api"
    assert edges[0]["kind"] == "thunk" and edges[0]["call_site"] is None
    incoming = runtime["get_call_edges"](target=TARGET, name="TEST::external_api", direction="in")["items"]
    assert incoming[0]["caller"]["entry"] == "00001010"


def test_bsim_reference_checks_program_and_function(runtime, tmp_path):
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    ref = dict(
        matched_ref_version=1,
        executable_md5="0" * 32,
        executable_name="tiny.bin",
        project_location=str(tmp_path),
        project_name="sample",
        domain_path="/tiny.bin",
        address="0x1000",
        name="old_name",
    )
    with pytest.raises(Exception, match="BSIM_MATCH_STALE"):
        runtime["bsim_load_matched_executable"](target=TARGET, matched_ref=ref)
    ref["executable_md5"] = str(_CONTEXTS[TARGET].program.getExecutableMD5())
    ref["address"] = "0x9999"
    with pytest.raises(Exception, match="BSIM_MATCH_STALE"):
        runtime["bsim_load_matched_executable"](target=TARGET, matched_ref=ref)
    ref["address"] = "0x1000"
    result = runtime["bsim_load_matched_executable"](target=TARGET, matched_ref=ref)
    assert result["status"] == "already_loaded"


def test_consolidated_queries_page_and_reject_stale_cursors(runtime):
    first = runtime["disassemble"](target=TARGET, address="0x1000", limit=1)
    assert first["has_more"] and len(first["items"]) == 1
    second = runtime["disassemble"](target=TARGET, address="0x1000", limit=1, cursor=first["next_cursor"])
    assert first["items"][0]["address"] != second["items"][0]["address"]
    ranged = runtime["disassemble"](target=TARGET, start_address="0x1000", length=9)
    assert len(ranged["items"]) == 3 and not ranged["has_more"]
    outgoing = runtime["get_call_edges"](target=TARGET, address="0x1000")
    assert outgoing["items"][0]["call_site"] == "00001000"
    assert outgoing["items"][0]["callee"]["entry"] == "00001010"
    incoming = runtime["get_call_edges"](target=TARGET, address="0x1010", direction="in")
    assert incoming["items"][0]["caller"]["entry"] == "00001000"
    refs = runtime["get_xrefs"](target=TARGET, address="0x1010")
    assert refs["items"][0]["from"] == "00001000"
    assert refs["items"][0]["to"] == "00001010"
    runtime["apply_edits"](
        target=TARGET, edits=[{"kind": "set_comment", "address": "0x1000", "comment_type": "pre", "comment": "changed"}]
    )
    with pytest.raises(Exception, match="SESSION_CHANGED"):
        runtime["disassemble"](target=TARGET, address="0x1000", limit=1, cursor=first["next_cursor"])


def test_consolidated_data_types(runtime):
    runtime["create_struct"](
        target=TARGET, name="Header", category="/types", members=[{"name": "magic", "type": "int"}]
    )
    described = runtime["get_data_type"](target=TARGET, path="/types/Header")
    assert described["members"][0]["name"] == "magic"
    assert "members" not in runtime["get_data_type"](target=TARGET, path="/types/Header", include_members=False)
    runtime["create_enum"](target=TARGET, name="Flags", values={"READ": 1})
    assert runtime["get_data_type"](target=TARGET, path="/Flags")["values"][0]["value"] == 1
    runtime["create_struct"](target=TARGET, name="Header", category="/another")
    with pytest.raises(Exception, match="AMBIGUOUS_DATA_TYPE"):
        runtime["get_data_type"](target=TARGET, path="Header")
    assert runtime["get_data_type"](target=TARGET, path="/types/Header")["members"][0]["name"] == "magic"


def test_batch_edits_commit_preview_and_rollback(runtime):
    revision = runtime["get_program_info"](target=TARGET)["revision"]
    edits = [
        {"kind": "rename_function", "address": "0x1000", "new_name": "main"},
        {"kind": "set_comment", "address": "0x1000", "comment_type": "pre", "comment": "reviewed"},
    ]
    preview = runtime["apply_edits"](target=TARGET, edits=edits, dry_run=True, expected_revision=revision)
    assert preview["status"] == "dry_run" and preview["applied_count"] == 0
    assert preview["results"][0]["after"]["function"]["name"] == "main"
    assert runtime["get_function"](target=TARGET, address="0x1000")["name"] != "main"
    result = runtime["apply_edits"](target=TARGET, edits=edits, expected_revision=preview["revision"])
    assert result["status"] == "applied" and result["applied_count"] == 2
    assert runtime["get_comments"](target=TARGET, address="0x1000")["pre"] == "reviewed"
    with pytest.raises(Exception, match="SESSION_CHANGED"):
        runtime["apply_edits"](target=TARGET, edits=edits, expected_revision=revision)
    bad = [
        {"kind": "rename_function", "address": "0x1000", "new_name": "must_rollback"},
        {"kind": "rename_function", "address": "0x9999", "new_name": "invalid"},
    ]
    failed = runtime["apply_edits"](target=TARGET, edits=bad)
    assert failed["status"] == "rolled_back" and failed["applied_count"] == 0
    assert runtime["get_function"](target=TARGET, address="0x1000")["name"] == "main"
    failed_preview = runtime["apply_edits"](target=TARGET, edits=bad, dry_run=True)
    assert failed_preview["status"] == "dry_run_failed" and failed_preview["applied_count"] == 0
    assert runtime["get_function"](target=TARGET, address="0x1000")["name"] == "main"
    partial = runtime["apply_edits"](target=TARGET, edits=bad, atomic=False)
    assert partial["status"] == "partial" and partial["applied_count"] == 1
    assert runtime["get_function"](target=TARGET, address="0x1000")["name"] == "must_rollback"


def test_open_program_reopens_an_existing_project(runtime, tmp_path):
    runtime["close_session"](target=TARGET)
    result = runtime["open_program"](
        target=TARGET, project_location=str(tmp_path), project_name="sample", domain_path="/tiny.bin"
    )
    assert result["status"] == "ok" and result["domain_path"] == "/tiny.bin"


def test_batch_edits_support_variable_prototype_and_data_changes(runtime):
    runtime["create_label"](target=TARGET, address="0x1009", name="initial_data")
    result = runtime["apply_edits"](
        target=TARGET,
        edits=[
            {"kind": "set_function_prototype", "function_address": "0x1000", "prototype": "int caller(void)"},
            {"kind": "rename_variable", "function_address": "0x1000", "old_name": "iVar1", "new_name": "answer"},
            {
                "kind": "set_local_variable_type",
                "function_address": "0x1000",
                "variable_name": "answer",
                "new_type": "uint",
            },
            {"kind": "set_global_data_type", "address": "0x1009", "data_type": "int", "length": 4},
            {"kind": "rename_data", "address": "0x1009", "new_name": "decoded_count"},
        ],
    )
    assert result["status"] == "applied", result
    assert result["applied_count"] == 5
    assert result["results"][1]["after"]["variable"]["name"] == "answer"
    assert result["results"][4]["after"]["name"] == "decoded_count"


def test_call_edges_exclude_data_refs_and_keep_unresolved_calls(runtime):
    from ghidra.program.model.symbol import RefType, SourceType

    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    p = _CONTEXTS[TARGET].program
    manager = p.getReferenceManager()
    address = p.getAddressFactory().getAddress
    tx = p.startTransaction("data reference")
    try:
        manager.addMemoryReference(address("1005"), address("1010"), RefType.DATA, SourceType.USER_DEFINED, 0)
    finally:
        p.endTransaction(tx, True)
    assert len(runtime["get_xrefs"](target=TARGET, address="0x1010")["items"]) == 2
    incoming = runtime["get_call_edges"](target=TARGET, address="0x1010", direction="in")["items"]
    assert len(incoming) == 1 and incoming[0]["call_site"] == "00001000"
    tx = p.startTransaction("unresolved call")
    try:
        manager.removeAllReferencesFrom(address("1000"))
    finally:
        p.endTransaction(tx, True)
    outgoing = runtime["get_call_edges"](target=TARGET, address="0x1000")["items"]
    assert len(outgoing) == 1 and outgoing[0]["resolved"] is False
    assert outgoing[0]["callee"] is None and outgoing[0]["call_site"] == "00001000"
    assert runtime["get_call_edges"](target=TARGET, address="0x1000", include_unresolved=False)["items"] == []


def test_disassembly_seek_preserves_holes_and_converts_only_returned_instructions(runtime, monkeypatch):
    from ghidra.program.model.address import AddressSet

    from ghidra_headless.handlers.commands import analysis_queries
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    program = _CONTEXTS[TARGET].program
    address = program.getAddressFactory().getAddress
    function = program.getFunctionManager().getFunctionAt(address("1000"))
    body = AddressSet(address("1000"), address("1004"))
    body.add(address("1008"))
    tx = program.startTransaction("non-contiguous test function")
    try:
        function.setBody(body)
    finally:
        program.endTransaction(tx, True)
    converted = []
    original = analysis_queries._instruction_to_dict

    def recording(inst, comment_types):
        converted.append(str(inst.getAddress()))
        return original(inst, comment_types)

    monkeypatch.setattr(analysis_queries, "_instruction_to_dict", recording)
    first = runtime["disassemble"](target=TARGET, address="0x1000", limit=1)
    second = runtime["disassemble"](target=TARGET, address="0x1000", limit=1, cursor=first["next_cursor"])
    assert [first["items"][0]["address"], second["items"][0]["address"]] == ["00001000", "00001008"]
    assert converted == ["00001000", "00001008"]
    assert second["next_cursor"] is None and not second["has_more"]
