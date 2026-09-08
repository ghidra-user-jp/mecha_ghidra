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
        runtime["rename_function"](target=TARGET, old_name="init", new_name="changed")
    runtime["rename_function"](target=TARGET, old_name="B::init", new_name="changed")
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
    assert runtime["get_callee"](target=TARGET, address="0x1010")[0]["name"] == "TEST::external_api"


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
