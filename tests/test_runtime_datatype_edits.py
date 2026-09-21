"""Real-Ghidra regressions for structure placement and enum replacement."""

import os

import pytest

from test_runtime_resource_safety import runtime as _runtime

runtime = _runtime
TARGET = "resource_safety"
pytestmark = pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra")


def _named_members(result):
    return {item["name"]: (item["offset"], item["length"]) for item in result["members"] if item["name"]}


@pytest.mark.parametrize("offset,size", [(0, None), (16, None), (0, 4)])
@pytest.mark.parametrize("data_type,length", [("int", 4), ("char", 1)])
def test_create_struct_reserves_space_for_explicit_member(runtime, offset, size, data_type, length):
    options = {} if size is None else {"size": size}
    result = runtime["create_struct"](
        target=TARGET,
        name="Layout",
        members=[{"name": "value", "type": data_type, "offset": offset}],
        **options,
    )
    assert result["length"] == max(size or 0, offset + length)
    assert _named_members(result) == {"value": (offset, length)}


@pytest.mark.parametrize("offset", [4, 16])
def test_add_struct_member_at_or_beyond_end_preserves_existing_offsets(runtime, offset):
    runtime["create_struct"](target=TARGET, name="Layout", members=[{"name": "first", "type": "int"}])
    result = runtime["add_struct_members"](
        target=TARGET, struct_name="Layout", members=[{"name": "second", "type": "short", "offset": offset}]
    )
    assert result["length"] == offset + 2
    assert _named_members(result) == {"first": (0, 4), "second": (offset, 2)}


def test_mixed_struct_placement_preserves_offsets_after_save_and_reload(runtime):
    runtime["create_struct"](
        target=TARGET,
        name="Layout",
        members=[
            {"name": "later", "type": "int", "offset": 16},
            {"name": "first", "type": "int", "offset": 0},
            {"name": "appended", "type": "short"},
        ],
    )
    runtime["add_struct_members"](
        target=TARGET, struct_name="Layout", members=[{"name": "middle", "type": "int", "offset": 8}]
    )
    runtime["save_project_program"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    result = runtime["get_data_type"](target=TARGET, path="/Layout")
    assert result["length"] == 22
    assert _named_members(result) == {
        "first": (0, 4),
        "middle": (8, 4),
        "later": (16, 4),
        "appended": (20, 2),
    }


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("invalid_offset", [-1, 32.5, True])
def test_invalid_offset_rolls_back_prior_structure_growth(runtime, existing, invalid_offset):
    before = None
    if existing:
        before = runtime["create_struct"](target=TARGET, name="Layout", members=[{"name": "first", "type": "int"}])
    tool = "add_struct_members" if existing else "create_struct"
    selector = {"struct_name" if existing else "name": "Layout"}
    with pytest.raises(Exception, match="VALIDATION_ERROR"):
        runtime[tool](
            target=TARGET,
            **selector,
            members=[
                {"name": "temporary", "type": "int", "offset": 16},
                {"name": "invalid", "type": "int", "offset": invalid_offset},
            ],
        )
    if existing:
        after = runtime["get_data_type"](target=TARGET, path="/Layout")
        assert after["length"] == before["length"]
        assert after["members"] == before["members"]
    else:
        with pytest.raises(Exception, match="Data type not found"):
            runtime["get_data_type"](target=TARGET, path="/Layout")


def _packet_type():
    from ghidra_headless.handlers import core_runtime

    return core_runtime._CONTEXTS[TARGET].program.getDataTypeManager().getDataType("/Packet")


def _parse_packed_packet(runtime):
    runtime["parse_c_declarations"](target=TARGET, source="struct Packet { char tag; int value; char tail; };")
    assert _packet_type().isPackingEnabled()
    result = runtime["get_data_type"](target=TARGET, path="/Packet")
    assert result["length"] == 12
    assert _named_members(result) == {"tag": (0, 1), "value": (4, 4), "tail": (8, 1)}
    return result


@pytest.mark.parametrize("offset", [0, 2, 4, 12, 16])
def test_explicit_offset_freezes_packed_layout_after_save_and_reload(runtime, offset):
    before = _parse_packed_packet(runtime)
    expected = _named_members(before)
    if offset == 0:
        expected.pop("tag")
    elif offset == 4:
        expected.pop("value")
    expected["extra"] = (offset, 1)
    result = runtime["add_struct_members"](
        target=TARGET, struct_name="Packet", members=[{"name": "extra", "type": "char", "offset": offset}]
    )
    assert _named_members(result) == expected
    assert result["length"] == max(12, offset + 1)
    assert not _packet_type().isPackingEnabled()
    runtime["save_project_program"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    reloaded = runtime["get_data_type"](target=TARGET, path="/Packet")
    assert reloaded["members"] == result["members"]
    assert reloaded["length"] == result["length"]
    assert not _packet_type().isPackingEnabled()


def test_implicit_append_keeps_packed_layout_after_save_and_reload(runtime):
    _parse_packed_packet(runtime)
    result = runtime["add_struct_members"](
        target=TARGET, struct_name="Packet", members=[{"name": "extra", "type": "char"}]
    )
    assert _named_members(result) == {"tag": (0, 1), "value": (4, 4), "tail": (8, 1), "extra": (9, 1)}
    assert result["length"] == 12
    assert _packet_type().isPackingEnabled()
    runtime["save_project_program"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    reloaded = runtime["get_data_type"](target=TARGET, path="/Packet")
    assert reloaded["members"] == result["members"]
    assert reloaded["length"] == result["length"]
    assert _packet_type().isPackingEnabled()


def test_mixed_offsets_switch_packed_layout_at_the_explicit_edit(runtime):
    _parse_packed_packet(runtime)
    result = runtime["add_struct_members"](
        target=TARGET,
        struct_name="Packet",
        members=[
            {"name": "auto_append", "type": "char"},
            {"name": "replacement", "type": "char", "offset": 4},
            {"name": "manual_append", "type": "char"},
        ],
    )
    assert _named_members(result) == {
        "tag": (0, 1),
        "replacement": (4, 1),
        "tail": (8, 1),
        "auto_append": (9, 1),
        "manual_append": (12, 1),
    }
    assert result["length"] == 13
    assert not _packet_type().isPackingEnabled()


@pytest.mark.parametrize("offset,error", [(-1, "VALIDATION_ERROR"), (2, "Not enough undefined bytes")])
def test_failed_edit_restores_packing_and_layout_after_save_and_reload(runtime, offset, error):
    before = _parse_packed_packet(runtime)
    with pytest.raises(Exception, match=error):
        runtime["add_struct_members"](
            target=TARGET,
            struct_name="Packet",
            members=[
                {"name": "temporary", "type": "char", "offset": 16},
                {"name": "invalid", "type": "int", "offset": offset},
            ],
        )
    after = runtime["get_data_type"](target=TARGET, path="/Packet")
    assert after["members"] == before["members"]
    assert after["length"] == before["length"]
    assert _packet_type().isPackingEnabled()
    runtime["save_project_program"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    reloaded = runtime["get_data_type"](target=TARGET, path="/Packet")
    assert reloaded["members"] == before["members"]
    assert reloaded["length"] == before["length"]
    assert _packet_type().isPackingEnabled()


@pytest.mark.parametrize("signed_before", [True, False])
@pytest.mark.parametrize("order", [("A", "B"), ("B", "A")])
def test_enum_replacement_is_independent_of_key_order(runtime, signed_before, order):
    initial = {"A": -1, "B": -2} if signed_before else {"A": 255, "B": 254}
    final = {"A": 255, "B": 1} if signed_before else {"A": -1, "B": 1}
    runtime["create_enum"](
        target=TARGET,
        name="Codes",
        size=1,
        values={**initial, "KEEP": {"value": 5, "comment": "preserved"}, "DROP": 9},
    )
    result = runtime["set_enum_values"](
        target=TARGET,
        name="Codes",
        values={key: {"value": final[key], "comment": f"updated {key}"} for key in order},
        remove=["DROP"],
    )
    assert {item["name"]: item["value"] for item in result["values"]} == {**final, "KEEP": 5}
    assert {item["name"]: item["comment"] for item in result["values"]} == {
        "A": "updated A",
        "B": "updated B",
        "KEEP": "preserved",
    }
    assert result["isSigned"] is not signed_before
    runtime["save_project_program"](target=TARGET)
    runtime["load_project_program"](target=TARGET, domain_path="/tiny.bin")
    after = runtime["get_data_type"](target=TARGET, path="/Codes")
    assert after["values"] == result["values"]
    assert after["isSigned"] == result["isSigned"]


@pytest.mark.parametrize("retained,replacement", [(-2, 255), (254, -1)])
def test_enum_replacement_conflicting_with_retained_values_rolls_back(runtime, retained, replacement):
    before = runtime["create_enum"](
        target=TARGET,
        name="Codes",
        size=1,
        values={"A": 1, "KEEP": {"value": retained, "comment": "preserved"}, "DROP": 9},
    )
    with pytest.raises(Exception, match="outside the range"):
        runtime["set_enum_values"](target=TARGET, name="Codes", values={"A": replacement}, remove=["DROP"])
    after = runtime["get_data_type"](target=TARGET, path="/Codes")
    assert after["values"] == before["values"]
    assert after["isSigned"] == before["isSigned"]
