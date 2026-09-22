"""Public and direct-core validation for optional function names and namespaces."""

import pytest
from pydantic import ValidationError

from ghidra_headless.contracts.function_edits import validate_function_rename
from ghidra_mcp.contracts.tool_spec import get_tool_spec


@pytest.mark.parametrize(
    "fields",
    [
        {"new_name": "decode_config"},
        {"namespace_path": "AI"},
        {"new_name": None, "namespace_path": "AI::crypto", "create_namespace": True},
        {"namespace_path": ""},
        {"new_name": "decode_config", "namespace_path": None},
        {"new_name": "decode_config", "namespace_path": "AI"},
    ],
)
def test_function_rename_accepts_name_namespace_or_both(fields):
    spec = get_tool_spec("apply_edits")
    edit = {"kind": "rename_function", "address": "0x1000", **fields}
    parsed = spec.input_model.model_validate({"edits": [edit]})
    serialized = parsed.model_dump()["edits"][0]
    assert all(serialized[key] == value for key, value in fields.items())


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"new_name": None, "namespace_path": None},
        {"new_name": ""},
        {"new_name": "AI::decode"},
        {"new_name": "decode", "create_namespace": True},
        {"namespace_path": "AI", "create_namespace": "true"},
        {"namespace_path": "AI", "create_namespace": 1},
        {"namespace_path": "AI", "create_namespace": None},
        {"namespace_path": "::AI"},
        {"namespace_path": "AI::"},
        {"namespace_path": "AI::::crypto"},
        {"namespace_path": "AI:crypto"},
        {"namespace_path": " AI"},
        {"namespace_path": "AI::bad name"},
        {"namespace_path": "AI::bad\x00name"},
        {"namespace_path": 42},
        {"namespace_path": "x" * 1025},
        {"namespace_path": "::".join(["x" * 1024] * 5)},
        {"new_name": "x" * 1025},
        {"new_name": 42},
    ],
)
def test_public_schema_and_core_reject_the_same_invalid_edits(fields):
    with pytest.raises(ValidationError):
        get_tool_spec("apply_edits").input_model.model_validate(
            {"edits": [{"kind": "rename_function", "address": "0x1000", **fields}]}
        )
    with pytest.raises(ValueError):
        validate_function_rename(
            fields.get("new_name"), fields.get("namespace_path"), fields.get("create_namespace", False)
        )


def test_schema_advertises_optional_name_and_namespace_semantics():
    schema = get_tool_spec("apply_edits").input_model.model_json_schema()["$defs"]["RenameFunctionEdit"]
    assert set(schema["required"]) == {"kind", "address"}
    assert schema["properties"]["create_namespace"]["default"] is False
    assert "Global" in schema["properties"]["namespace_path"]["description"]
