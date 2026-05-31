from __future__ import annotations

from ghidra_headless.handlers.commands.mutating_symbols import rename_function
from ghidra_headless.handlers.commands.read_only_decompile import decompile_function


class _Function:
    def __init__(self, name: str, entry: str) -> None:
        self.name = name
        self.entry = entry
        self.renamed_with = None

    def setName(self, new_name, source_type):  # noqa: N802
        self.name = new_name
        self.renamed_with = source_type

    def getName(self):  # noqa: N802
        return self.name

    def getEntryPoint(self):  # noqa: N802
        return self.entry


class _FunctionManager:
    def __init__(self, function: _Function) -> None:
        self.function = function

    def getFunctionContaining(self, address):  # noqa: N802, ARG002
        return self.function


class _Context:
    def __init__(self, function: _Function) -> None:
        self.function_manager = _FunctionManager(function)


class _SourceType:
    USER_DEFINED = object()


def test_decompile_function_prefers_address_over_name():
    address_function = _Function("by_address", "0x401000")
    ctx = _Context(address_function)

    def find_function_by_name(_ctx, _name):  # noqa: ARG001
        raise AssertionError("name lookup should not run when address is provided")

    result = decompile_function(
        {"address": "0x401000", "name": "by_name"},
        ensure_context=lambda: ctx,
        get_address=lambda _ctx, text: text,
        find_function_by_name=find_function_by_name,
        decompile_function_object=lambda _ctx, function: function.getName(),
    )

    assert result == "by_address"


def test_rename_function_prefers_address_over_name():
    address_function = _Function("by_address", "0x401000")
    ctx = _Context(address_function)

    def find_function_by_name(_ctx, _name):  # noqa: ARG001
        raise AssertionError("name lookup should not run when address is provided")

    result = rename_function(
        {"address": "0x401000", "oldName": "by_name", "newName": "renamed"},
        ensure_context=lambda: ctx,
        get_address=lambda _ctx, text: text,
        find_function_by_name=find_function_by_name,
        txn=lambda _ctx, _description, func: func(),
        source_type=_SourceType,
    )

    assert result == {"name": "renamed", "entry": "0x401000"}
    assert address_function.renamed_with is _SourceType.USER_DEFINED
