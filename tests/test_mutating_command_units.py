from __future__ import annotations

from types import SimpleNamespace

import pytest

from ghidra_headless.handlers.commands.mutating_data_types import clear_struct, remove_struct_members
from ghidra_headless.handlers.commands.mutating_symbols import rename_data


class _Symbol:
    def __init__(self, name: str = "old_name") -> None:
        self.name = name

    def setName(self, name, _source_type):
        self.name = name

    def getName(self):
        return self.name

    def getAddress(self):
        return "00402000"


class _EmptyStructure:
    def __init__(self) -> None:
        self.delete_all_calls = 0

    def deleteAll(self):
        self.delete_all_calls += 1


class _LegacyEmptyStructure:
    def getNumComponents(self):
        return 0

    def getComponents(self):
        return []

    def delete(self, _ordinal):
        raise AssertionError("an empty structure must not delete any component")


def _run_transaction(_ctx, _description, operation):
    return operation()


def test_rename_data_rejects_function_entry_without_mutating_symbol():
    symbol = _Symbol("function_name")
    context = SimpleNamespace(
        function_manager=SimpleNamespace(getFunctionAt=lambda _address: object()),
        symbol_table=SimpleNamespace(getPrimarySymbol=lambda _address: symbol),
    )

    with pytest.raises(ValueError, match="use rename_function instead"):
        rename_data(
            {"address": "00402000", "newName": "data_name"},
            ensure_context=lambda: context,
            get_address=lambda _ctx, text: text,
            txn=_run_transaction,
            source_type=SimpleNamespace(USER_DEFINED="user"),
        )

    assert symbol.getName() == "function_name"


def test_rename_data_renames_non_function_primary_symbol():
    symbol = _Symbol()
    context = SimpleNamespace(
        function_manager=SimpleNamespace(getFunctionAt=lambda _address: None),
        symbol_table=SimpleNamespace(getPrimarySymbol=lambda _address: symbol),
    )

    result = rename_data(
        {"address": "00402000", "newName": "new_name"},
        ensure_context=lambda: context,
        get_address=lambda _ctx, text: text,
        txn=_run_transaction,
        source_type=SimpleNamespace(USER_DEFINED="user"),
    )

    assert result == {"name": "new_name", "address": "00402000"}


def test_clear_struct_accepts_an_already_empty_structure():
    structure = _EmptyStructure()
    manager = SimpleNamespace(replaceDataType=lambda *_args: None)
    context = object()

    result = clear_struct(
        {"struct_name": "Empty"},
        ensure_context=lambda: context,
        txn=_run_transaction,
        get_struct_datatype=lambda _ctx, _name, _category: structure,
        safe_call=lambda obj, method: getattr(obj, method)(),
        iter_items=iter,
        dt_manager=lambda _ctx: manager,
        describe_struct=lambda _struct: {"name": "Empty", "members": []},
    )

    assert result == {"name": "Empty", "members": []}
    assert structure.delete_all_calls == 1


def test_clear_struct_accepts_an_already_empty_structure_without_delete_all():
    structure = _LegacyEmptyStructure()
    manager = SimpleNamespace(replaceDataType=lambda *_args: None)
    context = object()

    result = clear_struct(
        {"struct_name": "Empty"},
        ensure_context=lambda: context,
        txn=_run_transaction,
        get_struct_datatype=lambda _ctx, _name, _category: structure,
        safe_call=lambda obj, method: getattr(obj, method)(),
        iter_items=iter,
        dt_manager=lambda _ctx: manager,
        describe_struct=lambda _struct: {"name": "Empty", "members": []},
    )

    assert result == {"name": "Empty", "members": []}


def test_remove_struct_members_deletes_matching_ordinals_in_reverse_order():
    components = [
        SimpleNamespace(getFieldName=lambda: "first", getOrdinal=lambda: 0),
        SimpleNamespace(getFieldName=lambda: "second", getOrdinal=lambda: 1),
        SimpleNamespace(getFieldName=lambda: "keep", getOrdinal=lambda: 2),
        SimpleNamespace(getFieldName=lambda: "fourth", getOrdinal=lambda: 3),
    ]

    class _Structure:
        def __init__(self):
            self.deleted = []

        def getComponents(self):
            return components

        def delete(self, ordinal):
            self.deleted.append(ordinal)

    structure = _Structure()
    manager = SimpleNamespace(replaceDataType=lambda *_args: None)

    result = remove_struct_members(
        {"struct_name": "Fields", "members": ["first", "second", "fourth"]},
        ensure_context=lambda: object(),
        txn=_run_transaction,
        get_struct_datatype=lambda *_args: structure,
        dt_manager=lambda _ctx: manager,
        describe_struct=lambda _struct: {"name": "Fields"},
    )

    assert result == {"name": "Fields"}
    assert structure.deleted == [3, 1, 0]
