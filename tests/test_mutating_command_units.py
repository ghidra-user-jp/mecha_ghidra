from __future__ import annotations

from types import SimpleNamespace

import pytest

from ghidra_headless.handlers.commands.mutating_data_types import remove_struct_members
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


class _LegacyEmptyStructure:
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


def test_remove_struct_members_clear_all_clears_an_already_empty_structure():
    structure = _LegacyEmptyStructure()
    manager = SimpleNamespace(replaceDataType=lambda *_args: None)

    result = remove_struct_members(
        {"struct_name": "Empty", "clear_all": True},
        ensure_context=lambda: object(),
        txn=_run_transaction,
        get_struct_datatype=lambda _ctx, _name, _category: structure,
        dt_manager=lambda _ctx: manager,
        describe_struct=lambda _struct: {"name": "Empty", "members": []},
    )

    assert result == {"name": "Empty", "members": []}


def test_remove_struct_members_clear_all_removes_everything():
    components = [
        SimpleNamespace(getFieldName=lambda: "first", getOrdinal=lambda: 0),
        SimpleNamespace(getFieldName=lambda: "second", getOrdinal=lambda: 1),
    ]

    class _Structure:
        def __init__(self):
            self.deleted = []

        def getComponents(self):
            return components

        def delete(self, ordinal):
            self.deleted.append(ordinal)

    structure = _Structure()
    descriptions = []

    remove_struct_members(
        {"struct_name": "Fields", "clear_all": True},
        ensure_context=lambda: object(),
        txn=lambda _ctx, description, operation: (descriptions.append(description), operation())[1],
        get_struct_datatype=lambda *_args: structure,
        dt_manager=lambda _ctx: SimpleNamespace(replaceDataType=lambda *_args: None),
        describe_struct=lambda _struct: {"name": "Fields"},
    )

    assert structure.deleted == [1, 0]
    assert descriptions == ["Clear struct"]


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


class _SymbolIterator:
    def __init__(self, symbols) -> None:
        self._symbols = list(symbols)

    def hasNext(self):
        return bool(self._symbols)

    def next(self):
        return self._symbols.pop(0)


def _variable_edit_fixture(*, edited_while_decompiling: bool):
    """A program whose modification number moves while the function decompiles, as a GUI human's edit would."""
    program = SimpleNamespace(modification=5)
    program.getModificationNumber = lambda: program.modification
    symbol = SimpleNamespace(getName=lambda: "param_1")
    high_function = SimpleNamespace(
        getLocalSymbolMap=lambda: SimpleNamespace(getSymbols=lambda: _SymbolIterator([symbol]))
    )
    function = SimpleNamespace(getName=lambda: "main", getSignatureSource=lambda: "user")
    ctx = SimpleNamespace(
        program=program, function_manager=SimpleNamespace(getFunctionContaining=lambda _address: function)
    )

    def decompile(_ctx, _function):
        if edited_while_decompiling:
            program.modification += 1
        return high_function

    applied = []
    dependencies = dict(
        ensure_context=lambda: ctx,
        get_address=lambda _ctx, text: text,
        find_function_by_name=lambda _ctx, _name: function,
        decompile_high_function=decompile,
        requires_full_param_commit=lambda _symbol, _high: False,
        high_function_db_util=SimpleNamespace(updateDBVariable=lambda *args: applied.append(args)),
        txn=lambda _ctx, _description, func: func(),
        source_type=SimpleNamespace(USER_DEFINED="user"),
    )
    return dependencies, applied


@pytest.mark.parametrize("edited_while_decompiling", [False, True])
def test_variable_edits_never_apply_a_decompiled_view_the_program_moved_past(edited_while_decompiling):
    """rename_variable and set_local_variable_type decompile before their transaction (GUI: off the EDT)."""
    from ghidra_headless.errors import HeadlessError
    from ghidra_headless.handlers.commands.mutating_symbols import rename_variable, set_local_variable_type

    calls = [
        lambda deps: rename_variable({"functionAddress": "0x1000", "oldName": "param_1", "newName": "ctx"}, **deps),
        lambda deps: set_local_variable_type(
            {"function_address": "0x1000", "variable_name": "param_1", "new_type": "int"},
            parse_data_type=lambda _ctx, text: text,
            **deps,
        ),
    ]
    for call in calls:
        dependencies, applied = _variable_edit_fixture(edited_while_decompiling=edited_while_decompiling)
        if edited_while_decompiling:
            with pytest.raises(HeadlessError) as raised:
                call(dependencies)
            assert raised.value.code == "SESSION_CHANGED" and applied == []
        else:
            call(dependencies)
            assert len(applied) == 1
