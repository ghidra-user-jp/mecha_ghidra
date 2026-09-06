"""Unit tests for the program-level commands (metadata, comments, symbols, labels, undo/redo, export)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ghidra_headless.handlers.commands.mutating_data_types import create_enum, set_enum_values
from ghidra_headless.handlers.commands.program_tools import (
    create_label,
    export_program,
    get_comments,
    redo_program_change,
    search_symbols,
    undo_program_change,
)


def _safe_call(obj, name, *args):
    method = getattr(obj, name, None)
    if method is None:
        return None
    try:
        return method(*args)
    except Exception:
        return None


def _to_int(value, default):
    return default if value is None else int(value)


def _txn(_ctx, _description, operation):
    return operation()


class _UndoableProgram:
    def __init__(self, history: list[str]) -> None:
        self.history = list(history)
        self.redo_stack: list[str] = []

    def canUndo(self):
        return bool(self.history)

    def canRedo(self):
        return bool(self.redo_stack)

    def getUndoName(self):
        return self.history[-1]

    def getRedoName(self):
        return self.redo_stack[-1]

    def undo(self):
        self.redo_stack.append(self.history.pop())

    def redo(self):
        self.history.append(self.redo_stack.pop())

    def getAllUndoNames(self):
        return list(reversed(self.history))

    def getAllRedoNames(self):
        return list(reversed(self.redo_stack))


def _undo_context(program):
    return SimpleNamespace(program=program)


def test_undo_and_redo_walk_the_transaction_history():
    program = _UndoableProgram(["Rename function", "Set pre comment", "Create label"])

    result = undo_program_change(
        {"count": 2},
        ensure_context=lambda: _undo_context(program),
        safe_call=_safe_call,
        iter_items=iter,
    )

    assert result["status"] == "ok"
    assert result["undone"] == ["Create label", "Set pre comment"]
    assert result["undone_count"] == 2
    assert result["can_undo"] is True and result["can_redo"] is True
    assert result["remaining_undo"] == ["Rename function"]
    assert result["remaining_redo"] == ["Set pre comment", "Create label"]

    redone = redo_program_change(
        {},
        ensure_context=lambda: _undo_context(program),
        safe_call=_safe_call,
        iter_items=iter,
    )

    assert redone["status"] == "ok"
    assert redone["redone"] == ["Set pre comment"]
    assert program.history == ["Rename function", "Set pre comment"]


def test_undo_reports_noop_when_history_is_empty_and_bounds_count():
    program = _UndoableProgram([])

    result = undo_program_change(
        {"count": 5},
        ensure_context=lambda: _undo_context(program),
        safe_call=_safe_call,
        iter_items=iter,
    )

    assert result == {
        "status": "noop",
        "undone": [],
        "undone_count": 0,
        "can_undo": False,
        "can_redo": False,
        "remaining_undo": [],
        "remaining_redo": [],
    }
    with pytest.raises(ValueError, match="count must be between 1 and 100"):
        undo_program_change(
            {"count": 0},
            ensure_context=lambda: _undo_context(program),
            safe_call=_safe_call,
            iter_items=iter,
        )


def test_get_comments_returns_every_slot():
    stored = {("PRE", "0x1000"): "above", ("PLATE", "0x1000"): "header"}
    listing = SimpleNamespace(getComment=lambda kind, address: stored.get((kind, address)))
    code_unit = SimpleNamespace(
        PRE_COMMENT="PRE", EOL_COMMENT="EOL", POST_COMMENT="POST", PLATE_COMMENT="PLATE", REPEATABLE_COMMENT="REP"
    )

    result = get_comments(
        {"address": "0x1000"},
        ensure_context=lambda: SimpleNamespace(listing=listing),
        get_address=lambda _ctx, text: text,
        code_unit=code_unit,
    )

    assert result == {
        "address": "0x1000",
        "pre": "above",
        "eol": None,
        "post": None,
        "plate": "header",
        "repeatable": None,
    }


class _Symbol:
    def __init__(self, name: str, address: str, kind: str, *, primary: bool = True) -> None:
        self._name = name
        self._address = address
        self._kind = kind
        self._primary = primary

    def getName(self, full: bool = False):
        return f"ns::{self._name}" if full else self._name

    def getAddress(self):
        return self._address

    def getSymbolType(self):
        return self._kind

    def getParentNamespace(self):
        return SimpleNamespace(getName=lambda _full=True: "ns")

    def getSource(self):
        return "USER_DEFINED"

    def isPrimary(self):
        return self._primary

    def setPrimary(self):
        self._primary = True
        return True


def test_search_symbols_wraps_substring_queries_and_filters_by_type():
    symbols = [_Symbol("main", "0x1000", "Function"), _Symbol("main_data", "0x2000", "Label", primary=False)]
    seen_patterns: list[tuple[str, bool]] = []

    def get_symbol_iterator(pattern, case_sensitive):
        seen_patterns.append((pattern, case_sensitive))
        return iter(symbols)

    ctx = SimpleNamespace(symbol_table=SimpleNamespace(getSymbolIterator=get_symbol_iterator))

    everything = search_symbols(
        {"query": "main"}, ensure_context=lambda: ctx, to_int=_to_int, iter_items=iter, safe_call=_safe_call
    )
    labels = search_symbols(
        {"query": "main*", "type": "label"},
        ensure_context=lambda: ctx,
        to_int=_to_int,
        iter_items=iter,
        safe_call=_safe_call,
    )

    assert seen_patterns == [("*main*", False), ("main*", False)]
    assert [item["name"] for item in everything] == ["main", "main_data"]
    assert everything[0] == {
        "name": "main",
        "full_name": "ns::main",
        "address": "0x1000",
        "type": "Function",
        "namespace": "ns",
        "source": "USER_DEFINED",
        "is_primary": True,
    }
    assert labels == [everything[1]]
    with pytest.raises(ValueError, match="query is required"):
        search_symbols(
            {"query": " "}, ensure_context=lambda: ctx, to_int=_to_int, iter_items=iter, safe_call=_safe_call
        )


def test_create_label_creates_and_promotes_the_symbol():
    created: list[tuple[str, str, object]] = []
    symbol = _Symbol("new_label", "0x3000", "Label", primary=False)

    def create_label_java(address, name, source):
        created.append((address, name, source))
        return symbol

    ctx = SimpleNamespace(symbol_table=SimpleNamespace(createLabel=create_label_java))

    result = create_label(
        {"address": "0x3000", "name": " new_label "},
        ensure_context=lambda: ctx,
        get_address=lambda _ctx, text: text,
        txn=_txn,
        source_type=SimpleNamespace(USER_DEFINED="user"),
    )

    assert created == [("0x3000", "new_label", "user")]
    assert result == {"name": "new_label", "address": "0x3000", "is_primary": True}

    secondary = _Symbol("other", "0x3000", "Label", primary=False)
    ctx.symbol_table.createLabel = lambda *_args: secondary
    result = create_label(
        {"address": "0x3000", "name": "other", "make_primary": False},
        ensure_context=lambda: ctx,
        get_address=lambda _ctx, text: text,
        txn=_txn,
        source_type=SimpleNamespace(USER_DEFINED="user"),
    )
    assert result["is_primary"] is False


class _FakeEnum:
    def __init__(self, path, name, size) -> None:
        self.path = path
        self.name = name
        self.size = size
        self.values: dict[str, tuple[int, str]] = {}

    def add(self, name, value, comment=""):
        self.values[name] = (value, comment)

    def remove(self, name):
        del self.values[name]

    def getNames(self):
        return list(self.values)


def test_create_enum_parses_values_and_validates_size():
    added = []
    manager = SimpleNamespace(addDataType=lambda enum_dt, _handler: (added.append(enum_dt), enum_dt)[1])

    result = create_enum(
        {
            "name": "Color",
            "size": 1,
            "category": "/types",
            "values": {"RED": 1, "GREEN": "0x2", "BLUE": {"value": 3, "comment": "sky"}},
        },
        ensure_context=lambda: object(),
        to_int=_to_int,
        txn=_txn,
        dt_manager=lambda _ctx: manager,
        category_path=lambda text: f"path:{text}",
        enum_data_type=_FakeEnum,
        describe_enum=lambda enum_dt: {
            "name": enum_dt.name,
            "path": enum_dt.path,
            "size": enum_dt.size,
            "values": enum_dt.values,
        },
    )

    assert result == {
        "name": "Color",
        "path": "path:/types",
        "size": 1,
        "values": {"RED": (1, ""), "GREEN": (2, ""), "BLUE": (3, "sky")},
    }
    assert added and added[0].name == "Color"
    with pytest.raises(ValueError, match="size must be one of"):
        create_enum(
            {"name": "Bad", "size": 3},
            ensure_context=lambda: object(),
            to_int=_to_int,
            txn=_txn,
            dt_manager=lambda _ctx: manager,
            category_path=lambda text: text,
            enum_data_type=_FakeEnum,
            describe_enum=lambda enum_dt: {},
        )
    with pytest.raises(ValueError, match="enum value is not an integer"):
        create_enum(
            {"name": "Bad", "values": {"X": "ten"}},
            ensure_context=lambda: object(),
            to_int=_to_int,
            txn=_txn,
            dt_manager=lambda _ctx: manager,
            category_path=lambda text: text,
            enum_data_type=_FakeEnum,
            describe_enum=lambda enum_dt: {},
        )


def test_set_enum_values_replaces_and_removes_names():
    enum_dt = _FakeEnum("/", "Color", 4)
    enum_dt.add("RED", 1)
    enum_dt.add("GREEN", 2)

    result = set_enum_values(
        {"name": "Color", "values": {"GREEN": 20, "BLUE": 3}, "remove": ["RED"]},
        ensure_context=lambda: object(),
        txn=_txn,
        get_enum_datatype=lambda _ctx, _name, _category: enum_dt,
        describe_enum=lambda item: dict(item.values),
        iter_items=iter,
    )

    assert result == {"GREEN": (20, ""), "BLUE": (3, "")}
    with pytest.raises(LookupError, match="Enum values not found: PURPLE"):
        set_enum_values(
            {"name": "Color", "remove": ["PURPLE"]},
            ensure_context=lambda: object(),
            txn=_txn,
            get_enum_datatype=lambda _ctx, _name, _category: enum_dt,
            describe_enum=lambda item: dict(item.values),
            iter_items=iter,
        )
    with pytest.raises(ValueError, match="values or remove is required"):
        set_enum_values(
            {"name": "Color"},
            ensure_context=lambda: object(),
            txn=_txn,
            get_enum_datatype=lambda _ctx, _name, _category: enum_dt,
            describe_enum=lambda item: dict(item.values),
            iter_items=iter,
        )


def test_export_program_refuses_existing_file_and_missing_directory(tmp_path):
    existing = tmp_path / "out.gzf"
    existing.write_bytes(b"x")
    ctx = SimpleNamespace(program=object(), monitor=lambda: None)

    with pytest.raises(RuntimeError, match="EXPORT_TARGET_EXISTS"):
        export_program(
            {"output_path": str(existing), "format": "gzf"},
            ensure_context=lambda: ctx,
            safe_call=_safe_call,
        )
    with pytest.raises(RuntimeError, match="EXPORT_DIRECTORY_MISSING"):
        export_program(
            {"output_path": str(tmp_path / "missing" / "out.gzf")},
            ensure_context=lambda: ctx,
            safe_call=_safe_call,
        )
    with pytest.raises(ValueError, match="format must be one of"):
        export_program(
            {"output_path": str(tmp_path / "new.bin"), "format": "elf"},
            ensure_context=lambda: ctx,
            safe_call=_safe_call,
        )
