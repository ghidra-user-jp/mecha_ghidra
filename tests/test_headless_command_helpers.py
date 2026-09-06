from __future__ import annotations

import importlib
import sys
import types

import pytest

from ghidra_headless.handlers.commands.mutating_symbols import set_bytes
from ghidra_headless.handlers.commands.read_only_decompile import disassemble_range
from ghidra_headless.handlers.commands.read_only_functions import list_functions
from ghidra_headless.handlers.commands.read_only_memory_data import (
    get_bytes,
    get_data_by_label,
    list_bookmarks,
    list_data_items,
    list_data_types,
    list_exports,
    list_imports,
    list_namespaces,
    list_segments,
    list_strings,
    search_bytes,
)
from ghidra_headless.handlers.commands.read_only_xrefs import (
    get_function_xrefs,
    get_xrefs_from,
    get_xrefs_to,
)


def _import_core_helpers(monkeypatch: pytest.MonkeyPatch):
    def module(name: str, *, package: bool = False) -> types.ModuleType:
        mod = types.ModuleType(name)
        if package:
            mod.__path__ = []  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, mod)
        return mod

    try:
        import jpype  # noqa: F401
    except ImportError:
        # Only stub jpype when it is genuinely absent: replacing the real module
        # breaks pyghidra imports (`from jpype import JConversion`) triggered by
        # the core_helpers import chain.
        module("jpype")
    ghidra = module("ghidra", package=True)
    ghidra_app = module("ghidra.app", package=True)
    ghidra_app_decompiler = module("ghidra.app.decompiler")
    ghidra_app_util = module("ghidra.app.util", package=True)
    ghidra_app_util_parser = module("ghidra.app.util.parser")
    ghidra_program = module("ghidra.program", package=True)
    ghidra_program_model = module("ghidra.program.model", package=True)
    ghidra_program_model_symbol = module("ghidra.program.model.symbol")
    ghidra_program_model_data = module("ghidra.program.model.data")

    ghidra.app = ghidra_app
    ghidra_app.decompiler = ghidra_app_decompiler
    ghidra_app.util = ghidra_app_util
    ghidra_app_util.parser = ghidra_app_util_parser
    ghidra.program = ghidra_program
    ghidra_program.model = ghidra_program_model
    ghidra_program_model.symbol = ghidra_program_model_symbol
    ghidra_program_model.data = ghidra_program_model_data

    class _Dummy:
        pass

    ghidra_app_decompiler.DecompInterface = _Dummy
    ghidra_app_util_parser.FunctionSignatureParser = _Dummy
    ghidra_program_model_symbol.SourceType = _Dummy
    for name in (
        "CategoryPath",
        "StructureDataType",
        "DataUtilities",
        "VoidDataType",
        "CharDataType",
        "UnsignedCharDataType",
        "ShortDataType",
        "UnsignedShortDataType",
        "IntegerDataType",
        "UnsignedIntegerDataType",
        "LongLongDataType",
        "UnsignedLongLongDataType",
        "FloatDataType",
        "DoubleDataType",
        "BooleanDataType",
        "StringDataType",
        "UnicodeDataType",
    ):
        setattr(ghidra_program_model_data, name, _Dummy)

    original = sys.modules.pop("ghidra_headless.handlers.core_helpers", None)
    fresh = importlib.import_module("ghidra_headless.handlers.core_helpers")
    # The fresh import is bound to the stub ghidra.*/jpype modules above, which
    # vanish at monkeypatch teardown. Un-cache it (and restore any previously
    # imported real module, including the parent-package attribute the import
    # machinery set) so later tests do not silently reuse the stub-bound module.
    handlers_pkg = sys.modules.get("ghidra_headless.handlers")
    if original is not None:
        sys.modules["ghidra_headless.handlers.core_helpers"] = original
        if handlers_pkg is not None:
            handlers_pkg.core_helpers = original
    else:
        sys.modules.pop("ghidra_headless.handlers.core_helpers", None)
        if handlers_pkg is not None and getattr(handlers_pkg, "core_helpers", None) is fresh:
            del handlers_pkg.core_helpers
    return fresh


def test_import_core_helpers_does_not_pollute_sys_modules(monkeypatch: pytest.MonkeyPatch):
    original = sys.modules.get("ghidra_headless.handlers.core_helpers")

    fresh = _import_core_helpers(monkeypatch)

    # The stub-bound module must not stay cached for later tests (its ghidra.*
    # dependencies vanish at monkeypatch teardown); any pre-existing real
    # import must be restored.
    assert sys.modules.get("ghidra_headless.handlers.core_helpers") is not fresh
    assert sys.modules.get("ghidra_headless.handlers.core_helpers") is original


def test_get_bytes_rejects_oversized_request_before_allocating():
    ctx = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: object()))
    hexdump_called = False

    def unexpected_hexdump(*_args):
        nonlocal hexdump_called
        hexdump_called = True
        raise AssertionError("oversized request must not allocate a byte buffer")

    with pytest.raises(ValueError, match="must not exceed 1048576 bytes"):
        get_bytes(
            {"address": "0x1000", "size": 1024 * 1024 + 1},
            ensure_context=lambda: ctx,
            to_int=lambda value, _default: int(value),
            get_address=lambda _ctx, value: value,
            hexdump=unexpected_hexdump,
        )

    assert hexdump_called is False


def test_get_bytes_allows_request_at_size_limit():
    memory = object()
    ctx = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory))
    calls = []

    result = get_bytes(
        {"address": "0x1000", "size": 1024 * 1024},
        ensure_context=lambda: ctx,
        to_int=lambda value, _default: int(value),
        get_address=lambda _ctx, value: value,
        hexdump=lambda *args: calls.append(args) or "dump",
    )

    assert result == "dump"
    assert calls == [(memory, "0x1000", 1024 * 1024)]


@pytest.mark.parametrize("limit", [0, -1])
def test_list_segments_rejects_non_positive_limit(limit):
    get_blocks_called = False

    def get_blocks():
        nonlocal get_blocks_called
        get_blocks_called = True
        return [object()]

    memory = types.SimpleNamespace(getBlocks=get_blocks)
    ctx = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory))

    with pytest.raises(ValueError, match="limit must be >= 1"):
        list_segments(
            {"offset": 0, "limit": limit},
            ensure_context=lambda: ctx,
            to_int=lambda value, _default: int(value),
        )

    assert get_blocks_called is False


def test_list_segments_rejects_negative_offset():
    block = types.SimpleNamespace(
        getName=lambda: "text",
        getStart=lambda: "0x1000",
        getEnd=lambda: "0x10ff",
        getSize=lambda: 0x100,
        isRead=lambda: True,
        isWrite=lambda: False,
        isExecute=lambda: True,
    )
    memory = types.SimpleNamespace(getBlocks=lambda: [block])
    ctx = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory))

    with pytest.raises(ValueError, match="offset must be >= 0"):
        list_segments(
            {"offset": -5, "limit": 1},
            ensure_context=lambda: ctx,
            to_int=lambda value, _default: int(value),
        )


def test_paginated_commands_reject_invalid_limit_before_runtime_access():
    context = object()

    def checked_context():
        return context

    def unexpected_iter(_context):
        raise AssertionError("invalid limit must not enumerate Ghidra objects")

    def unexpected_collect(*_args):
        raise AssertionError("invalid limit must not collect Ghidra objects")

    def noop_to_int(value, default):
        return default if value is None else int(value)

    def no_items(items):
        return iter(items)

    commands = [
        lambda: list_functions(
            {"limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            collect=unexpected_collect,
            iter_items=no_items,
            source_type=types.SimpleNamespace(DEFAULT="default"),
        ),
        lambda: list_functions(
            {"filter": "entry", "limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            collect=unexpected_collect,
            iter_items=no_items,
            source_type=types.SimpleNamespace(DEFAULT="default"),
        ),
        lambda: list_segments({"limit": 0}, ensure_context=checked_context, to_int=noop_to_int),
        lambda: list_imports({"limit": 0}, ensure_context=checked_context, to_int=noop_to_int),
        lambda: list_exports(
            {"limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            iter_items=no_items,
            is_exported_symbol=lambda *_args: True,
        ),
        lambda: list_namespaces(
            {"limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            iter_namespaces=unexpected_iter,
            safe_call=lambda *_args: None,
        ),
        lambda: list_data_items({"limit": 0}, ensure_context=checked_context, to_int=noop_to_int),
        lambda: list_strings({"limit": 0}, ensure_context=checked_context, to_int=noop_to_int),
        lambda: search_bytes(
            {"bytes": "90", "limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            decode_hex_bytes=bytearray.fromhex,
        ),
        lambda: get_xrefs_to(
            {"address": "0x1000", "limit": 0},
            ensure_context=checked_context,
            get_address=lambda *_args: None,
            to_int=noop_to_int,
            iter_items=no_items,
        ),
        lambda: get_xrefs_from(
            {"address": "0x1000", "limit": 0},
            ensure_context=checked_context,
            get_address=lambda *_args: None,
            to_int=noop_to_int,
            iter_items=no_items,
        ),
        lambda: get_function_xrefs(
            {"name": "entry", "limit": 0},
            ensure_context=checked_context,
            get_address=lambda *_args: None,
            find_function_by_name=lambda *_args: None,
            to_int=noop_to_int,
            iter_items=no_items,
        ),
        lambda: list_data_types(
            {"limit": 0},
            ensure_context=checked_context,
            to_int=noop_to_int,
            dt_manager=lambda *_args: None,
            collect=unexpected_collect,
            iter_items=no_items,
            safe_call=lambda *_args: None,
            describe_data_type=lambda item: item,
        ),
        lambda: list_bookmarks(
            {"limit": 0},
            ensure_context=checked_context,
            get_address=lambda *_args: None,
            to_int=noop_to_int,
            collect=unexpected_collect,
            iter_items=no_items,
        ),
    ]

    for command in commands:
        with pytest.raises(ValueError, match="limit must be >= 1"):
            command()


def _collect_python(iterator, offset, limit, to_value):
    if limit <= 0:
        return []
    result = []
    for index, item in enumerate(iterator):
        if index < offset:
            continue
        result.append(to_value(item))
        if len(result) >= limit:
            break
    return result


def _fake_function(name: str, entry: str, *, default_name: bool = False, size: int = 4, thunk: bool = False):
    symbol = types.SimpleNamespace(getSource=lambda: "default" if default_name else "user")
    body = types.SimpleNamespace(getNumAddresses=lambda: size)
    return types.SimpleNamespace(
        getName=lambda: name,
        getEntryPoint=lambda: entry,
        getSymbol=lambda: symbol,
        getBody=lambda: body,
        isThunk=lambda: thunk,
    )


def _list_functions(params, functions):
    manager = types.SimpleNamespace(getFunctions=lambda _forward: iter(functions))
    context = types.SimpleNamespace(function_manager=manager)
    return list_functions(
        params,
        ensure_context=lambda: context,
        to_int=lambda value, default: default if value is None else int(value),
        collect=_collect_python,
        iter_items=iter,
        source_type=types.SimpleNamespace(DEFAULT="default"),
    )


@pytest.mark.parametrize("offset", [-7, -1])
def test_list_functions_rejects_negative_offset(offset):
    functions = [_fake_function("first", "0x1000"), _fake_function("second", "0x2000")]

    with pytest.raises(ValueError, match="offset must be >= 0"):
        _list_functions({"filter": "first", "offset": offset, "limit": 1}, functions)


def test_list_functions_filters_case_insensitively_and_reports_size():
    functions = [
        _fake_function("Main", "0x1000", size=32),
        _fake_function("FUN_00002000", "0x2000", default_name=True, size=8, thunk=True),
        _fake_function("helper_main", "0x3000", size=16),
    ]

    assert _list_functions({"filter": "MAIN"}, functions) == [
        {"name": "Main", "entry": "0x1000", "size": 32, "is_thunk": False},
        {"name": "helper_main", "entry": "0x3000", "size": 16, "is_thunk": False},
    ]
    assert _list_functions({"only_default_names": True}, functions) == [
        {"name": "FUN_00002000", "entry": "0x2000", "size": 8, "is_thunk": True},
    ]
    assert _list_functions({"filter": "main", "offset": 1, "limit": 5}, functions) == [
        {"name": "helper_main", "entry": "0x3000", "size": 16, "is_thunk": False},
    ]


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"offset": 1_000_001, "limit": 1}, "offset must be <= 1000000"),
        ({"offset": 0, "limit": 10_001}, "limit must be <= 10000"),
    ],
)
def test_list_segments_rejects_unbounded_pagination(params, message):
    memory = types.SimpleNamespace(
        getBlocks=lambda: (_ for _ in ()).throw(AssertionError("invalid pagination must not enumerate memory blocks"))
    )
    ctx = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory))

    with pytest.raises(ValueError, match=message):
        list_segments(
            params,
            ensure_context=lambda: ctx,
            to_int=lambda value, _default: int(value),
        )


def test_search_bytes_stops_at_memory_max_address():
    class _Address:
        def __init__(self):
            self.add_called = False

        def compareTo(self, other):
            assert other is self
            return 0

        def add(self, _amount):
            self.add_called = True
            raise AssertionError("must not advance past the maximum address")

        def __str__(self):
            return "0xffff"

    address = _Address()
    memory = types.SimpleNamespace(
        getMinAddress=lambda: address,
        getMaxAddress=lambda: address,
        findBytes=lambda *_args: address,
    )
    context = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory), monitor=lambda: object())

    result = search_bytes(
        {"bytes": "ff", "limit": 2},
        ensure_context=lambda: context,
        to_int=lambda value, default: default if value is None else int(value),
        decode_hex_bytes=bytearray.fromhex,
    )

    assert result == ["0xffff"]
    assert address.add_called is False


def test_disassemble_range_maps_address_overflow_to_validation_error():
    class _MaxAddress:
        def add(self, _amount):
            raise RuntimeError("AddressOverflowException")

    context = types.SimpleNamespace(
        listing=types.SimpleNamespace(
            getInstructions=lambda *_args: pytest.fail("an invalid range must not enumerate instructions")
        )
    )

    with pytest.raises(ValueError, match="length exceeds the address space"):
        disassemble_range(
            {"start_address": "0xffffffff", "length": 2, "limit": 1},
            ensure_context=lambda: context,
            get_address=lambda _ctx, _text: _MaxAddress(),
            to_int=lambda value, default: default if value is None else int(value),
            iter_items=iter,
            code_unit=object(),
        )


def test_search_bytes_does_not_materialize_skipped_matches():
    class _Address:
        def __init__(self, value):
            self.value = value

        def compareTo(self, other):
            return (self.value > other.value) - (self.value < other.value)

        def add(self, amount):
            return _Address(self.value + amount)

        def __str__(self):
            stringified.append(self.value)
            return "0x%x" % self.value

    stringified = []
    end = _Address(10_000)
    memory = types.SimpleNamespace(
        getMinAddress=lambda: _Address(0),
        getMaxAddress=lambda: end,
        findBytes=lambda current, *_args: _Address(current.value),
    )
    context = types.SimpleNamespace(program=types.SimpleNamespace(getMemory=lambda: memory), monitor=lambda: object())

    result = search_bytes(
        {"bytes": "00", "offset": 10_000, "limit": 1},
        ensure_context=lambda: context,
        to_int=lambda value, default: default if value is None else int(value),
        decode_hex_bytes=bytearray.fromhex,
    )

    assert result == ["0x2710"]
    assert stringified == [10_000]


def test_get_data_by_label_excludes_non_data_symbols():
    data = types.SimpleNamespace(getDefaultValueRepresentation=lambda: '"value"')
    symbols = [
        types.SimpleNamespace(getAddress=lambda: "0x1000", getName=lambda _full: "function"),
        types.SimpleNamespace(getAddress=lambda: "0x2000", getName=lambda _full: "global_data"),
    ]
    context = types.SimpleNamespace(
        symbol_table=types.SimpleNamespace(getSymbols=lambda _label: symbols),
        listing=types.SimpleNamespace(getDefinedDataAt=lambda address: data if address == "0x2000" else None),
    )

    result = get_data_by_label(
        {"label": "same_name"},
        ensure_context=lambda: context,
        iter_items=iter,
    )

    assert result == [{"name": "global_data", "address": "0x2000", "value": '"value"'}]


def test_list_exports_includes_exported_data_symbols():
    function_symbol = types.SimpleNamespace(getName=lambda _full: "exported_function")
    data_symbol = types.SimpleNamespace(getName=lambda _full: "exported_data")
    symbols = {"0x1000": function_symbol, "0x2000": data_symbol}
    symbol_table = types.SimpleNamespace(
        getExternalEntryPointIterator=lambda: iter(symbols),
        getPrimarySymbol=lambda address: symbols[address],
    )
    context = types.SimpleNamespace(symbol_table=symbol_table)

    result = list_exports(
        {"offset": 0, "limit": 10},
        ensure_context=lambda: context,
        to_int=lambda value, default: default if value is None else int(value),
        iter_items=iter,
        is_exported_symbol=lambda _ctx, symbol: symbol in (function_symbol, data_symbol),
    )

    assert result == [
        {"name": "exported_function", "address": "0x1000"},
        {"name": "exported_data", "address": "0x2000"},
    ]


@pytest.mark.parametrize("command", ["search", "set"])
def test_byte_commands_reject_whitespace_only_payload(command):
    def decode(value):
        return bytearray.fromhex(value)

    if command == "search":
        with pytest.raises(ValueError, match="at least one byte"):
            search_bytes(
                {"bytes": "   \t"},
                ensure_context=lambda: object(),
                to_int=lambda value, default: default if value is None else int(value),
                decode_hex_bytes=decode,
            )
    else:
        with pytest.raises(ValueError, match="at least one byte"):
            set_bytes(
                {"address": "0x1000", "bytes": "   \t"},
                ensure_context=lambda: object(),
                get_address=lambda *_args: None,
                decode_hex_bytes=decode,
                txn=lambda *_args: None,
            )


@pytest.mark.parametrize("command", ["search", "set"])
def test_byte_commands_reject_oversized_payload_before_decoding(command):
    decoded = False
    context_accessed = False

    def unexpected_context():
        nonlocal context_accessed
        context_accessed = True
        raise AssertionError("oversized payload must be rejected before Ghidra access")

    def unexpected_decode(_value):
        nonlocal decoded
        decoded = True
        raise AssertionError("oversized payload must not allocate a bytearray")

    oversized = "00" * (1024 * 1024 + 1)
    if command == "search":
        with pytest.raises(ValueError, match="must not exceed 1048576 bytes"):
            search_bytes(
                {"bytes": oversized},
                ensure_context=unexpected_context,
                to_int=lambda value, default: default if value is None else int(value),
                decode_hex_bytes=unexpected_decode,
            )
    else:
        with pytest.raises(ValueError, match="must not exceed 1048576 bytes"):
            set_bytes(
                {"address": "0x1000", "bytes": oversized},
                ensure_context=unexpected_context,
                get_address=lambda *_args: None,
                decode_hex_bytes=unexpected_decode,
                txn=lambda *_args: None,
            )

    assert decoded is False
    assert context_accessed is False


def test_iter_items_propagates_mid_iteration_errors(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    def _exploding():
        yield 1
        yield 2
        raise RuntimeError("boom")

    collected = []
    # A mid-iteration failure must surface instead of silently truncating the
    # result into a partial list the caller reports as complete.
    with pytest.raises(RuntimeError, match="boom"):
        for item in core_helpers._iter_items(_exploding()):
            collected.append(item)

    assert collected == [1, 2]


def test_iter_items_supports_bare_next_iterator(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class _BareNext:
        def __init__(self):
            self._values = iter([10, 20])

        def next(self):
            return next(self._values)

    assert list(core_helpers._iter_items(_BareNext())) == [10, 20]


def test_iter_items_bare_next_treats_java_no_such_element_as_end(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    # Pure-Python fakes usually expose the simple class name, while real JPype
    # classes use the fully qualified name ``java.util.NoSuchElementException``.
    class NoSuchElementException(Exception):
        pass

    QualifiedNoSuchElementException = type("java.util.NoSuchElementException", (Exception,), {})

    class _BareNextJava:
        def __init__(self, exception_type):
            self._values = [10, 20]
            self._exception_type = exception_type

        def next(self):
            if not self._values:
                raise self._exception_type()
            return self._values.pop(0)

    for exception_type in (NoSuchElementException, QualifiedNoSuchElementException):
        assert list(core_helpers._iter_items(_BareNextJava(exception_type))) == [10, 20]

    class _ExplodingBareNext:
        def next(self):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        list(core_helpers._iter_items(_ExplodingBareNext()))


def test_iter_items_supports_java_style_iterator(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class _JavaIter:
        def __init__(self):
            self._values = [1, 2, 3]
            self._index = 0

        def hasNext(self):
            return self._index < len(self._values)

        def next(self):
            value = self._values[self._index]
            self._index += 1
            return value

    assert list(core_helpers._iter_items(_JavaIter())) == [1, 2, 3]


def test_iter_items_propagates_iterator_acquisition_errors(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class _BrokenIterable:
        def iterator(self):
            raise RuntimeError("backend iterator unavailable")

    with pytest.raises(RuntimeError, match="backend iterator unavailable"):
        list(core_helpers._iter_items(_BrokenIterable()))


def test_iter_items_falls_back_when_iterator_returns_none(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class _PythonIterable:
        def iterator(self):
            return None

        def __iter__(self):
            return iter([4, 5, 6])

    assert list(core_helpers._iter_items(_PythonIterable())) == [4, 5, 6]


# --- list_namespaces --------------------------------------------------------


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


class _SymbolType:
    def __init__(self, name: str) -> None:
        self._name = name

    def __str__(self) -> str:
        return self._name


class _FakeNamespace:
    def __init__(self, name: str, *, symbol_type: str | None, is_global: bool = False) -> None:
        self._name = name
        self._symbol_type = symbol_type
        self._is_global = is_global

    def getName(self, _full: bool = True) -> str:
        return self._name

    def isGlobal(self) -> bool:
        return self._is_global

    def getSymbol(self):
        if self._symbol_type is None:
            return None
        symbol_type = _SymbolType(self._symbol_type)
        return types.SimpleNamespace(getSymbolType=lambda: symbol_type)


def test_list_namespaces_reports_classes_and_can_filter_to_them():
    namespaces = [
        _FakeNamespace("Global", symbol_type="Namespace", is_global=True),
        _FakeNamespace("std", symbol_type="Namespace"),
        _FakeNamespace("MyClass", symbol_type="Class"),
        _FakeNamespace("no_symbol", symbol_type=None),
    ]

    everything = list_namespaces(
        {},
        ensure_context=lambda: None,
        to_int=_to_int,
        iter_namespaces=lambda _ctx: iter(namespaces),
        safe_call=_safe_call,
    )
    classes = list_namespaces(
        {"classes_only": True},
        ensure_context=lambda: None,
        to_int=_to_int,
        iter_namespaces=lambda _ctx: iter(namespaces),
        safe_call=_safe_call,
    )

    assert everything == [
        {"name": "std", "is_class": False},
        {"name": "MyClass", "is_class": True},
        {"name": "no_symbol", "is_class": False},
    ]
    assert classes == [{"name": "MyClass", "is_class": True}]
