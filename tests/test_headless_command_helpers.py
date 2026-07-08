from __future__ import annotations

import importlib
import sys
import types

import pytest

from ghidra_headless.handlers.commands.read_only_functions import list_classes


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

    # jpype maps java.util.NoSuchElementException to a Python class of the same
    # name; a bare-next iterator raising it has ended, not failed.
    class NoSuchElementException(Exception):
        pass

    class _BareNextJava:
        def __init__(self):
            self._values = [10, 20]

        def next(self):
            if not self._values:
                raise NoSuchElementException()
            return self._values.pop(0)

    assert list(core_helpers._iter_items(_BareNextJava())) == [10, 20]

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


# --- list_classes -----------------------------------------------------------


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


def test_list_classes_flags_class_namespaces_via_symbol_type():
    namespaces = [
        _FakeNamespace("Global", symbol_type="Namespace", is_global=True),
        _FakeNamespace("std", symbol_type="Namespace"),
        _FakeNamespace("MyClass", symbol_type="Class"),
        _FakeNamespace("no_symbol", symbol_type=None),
    ]

    result = list_classes(
        {},
        context=None,
        to_int=_to_int,
        iter_namespaces=lambda _ctx: iter(namespaces),
        safe_call=_safe_call,
    )

    assert result == [
        {"name": "std", "isClass": False},
        {"name": "MyClass", "isClass": True},
        {"name": "no_symbol", "isClass": False},
    ]
