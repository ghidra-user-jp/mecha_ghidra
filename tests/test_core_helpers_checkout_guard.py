from __future__ import annotations

import importlib
import sys
import types

import pytest


def _import_core_helpers(monkeypatch: pytest.MonkeyPatch):
    def module(name: str, *, package: bool = False) -> types.ModuleType:
        mod = types.ModuleType(name)
        if package:
            mod.__path__ = []  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, mod)
        return mod

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

    sys.modules.pop("ghidra_headless.handlers.core_helpers", None)
    return importlib.import_module("ghidra_headless.handlers.core_helpers")


def test_checkout_guard_fails_closed_when_version_state_unavailable(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class BrokenDomainFile:
        def isVersioned(self):
            raise RuntimeError("backend unavailable")

    class Program:
        def getDomainFile(self):
            return BrokenDomainFile()

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.isVersioned"):
        core_helpers._ensure_checkout_for_versioned_program(types.SimpleNamespace(program=Program()))


def test_checkout_guard_fails_closed_when_checkout_state_unavailable(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class BrokenDomainFile:
        def isVersioned(self):
            return True

        def isCheckedOut(self):
            raise RuntimeError("backend unavailable")

    class Program:
        def getDomainFile(self):
            return BrokenDomainFile()

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.isCheckedOut"):
        core_helpers._ensure_checkout_for_versioned_program(types.SimpleNamespace(program=Program()))
