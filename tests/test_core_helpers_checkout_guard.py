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


def test_readonly_decompile_does_not_auto_analyze_after_decompile_failure(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)
    calls: list[str] = []

    class DecompileResult:
        def getDecompiledFunction(self):
            return None

        def getErrorMessage(self):
            return "needs analysis"

    class FailingDecompInterface:
        def openProgram(self, _program):
            calls.append("openProgram")
            return True

        def decompileFunction(self, _function, _timeout, _monitor):
            calls.append("decompileFunction")
            return DecompileResult()

        def dispose(self):
            calls.append("dispose")

    class Utilities:
        def shouldAskToAnalyze(self, _program):
            calls.append("shouldAskToAnalyze")
            return True

        def markProgramAnalyzed(self, _program):
            calls.append("markProgramAnalyzed")

    class ScriptUtil:
        def acquireBundleHostReference(self):
            calls.append("acquire")

        def releaseBundleHostReference(self):
            calls.append("release")

    class FlatAPI:
        def analyzeAll(self, _program):
            calls.append("analyzeAll")

    monkeypatch.setattr(core_helpers, "DecompInterface", FailingDecompInterface)
    monkeypatch.setattr(core_helpers, "_ghidra_program_utilities", lambda: Utilities())
    monkeypatch.setattr(core_helpers, "_ghidra_script_util", lambda: ScriptUtil())

    ctx = types.SimpleNamespace(
        program=object(),
        flat_api=FlatAPI(),
        monitor=lambda: None,
    )

    with pytest.raises(RuntimeError, match="Decompilation result is empty: needs analysis"):
        core_helpers._decompile_function_object(ctx, object())

    assert calls == ["openProgram", "decompileFunction", "dispose"]


def test_high_function_fallback_requires_checkout_before_analysis(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)
    calls: list[str] = []

    class DecompileResult:
        def decompileCompleted(self):
            return False

        def getErrorMessage(self):
            return "needs analysis"

    class FailingDecompInterface:
        def openProgram(self, _program):
            calls.append("openProgram")
            return True

        def decompileFunction(self, _function, _timeout, _monitor):
            calls.append("decompileFunction")
            return DecompileResult()

        def dispose(self):
            calls.append("dispose")

    class DomainFile:
        def isVersioned(self):
            calls.append("isVersioned")
            return True

        def isCheckedOut(self):
            calls.append("isCheckedOut")
            return False

    class Program:
        def getDomainFile(self):
            return DomainFile()

    class Utilities:
        def shouldAskToAnalyze(self, _program):
            calls.append("shouldAskToAnalyze")
            return True

        def markProgramAnalyzed(self, _program):
            calls.append("markProgramAnalyzed")

    class FlatAPI:
        def analyzeAll(self, _program):
            calls.append("analyzeAll")

    monkeypatch.setattr(core_helpers, "DecompInterface", FailingDecompInterface)
    monkeypatch.setattr(core_helpers, "_ghidra_program_utilities", lambda: Utilities())

    ctx = types.SimpleNamespace(
        program=Program(),
        flat_api=FlatAPI(),
        monitor=lambda: None,
    )

    with pytest.raises(RuntimeError, match="CHECKOUT_REQUIRED"):
        core_helpers._decompile_high_function(ctx, object())

    assert calls == ["openProgram", "decompileFunction", "dispose", "isVersioned", "isCheckedOut"]
