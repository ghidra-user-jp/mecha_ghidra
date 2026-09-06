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

        def isHijacked(self):
            return False

        def isCheckedOut(self):
            raise RuntimeError("backend unavailable")

    class Program:
        def getDomainFile(self):
            return BrokenDomainFile()

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.isCheckedOut"):
        core_helpers._ensure_checkout_for_versioned_program(types.SimpleNamespace(program=Program()))


def test_checkout_guard_rejects_hijacked_program_reported_as_unversioned(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class HijackedDomainFile:
        def isVersioned(self):
            return False

        def isHijacked(self):
            return True

        def isCheckedOut(self):
            pytest.fail("checkout state must not authorize a hijacked file")

    class Program:
        def getDomainFile(self):
            return HijackedDomainFile()

    with pytest.raises(RuntimeError, match="HIJACKED_PROGRAM"):
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


def test_high_function_failure_reports_missing_analysis_instead_of_analyzing(monkeypatch: pytest.MonkeyPatch):
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
        program=object(),
        flat_api=FlatAPI(),
        monitor=lambda: None,
    )

    # A rename/retype must never start a multi-minute auto-analysis behind the
    # caller's back; it reports the missing analysis as an explicit error.
    with pytest.raises(RuntimeError, match="PROGRAM_NOT_ANALYZED") as exc_info:
        core_helpers._decompile_high_function(ctx, object())

    assert "run analyze_program first" in str(exc_info.value)
    assert calls == ["openProgram", "decompileFunction", "dispose", "shouldAskToAnalyze"]
    assert "analyzeAll" not in calls


def test_high_function_failure_without_pending_analysis_propagates(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)

    class DecompileResult:
        def decompileCompleted(self):
            return False

        def getErrorMessage(self):
            return "native crash"

    class FailingDecompInterface:
        def openProgram(self, _program):
            return True

        def decompileFunction(self, _function, _timeout, _monitor):
            return DecompileResult()

        def dispose(self):
            pass

    class Utilities:
        def shouldAskToAnalyze(self, _program):
            return False

    monkeypatch.setattr(core_helpers, "DecompInterface", FailingDecompInterface)
    monkeypatch.setattr(core_helpers, "_ghidra_program_utilities", lambda: Utilities())
    ctx = types.SimpleNamespace(program=object(), flat_api=object(), monitor=lambda: None)

    with pytest.raises(RuntimeError, match="Decompilation failed: native crash"):
        core_helpers._decompile_high_function(ctx, object())


def test_shared_context_decompiler_is_reused_and_reset_on_failure(monkeypatch: pytest.MonkeyPatch):
    core_helpers = _import_core_helpers(monkeypatch)
    created: list[object] = []

    class Decompiled:
        def getC(self):
            return "int main(void) {}"

    class Result:
        def __init__(self, ok):
            self._ok = ok

        def getDecompiledFunction(self):
            return Decompiled() if self._ok else None

        def getErrorMessage(self):
            return "" if self._ok else "boom"

    class Interface:
        def __init__(self):
            created.append(self)
            self.disposed = False
            self.fail_next = False

        def openProgram(self, _program):
            return True

        def decompileFunction(self, _function, _timeout, _monitor):
            if self.fail_next:
                raise RuntimeError("process died")
            return Result(True)

        def dispose(self):
            self.disposed = True

    class Ctx:
        program = object()

        def __init__(self):
            self._decompiler = None

        def monitor(self):
            return None

        def decompiler(self, factory):
            if self._decompiler is None:
                self._decompiler = factory()
                self._decompiler.openProgram(self.program)
            return self._decompiler

        def reset_decompiler(self):
            interface, self._decompiler = self._decompiler, None
            if interface is not None:
                interface.dispose()

    monkeypatch.setattr(core_helpers, "DecompInterface", Interface)
    ctx = Ctx()
    assert core_helpers._decompile_function_object(ctx, object()) == "int main(void) {}"
    assert core_helpers._decompile_function_object(ctx, object()) == "int main(void) {}"
    assert len(created) == 1 and not created[0].disposed

    created[0].fail_next = True
    with pytest.raises(RuntimeError, match="process died"):
        core_helpers._decompile_function_object(ctx, object())
    assert created[0].disposed
    assert core_helpers._decompile_function_object(ctx, object()) == "int main(void) {}"
    assert len(created) == 2
