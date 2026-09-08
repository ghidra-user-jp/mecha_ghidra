"""Context replacement must reclaim native decompilers without breaking rollback."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def runtime(monkeypatch):
    flatapi = ModuleType("ghidra.program.flatapi")
    flatapi.FlatProgramAPI = lambda program: program
    task = ModuleType("ghidra.util.task")
    task.TaskMonitor = SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(sys.modules, flatapi.__name__, flatapi)
    monkeypatch.setitem(sys.modules, task.__name__, task)
    path = Path(__file__).resolve().parents[1] / "src/ghidra_headless/handlers/core_runtime.py"
    spec = importlib.util.spec_from_file_location("review_core_runtime", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    module.clear_contexts()


def program():
    return SimpleNamespace(
        **{
            method: lambda: object()
            for method in (
                "getSymbolTable",
                "getFunctionManager",
                "getNamespaceManager",
                "getAddressFactory",
                "getListing",
                "getReferenceManager",
            )
        }
    )


class Decompiler:
    def __init__(self):
        self.dispose_calls = 0

    def openProgram(self, _program):
        return True

    def dispose(self):
        self.dispose_calls += 1


def test_replacing_context_disposes_previous_decompiler_only(runtime):
    old = runtime.initialize(program(), key="main")
    old_decompiler = old.decompiler(Decompiler)
    other = runtime.initialize(program(), key="other").decompiler(Decompiler)

    replacement = runtime.initialize(program(), key="main")

    assert old_decompiler.dispose_calls == 1
    assert other.dispose_calls == 0
    assert runtime._ensure_context_for_key("main") is replacement
    assert replacement is not old
    new_decompiler = replacement.decompiler(Decompiler)
    runtime.remove_context("main")
    assert new_decompiler.dispose_calls == 1
    assert old_decompiler.dispose_calls == 1


def test_failed_context_initialization_preserves_working_context(runtime, monkeypatch):
    old = runtime.initialize(program(), key="main")
    decompiler = old.decompiler(Decompiler)

    def fail(_program):
        raise RuntimeError("program cannot initialize")

    monkeypatch.setattr(runtime, "HeadlessContext", fail)
    with pytest.raises(RuntimeError, match="program cannot initialize"):
        runtime.initialize(program(), key="main")

    assert runtime._ensure_context_for_key("main") is old
    assert decompiler.dispose_calls == 0
