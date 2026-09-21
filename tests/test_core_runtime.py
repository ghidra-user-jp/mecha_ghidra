"""Context replacement must reclaim native decompilers without breaking rollback."""

from __future__ import annotations

import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor
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

    def fail(_program, project=None):
        raise RuntimeError("program cannot initialize")

    monkeypatch.setattr(runtime, "HeadlessContext", fail)
    with pytest.raises(RuntimeError, match="program cannot initialize"):
        runtime.initialize(program(), key="main")

    assert runtime._ensure_context_for_key("main") is old
    assert decompiler.dispose_calls == 0


def test_quarantine_updates_preserve_threads_and_use_python_tokens(runtime):
    ctx = runtime.initialize(program(), key="main")
    java = {"kind": "java", "id": 7, "name": "java-worker", "daemon": True}
    python = {"kind": "python", "id": 7, "token": "first", "name": "python-worker", "daemon": True}
    reused_ident = {**python, "token": "second"}
    ctx.mark_execution_invalid("script_run", {"stray_threads": [java, python], "script_id": "test"})
    first = ctx.execution_invalid
    ctx.mark_execution_invalid("stray_transaction", {"description": "later transaction"})
    assert ctx.execution_invalid["stray_threads"] == [java, python]
    assert first["reason"] == "script_run", "already-returned details remain a snapshot"
    ctx.mark_execution_invalid("script_run", {"stray_threads": [java, reused_ident]})
    assert ctx.execution_invalid["stray_threads"] == [java, python, reused_ident]
    ctx.mark_execution_invalid("stray_transaction", {"stray_threads": []})
    assert ctx.execution_invalid["stray_threads"] == [java, python, reused_ident]
    assert ctx.execution_invalid["script_id"] == "test"


def test_concurrent_quarantine_reports_keep_all_thread_records(runtime):
    ctx = runtime.initialize(program(), key="main")

    def report(identity):
        ctx.mark_execution_invalid("script_run", {"stray_threads": [{"kind": "java", "id": identity}]})
        ctx.mark_execution_invalid("stray_transaction")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(report, range(32)))
    assert {entry["id"] for entry in ctx.execution_invalid["stray_threads"]} == set(range(32))
