"""Opt-in real-Ghidra jobs: PE analysis held past the client budget, analysis jobs, and shutdown cancellation."""

from __future__ import annotations

import asyncio
import os
import threading
import time
from dataclasses import replace
from uuid import uuid4

import anyio
import pytest

from binary_fixtures import GHIDRA_EXERCISE_PE
from cli_support import analyze_and_wait, import_and_wait
from test_runtime_import_lifecycle import bundle as _bundle

bundle = _bundle
pytestmark = pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra")


def test_analyzed_pe_result_survives_lost_receipt_and_long_analysis(bundle, tmp_path, monkeypatch):
    from ghidra.app.util.opinion import PeLoader

    from ghidra_headless.session import ProjectHandle

    pe_path = GHIDRA_EXERCISE_PE
    hold_seconds = float(os.environ.get("GHIDRA_IMPORT_GATE_SECONDS", "0"))
    assert 0 <= hold_seconds <= 600
    entered, release = threading.Event(), threading.Event()
    original_post_process = ProjectHandle._post_process_imported_program_locked

    def gated(self, *args, **kwargs):
        entered.set()
        assert release.wait(hold_seconds + 120), "coordinator did not release analysis"
        return original_post_process(self, *args, **kwargs)

    monkeypatch.setattr(ProjectHandle, "_post_process_imported_program_locked", gated)
    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="async_pe")
    api["register_target"](target="pe", project_location=str(tmp_path), project_name="async_pe")
    mcp = bundle.runtime.mcp
    original = mcp.bindings["import_program"]

    async def lose_receipt(**kwargs):
        value = await original.function(**kwargs)
        await asyncio.sleep(0.25)
        return value

    mcp.bindings["import_program"] = replace(original, function=lose_receipt)
    request_id = str(uuid4())

    async def scenario():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                mcp.call_tool(
                    "import_program",
                    {
                        "target": "pe",
                        "binary_path": str(pe_path),
                        "request_id": request_id,
                        "import_mode": "auto",
                        "analyze_imported": True,
                        "wait_seconds": 0,
                    },
                ),
                timeout=0.05,
            )
        with anyio.fail_after(60):
            while not entered.is_set():
                await asyncio.sleep(0.01)
        held_since = time.monotonic()
        while True:
            state = (
                await mcp.call_tool("get_operation", {"request_id": request_id, "wait_seconds": 0})
            ).structured_content["result"]
            assert state["state"] == "running" and state["phase"] == "executing"
            if time.monotonic() - held_since >= hold_seconds:
                break
            await asyncio.sleep(min(1, hold_seconds))
        release.set()
        with anyio.fail_after(120):
            while True:
                state = (
                    await mcp.call_tool("get_operation", {"request_id": request_id, "wait_seconds": 20})
                ).structured_content["result"]
                if state["state"] in {"succeeded", "failed"}:
                    break
        assert state["state"] == "succeeded", state
        return state

    try:
        state = asyncio.run(scenario())
    finally:
        release.set()
        mcp.bindings["import_program"] = original
    # Reopen through the handle: the import itself persisted the analyzed mark.
    handle = bundle.runtime_backend._store.get_target_handle("pe")
    session = handle.open_program(state["result"]["program"])
    try:
        program = session.get_program()
        options = program.getOptions("Program Information")
        assert options.contains("Analyzed") and options.getBoolean("Analyzed", False)
        assert not program.isChanged()
        assert program.getExecutableFormat() == PeLoader.PE_NAME
        assert program.getFunctionManager().getFunctionCount() > 0
    finally:
        session.close()


@pytest.mark.parametrize(
    "gated_step,options",
    [
        ("_analyze_program_locked", {}),
        # Analysis off: a cancelled entry bootstrap stops early without failing.
        ("_bootstrap_entry_locked", {"analyze_imported": False, "entry_offset": 0}),
    ],
)
def test_shutdown_cancels_post_processing_and_rolls_the_import_back(bundle, tmp_path, monkeypatch, gated_step, options):
    from ghidra_headless.session import ProjectHandle

    entered, release = threading.Event(), threading.Event()
    seen = {}
    original_step = getattr(ProjectHandle, gated_step)

    def gated(self, program, flat_api, *args):
        seen["monitor"] = flat_api.getMonitor()
        entered.set()
        assert release.wait(60), "coordinator did not release post-processing"
        return original_step(self, program, flat_api, *args)

    monkeypatch.setattr(ProjectHandle, gated_step, gated)
    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="cancel")
    api["register_target"](target="cancel", project_location=str(tmp_path), project_name="cancel")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    record = api["import_program"](
        target="cancel",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        wait_seconds=0,
        **options,
    )
    assert entered.wait(60)
    manager = bundle.registry.operations
    closing = threading.Thread(target=manager.shutdown)
    closing.start()
    try:
        deadline = time.monotonic() + 10
        while not seen["monitor"].isCancelled():
            assert time.monotonic() < deadline, "shutdown did not cancel the running import"
            time.sleep(0.01)
        release.set()
        closing.join(60)
        assert not closing.is_alive()
    finally:
        release.set()
        closing.join(60)
    error = manager.get(operation_id=record["operation_id"])["operation_error"]
    assert error["code"] == "OPERATION_SHUTDOWN"
    assert error["details"]["cancelled"] is True
    assert error["details"]["rollback_deleted"] is True and error["details"]["output_state"] == "absent"
    handle = bundle.runtime_backend._store.get_target_handle("cancel")
    assert handle.project.getProjectData().getFile("/tiny.bin") is None


def _load_unanalyzed(api, tmp_path, name):
    api["create_project"](project_location=str(tmp_path), project_name=name)
    api["register_target"](target=name, project_location=str(tmp_path), project_name=name)
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    imported = import_and_wait(
        api,
        target=name,
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        base_address="0x1000",
        entry_address="0x1000",
        analyze_imported=False,
    )
    loaded = api["load_project_program"](target=name, domain_path=imported["program"])
    # Loading never analyzes, and says so.
    assert loaded["is_analyzed"] is False
    return imported["program"]


def test_analysis_job_analyzes_the_loaded_program_without_saving(bundle, tmp_path):
    api = bundle.runtime.tools
    program = _load_unanalyzed(api, tmp_path, "analysis")
    assert api["get_program_info"](target="analysis")["is_analyzed"] is False
    assert analyze_and_wait(api, target="analysis") == {"program": program, "analyzed": True, "forced": False}
    info = api["get_program_info"](target="analysis")
    assert info["is_analyzed"] is True and info["has_unsaved_changes"] is True
    assert analyze_and_wait(api, target="analysis")["analyzed"] is False
    assert analyze_and_wait(api, target="analysis", force=True)["forced"] is True
    api["save_project_program"](target="analysis")
    reloaded = api["load_project_program"](target="analysis", domain_path=program)
    assert reloaded["reloaded"] is True and reloaded["is_analyzed"] is True
    api["close_session"](target="analysis")
    opened = api["load_project_program"](target="analysis", domain_path=program)
    assert opened["reloaded"] is False and opened["is_analyzed"] is True


def test_shutdown_cancels_an_analysis_job_and_rolls_the_analysis_back(bundle, tmp_path, monkeypatch):
    from ghidra_headless.handlers import core, core_runtime

    api = bundle.runtime.tools
    program_path = _load_unanalyzed(api, tmp_path, "cancel")
    entered, release = threading.Event(), threading.Event()
    seen = {}
    original = core._PROFILE_DEPENDENCIES["analyze_program_impl"]

    def gated(ctx, force=False, monitor=None):
        seen["monitor"] = monitor
        entered.set()
        assert release.wait(60), "coordinator did not release the analysis"
        return original(ctx, force=force, monitor=monitor)

    monkeypatch.setitem(core._PROFILE_DEPENDENCIES, "analyze_program_impl", gated)
    record = api["analyze_program"](target="cancel", wait_seconds=0)
    assert entered.wait(60)
    manager = bundle.registry.operations
    closing = threading.Thread(target=manager.shutdown)
    closing.start()
    try:
        deadline = time.monotonic() + 10
        while not seen["monitor"].isCancelled():
            assert time.monotonic() < deadline, "shutdown did not cancel the running analysis"
            time.sleep(0.01)
        release.set()
        closing.join(60)
        assert not closing.is_alive()
    finally:
        release.set()
        closing.join(60)
    error = manager.get(operation_id=record["operation_id"])["operation_error"]
    assert error["code"] == "OPERATION_SHUTDOWN"
    assert error["details"]["cancelled"] is True and error["details"]["output_state"] == "absent"
    # The cancelled analysis aborted its transaction: no analyzed mark, nothing to save.
    program = core_runtime._CONTEXTS["cancel"].program
    options = program.getOptions("Program Information")
    assert not (options.contains("Analyzed") and options.getBoolean("Analyzed", False))
    assert not bundle.runtime_backend._store.is_dirty_program("cancel", program_path)


def test_an_unanalyzed_gzf_is_analyzed_when_imported(bundle, tmp_path):
    """GzfLoader leaves Ghidra's ask-to-analyze flag off; the Analyzed mark decides, so the import analyzes it."""
    api = bundle.runtime.tools
    _load_unanalyzed(api, tmp_path, "gzf_source")
    archive = tmp_path / "unanalyzed.gzf"
    api["export_program"](target="gzf_source", output_path=str(archive), format="gzf")
    api["create_project"](project_location=str(tmp_path), project_name="gzf_target")
    api["register_target"](target="gzf_target", project_location=str(tmp_path), project_name="gzf_target")
    imported = import_and_wait(api, target="gzf_target", binary_path=str(archive))
    loaded = api["load_project_program"](target="gzf_target", domain_path=imported["program"])
    assert loaded["is_analyzed"] is True
