"""Real-Ghidra regressions for project protection, export paths and decompiler lifetime."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.contracts.tool_spec import get_all_tool_specs, get_checkout_required_tool_names
from ghidra_mcp.presentation.cli_runtime import create_cli_runtime
from test_runtime_readonly_commands import _start_pyghidra_if_needed

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


@pytest.fixture
def runtime(tmp_path, monkeypatch, request):
    _start_pyghidra_if_needed()
    from ghidra_headless.handlers import core

    exports = tmp_path / "exports"
    exports.mkdir()
    monkeypatch.chdir(exports)
    specs = get_all_tool_specs()
    bundle = create_cli_runtime(
        registered_specs=specs,
        core_accessor=lambda: core,
        checkout_required_commands=get_checkout_required_tool_names(specs),
        path_policy=PathPolicy.from_roots(export_roots=[exports]),
    )
    api = bundle.runtime.tools
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(getattr(request, "param", bytes.fromhex("b8 2a 00 00 00 c3")))
    try:
        api["create_project"](project_location=str(tmp_path), project_name="sample")
        api["register_target"](target="resource_safety", project_location=str(tmp_path), project_name="sample")
        imported = api["import_program"](
            target="resource_safety",
            binary_path=str(binary),
            import_mode="raw_binary",
            language_id="x86:LE:64:default",
            base_address="0x1000",
            entry_address="0x1000",
            analyze_imported=True,
        )
        api["load_project_program"](target="resource_safety", domain_path=imported["program"])
        yield api
    finally:
        bundle.target_service.close_all()


def test_runtime_project_name_alias_cannot_overwrite_loaded_project(runtime, tmp_path):
    sentinel = tmp_path / "sample.rep" / "sentinel.txt"
    sentinel.write_text("existing project data")
    with pytest.raises(Exception, match="PROJECT_IN_USE"):
        runtime["create_project"](project_location=str(tmp_path), project_name="sample", overwrite=True)
    with pytest.raises(Exception, match="VALIDATION_ERROR"):
        runtime["create_project"](project_location=str(tmp_path), project_name="sample.gpr", overwrite=True)

    assert sentinel.read_text() == "existing project data"
    assert "0x2a" in runtime["decompile_function"](target="resource_safety", address="0x1000")


def test_runtime_export_uses_only_the_validated_path(runtime, tmp_path):
    outside = tmp_path / "outside.bin"
    for prefix in ("", " ", "\t", "\n"):
        with pytest.raises(Exception, match="PATH_NOT_ALLOWED"):
            runtime["export_program"](target="resource_safety", output_path=prefix + str(outside), format="binary")
    assert not outside.exists()

    exported = runtime["export_program"](target="resource_safety", output_path=" valid.bin ", format="binary")
    assert exported["output_path"] == str(tmp_path / "exports" / "valid.bin")
    assert (tmp_path / "exports" / "valid.bin").read_bytes() == bytes.fromhex("b8 2a 00 00 00 c3")

    destination = tmp_path / "exports" / "resolved destination "
    (tmp_path / "exports" / "link.bin").symlink_to(destination)
    runtime["export_program"](target="resource_safety", output_path="link.bin", format="binary")
    assert destination.read_bytes() == bytes.fromhex("b8 2a 00 00 00 c3")


@pytest.mark.parametrize("offset,length", [(16, 24), (10, 16), (0, 32)])
def test_runtime_raw_import_preserves_decimal_byte_ranges_after_reload(runtime, tmp_path, offset, length):
    import jpype

    from ghidra_headless.handlers import core_runtime

    binary = tmp_path / "range.bin"
    contents = bytes(range(128))
    binary.write_bytes(contents)
    imported = runtime["import_program"](
        target="resource_safety",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        compiler_spec_id="windows",
        base_address="0x2000",
        file_offset=offset,
        length=length,
        block_name="range_block",
        analyze_imported=False,
    )
    for _ in range(2):
        runtime["load_project_program"](target="resource_safety", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["resource_safety"].program
        block = program.getMemory().getBlocks()[0]
        assert int(block.getStart().getOffset()) == 0x2000
        assert int(block.getSize()) == length
        assert str(block.getName()) == "range_block"
        assert str(program.getCompilerSpec().getCompilerSpecID()) == "windows"
        actual = jpype.JArray(jpype.JByte)(length)
        assert program.getMemory().getBytes(block.getStart(), actual) == length
        assert bytes(actual) == contents[offset : offset + length]
        runtime["close_session"](target="resource_safety")


def _native_decompiler_process():
    from ghidra_headless.handlers import core_runtime

    # Inspect only the process owned by this test's interface; enumerating host
    # processes is unavailable on sandboxed macOS and could include other work.
    interface = core_runtime._CONTEXTS["resource_safety"]._decompiler
    field = interface.getClass().getDeclaredField("decompProcess")
    field.setAccessible(True)
    decompiler = field.get(interface)
    native_field = decompiler.getClass().getDeclaredField("nativeProcess")
    native_field.setAccessible(True)
    return native_field.get(decompiler)


def test_runtime_reloading_and_closing_reclaims_native_decompilers(runtime):
    from java.util.concurrent import TimeUnit

    processes = []
    try:
        for _ in range(3):
            assert "0x2a" in runtime["decompile_function"](target="resource_safety", address="0x1000")
            process = _native_decompiler_process()
            processes.append(process)
            runtime["load_project_program"](target="resource_safety", domain_path="/tiny.bin")
            assert process.waitFor(5, TimeUnit.SECONDS), "reloading left an old decompiler running"

        runtime["decompile_function"](target="resource_safety", address="0x1000")
        processes.append(_native_decompiler_process())
        runtime["close_session"](target="resource_safety")
        assert processes[-1].waitFor(5, TimeUnit.SECONDS), "closing left the current decompiler running"
        assert not any(process.isAlive() for process in processes)
    finally:
        for process in processes:
            if process.isAlive():
                process.destroy()


@pytest.mark.parametrize("analyze_imported", [False, True])
def test_runtime_auto_import_uses_public_loader_and_releases_results(runtime, monkeypatch, analyze_imported):
    import jpype
    import pyghidra

    from ghidra_headless.handlers import core_runtime

    original_loader = pyghidra.program_loader
    loaded_programs = []
    detected_formats = []
    closed_results = []

    class Results:
        def __init__(self, delegate):
            self.delegate = delegate

        def getPrimary(self):
            primary = self.delegate.getPrimary()
            consumer = jpype.JClass("java.lang.Object")()
            program = primary.getDomainObject(consumer)
            try:
                loaded_programs.append(program)
                detected_formats.append(str(program.getExecutableFormat()))
            finally:
                program.release(consumer)
            return primary

        def close(self):
            self.delegate.close()
            closed_results.append(self.delegate)

    class Builder:
        def __init__(self):
            self.delegate = original_loader()

        def __getattr__(self, name):
            def option(*args):
                self.delegate = getattr(self.delegate, name)(*args)
                return self

            return option

        def load(self):
            return Results(self.delegate.load())

    monkeypatch.setattr(pyghidra, "program_loader", Builder)
    sample = Path(__file__).resolve().parents[1] / "samples" / "hello.bin"
    imported = runtime["import_program"](
        target="resource_safety", binary_path=str(sample), analyze_imported=analyze_imported
    )
    assert imported["program"] == "/hello.bin"
    assert len(loaded_programs) == len(closed_results) == 1
    assert detected_formats[0] and detected_formats[0] != "Raw Binary"
    assert loaded_programs[0].isClosed(), "the loader must release its program before a subsequent open"

    for _ in range(2):
        runtime["load_project_program"](target="resource_safety", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["resource_safety"].program
        assert str(program.getName()) == "hello.bin"
        assert str(program.getExecutableFormat()) == detected_formats[0]
        assert int(program.getMemory().getSize()) > 0
        assert program.getCurrentTransactionInfo() is None
        if analyze_imported:
            assert program.getFunctionManager().getFunctionCount() > 0
        runtime["close_session"](target="resource_safety")
        assert program.isClosed()
