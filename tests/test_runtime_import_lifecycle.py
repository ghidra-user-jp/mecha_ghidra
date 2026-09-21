"""Real-Ghidra regressions for open failures and imported entry addresses."""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from ghidra_mcp.contracts.tool_spec import get_all_tool_specs, get_checkout_required_tool_names
from ghidra_mcp.presentation.cli_runtime import create_cli_runtime
from test_runtime_readonly_commands import _start_pyghidra_if_needed, _unwrap_runtime_result

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


@pytest.fixture
def bundle():
    _start_pyghidra_if_needed()
    from ghidra_headless.handlers import core

    specs = get_all_tool_specs()
    runtime = create_cli_runtime(
        registered_specs=specs,
        core_accessor=lambda: core,
        checkout_required_commands=get_checkout_required_tool_names(specs),
    )
    try:
        yield runtime
    finally:
        runtime.target_service.close_all()


@pytest.mark.parametrize("registered_before", [False, True])
def test_runtime_open_timeout_preserves_binding_and_allows_retry(bundle, tmp_path, monkeypatch, registered_before):
    api = bundle.runtime.tools
    for name in ("original", "busy"):
        api["create_project"](project_location=str(tmp_path), project_name=name)
    api["register_target"](target="owner", project_location=str(tmp_path), project_name="busy")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    imported = api["import_program"](
        target="owner",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        analyze_imported=False,
    )
    if registered_before:
        api["register_target"](target="subject", project_location=str(tmp_path), project_name="original")
    before = api["list_targets"]()
    store = bundle.runtime_backend._store
    project_lock = store.project_locks[store.target_projects["owner"]]
    acquired = threading.Event()
    release = threading.Event()

    def hold_lock():
        with project_lock:
            acquired.set()
            release.wait(10)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    try:
        assert acquired.wait(3)
        with monkeypatch.context() as patch:
            patch.setattr("ghidra_mcp.application.locks.get_lock_timeout_seconds", lambda: 0.05)
            with pytest.raises(Exception, match="LOCK_TIMEOUT") as failed:
                api["open_program"](
                    target="subject",
                    project_location=str(tmp_path),
                    project_name="busy",
                    domain_path=imported["program"],
                )
        assert failed.value.domain_error["code"] == "LOCK_TIMEOUT"
        assert failed.value.domain_error["details"]["lock"] == "project"
    finally:
        release.set()
        holder.join(5)
    assert not holder.is_alive()
    assert api["list_targets"]() == before
    assert "subject" not in store.sessions
    if registered_before:
        assert _unwrap_runtime_result(api["list_project_programs"](target="subject")) == []

    opened = api["open_program"](
        target="subject",
        project_location=str(tmp_path),
        project_name="busy",
        domain_path=imported["program"],
    )
    assert opened["project_name"] == "busy"
    assert opened["domain_path"] == imported["program"]


@pytest.mark.parametrize("base_value", [0x1000, 0xFFFF800000001000], ids=["low", "upper64"])
@pytest.mark.parametrize("notation", [hex, str, oct, bin], ids=["hex", "decimal", "octal", "binary"])
@pytest.mark.parametrize("selector", ["entry_address", "entry_offset"])
def test_runtime_import_entry_survives_reload(bundle, tmp_path, base_value, notation, selector):
    from ghidra_headless.handlers import core_runtime

    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="entry")
    api["register_target"](target="entry", project_location=str(tmp_path), project_name="entry")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    base_address = notation(base_value)
    imported = api["import_program"](
        target="entry",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        base_address=base_address,
        analyze_imported=False,
        **{selector: base_address if selector == "entry_address" else 0},
    )
    for _ in range(2):
        api["load_project_program"](target="entry", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["entry"].program
        address = program.getMinAddress()
        assert int(str(address.getOffsetAsBigInteger())) == base_value
        assert program.getFunctionManager().getFunctionAt(address) is not None
        assert program.getSymbolTable().isExternalEntryPoint(address)
        api["close_session"](target="entry")
        assert program.isClosed()


@pytest.mark.parametrize("bits,value", [(32, 1 << 32), (32, 0xFFFF800000001000), (64, 1 << 64)])
def test_runtime_entry_address_rejects_out_of_range(bits, value):
    _start_pyghidra_if_needed()
    import jpype

    from ghidra_headless.session import ProjectHandle

    address_space_class = jpype.JClass("ghidra.program.model.address.AddressSpace")
    address_space = jpype.JClass("ghidra.program.model.address.GenericAddressSpace")(
        "ram", bits, address_space_class.TYPE_RAM, 0
    )
    program = SimpleNamespace(getAddressFactory=lambda: SimpleNamespace(getDefaultAddressSpace=lambda: address_space))
    handle = object.__new__(ProjectHandle)
    address_error = jpype.JClass("ghidra.program.model.address.AddressOutOfBoundsException")
    with pytest.raises((ValueError, address_error)):
        handle._resolve_entry_address_locked(program, entry_address=hex(value), entry_offset=None)


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("boundary", ["negative", "overflow", "zero", "maximum"])
def test_runtime_import_base_address_bounds_and_retry(bundle, tmp_path, bits, boundary):
    from ghidra_headless.handlers import core_runtime

    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="range")
    api["register_target"](target="range", project_location=str(tmp_path), project_name="range")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"\xc3")
    value = {"negative": -1, "overflow": 1 << bits, "zero": 0, "maximum": (1 << bits) - 1}[boundary]
    arguments = dict(
        target="range",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id=f"x86:LE:{bits}:default",
        analyze_imported=False,
    )
    if boundary in {"negative", "overflow"}:
        with pytest.raises(Exception, match="VALIDATION_ERROR") as failed:
            api["import_program"](**arguments, base_address=hex(value))
        assert failed.value.domain_error["code"] == "VALIDATION_ERROR"
        assert "outside the default address space" in str(failed.value.__cause__)
        assert _unwrap_runtime_result(api["list_project_programs"](target="range")) == []
        value = 0x1000
    imported = api["import_program"](**arguments, base_address=hex(value))
    for _ in range(2):
        api["load_project_program"](target="range", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["range"].program
        assert int(str(program.getMinAddress().getOffsetAsBigInteger())) == value
        api["close_session"](target="range")
        assert program.isClosed()


@pytest.mark.parametrize("offset,length", [(0, None), (4, None), (4, 6), (4, 2)])
def test_runtime_raw_import_length_matches_remaining_bytes(bundle, tmp_path, offset, length):
    from ghidra_headless.handlers import core_runtime

    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="offset")
    api["register_target"](target="offset", project_location=str(tmp_path), project_name="offset")
    data = bytes(range(10))
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(data)
    imported = api["import_program"](
        target="offset",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:32:default",
        file_offset=offset,
        length=length,
        base_address="0x1000",
        analyze_imported=False,
    )
    expected = data[offset : offset + length if length is not None else None]
    for _ in range(2):
        api["load_project_program"](target="offset", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["offset"].program
        memory = program.getMemory()
        block = memory.getBlocks()[0]
        assert block.getSize() == len(expected)
        actual = bytes(int(memory.getByte(block.getStart().add(i))) & 255 for i in range(len(expected)))
        assert actual == expected
        api["close_session"](target="offset")
        assert program.isClosed()


@pytest.mark.parametrize("offset", [10, 11])
def test_runtime_raw_import_implicit_length_rejects_offset_at_or_past_eof(bundle, tmp_path, offset):
    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="offset")
    api["register_target"](target="offset", project_location=str(tmp_path), project_name="offset")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes(range(10)))
    with pytest.raises(Exception, match="VALIDATION_ERROR"):
        api["import_program"](
            target="offset",
            binary_path=str(binary),
            import_mode="raw_binary",
            language_id="x86:LE:32:default",
            file_offset=offset,
            analyze_imported=False,
        )
    assert _unwrap_runtime_result(api["list_project_programs"](target="offset")) == []


@pytest.mark.parametrize("notation", [hex, str, oct, bin], ids=["hex", "decimal", "octal", "binary"])
@pytest.mark.parametrize("selector", ["entry_address", "entry_offset"])
def test_runtime_word_addressed_entry_survives_reload(bundle, tmp_path, notation, selector):
    from ghidra_headless.handlers import core_runtime

    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="word")
    api["register_target"](target="word", project_location=str(tmp_path), project_name="word")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(b"\0\0\0\0")
    # The second PIC instruction is at word address 0x1001 / byte offset 2.
    imported = api["import_program"](
        target="word",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="PIC-16:LE:16:PIC-16",
        base_address=notation(0x1000),
        analyze_imported=False,
        **{selector: notation(0x1001) if selector == "entry_address" else 2},
    )
    for _ in range(2):
        api["load_project_program"](target="word", domain_path=imported["program"])
        program = core_runtime._CONTEXTS["word"].program
        expected = program.getMinAddress().add(2)
        assert str(expected) == "CODE:1001"
        assert program.getFunctionManager().getFunctionAt(expected) is not None
        assert program.getSymbolTable().isExternalEntryPoint(expected)
        api["close_session"](target="word")
        assert program.isClosed()
