from __future__ import annotations

import os
import re
import shutil
import uuid
from pathlib import Path

import pyghidra
import pyghidra.core as pycore
import pytest
from mcp.types import CallToolResult

from ghidra_mcp import cli


RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


def _resolve_ghidra_install_dir() -> str:
    explicit = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [
        explicit,
        "/Applications/ghidra_11.4_PUBLIC",
        "/Applications/Ghidra.app/Contents/Resources/ghidra",
        str(Path.home() / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_11.4_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_11.3_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.0.4_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.0.3_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.0_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.0.4_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.0.3_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.0.1_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.0_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_11.4.3_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_11.4.2_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_11.4.1_PUBLIC"),
    ]
    candidates.extend(str(path) for path in sorted((Path.home() / "ghidra").glob("ghidra_*_PUBLIC"), reverse=True))
    candidates.extend(
        str(path) for path in sorted((Path.home() / "Library" / "ghidra").glob("ghidra_*_PUBLIC"), reverse=True)
    )
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    pytest.fail("Cannot continue runtime tests because GHIDRA_INSTALL_DIR was not found")


def _resolve_runtime_binary_path() -> str:
    value = os.environ.get("GHIDRA_RUNTIME_BINARY_PATH")
    if not value:
        pytest.fail("GHIDRA_RUNTIME_BINARY_PATH is not set (required for runtime tests)")
    path = Path(value).expanduser().resolve()
    if not path.exists():
        pytest.fail(f"GHIDRA_RUNTIME_BINARY_PATH does not exist: {path}")
    return str(path)


def _start_pyghidra_if_needed() -> None:
    if pyghidra.started():
        return
    if shutil.which("java") is None:
        pytest.fail("java command not found (required for runtime tests)")
    try:
        pyghidra.start(install_dir=_resolve_ghidra_install_dir())
    except Exception as exc:
        pytest.fail(f"Failed to start pyghidra: {exc}")


def _ensure_project_created(project_dir: Path, project_name: str) -> None:
    marker = project_dir / f"{project_name}.gpr"
    if marker.exists():
        return
    project_dir.mkdir(parents=True, exist_ok=True)
    ghidra_project = pycore.JClass("ghidra.base.project.GhidraProject")
    project = ghidra_project.createProject(str(project_dir), project_name, False)
    project.close()


def _unwrap_runtime_result(result):
    if isinstance(result, CallToolResult):
        assert len(result.content) == 1
        assert result.content[0].text == "[]"
        return []
    return result


def _sample_of(value):
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        head = value.splitlines()[0] if value else ""
        return head[:120]
    return value


def _count_of(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, str):
        return len(value.splitlines())
    return None


def _log_runtime_result(name: str, value) -> None:
    print(
        f"[runtime] {name}: type={type(value).__name__} "
        f"count={_count_of(value)} sample={_sample_of(value)!r}"
    )


def _extract_prototype(decompiled_text: str) -> str | None:
    for line in decompiled_text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.endswith("{"):
            candidate = candidate[:-1].strip()
        if "(" not in candidate or ")" not in candidate:
            continue
        if candidate.startswith(("if ", "for ", "while ", "switch ", "return ")):
            continue
        return candidate
    return None


def _extract_variable_candidates(decompiled_text: str) -> list[str]:
    seen = []
    for name in re.findall(r"\b(?:param|local)_[A-Za-z0-9_]+\b", decompiled_text):
        if name not in seen:
            seen.append(name)
    return seen


def _derive_patch_bytes_from_hexdump(hexdump: str) -> str:
    for line in hexdump.splitlines():
        if "  " not in line:
            continue
        hex_part = line.split("  ", 1)[1]
        bytes_tokens = [token for token in hex_part.split() if len(token) == 2]
        if bytes_tokens:
            return "".join(bytes_tokens[:2])
    return "90"


def _pick_primary_function(target: str) -> tuple[str, str, str]:
    search_result = _unwrap_runtime_result(
        cli.search_functions_by_name(query="main", offset=0, limit=10, target=target)
    )
    candidates = list(search_result) or _unwrap_runtime_result(
        cli.list_functions(offset=0, limit=20, target=target)
    )
    first = candidates[0]
    address = first["entry"]
    name = first["name"]
    decompiled = _unwrap_runtime_result(
        cli.decompile_function_by_address(address=address, target=target)
    )
    return address, name, decompiled


def _run_variable_mutations(target: str, function_entries: list[dict]) -> tuple[dict, dict]:
    last_error = None
    for entry in function_entries:
        address = entry["entry"]
        info = _unwrap_runtime_result(
            cli.get_function_by_address(address=address, target=target)
        )
        function_name = info["name"]
        decompiled = _unwrap_runtime_result(
            cli.decompile_function_by_address(address=address, target=target)
        )
        for var_name in _extract_variable_candidates(decompiled):
            new_name = f"it_{var_name}_renamed"
            try:
                rename_result = _unwrap_runtime_result(
                    cli.rename_variable(
                        function_name=function_name,
                        old_name=var_name,
                        new_name=new_name,
                        target=target,
                    )
                )
                set_type_result = _unwrap_runtime_result(
                    cli.set_local_variable_type(
                        function_address=address,
                        variable_name=new_name,
                        new_type="int",
                        target=target,
                    )
                )
                return rename_result, set_type_result
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
    raise RuntimeError(
        f"No candidate succeeded for rename_variable / set_local_variable_type: {last_error}"
    )


def test_runtime_raw_binary_import_bootstraps_entry(tmp_path):
    _start_pyghidra_if_needed()

    target = f"runtime_raw_{uuid.uuid4().hex[:8]}"
    project_dir = tmp_path / "runtime_raw_project"
    project_name = "runtime_raw_validation"
    raw_blob = tmp_path / "shellcode.bin"
    raw_blob.write_bytes(b"\x55\x8b\xec\xc3")
    _ensure_project_created(project_dir, project_name)

    try:
        cli.register_target(
            target=target,
            project_location=str(project_dir),
            project_name=project_name,
        )
        imported = cli.import_program(
            target=target,
            binary_path=str(raw_blob),
            import_mode="raw_binary",
            language_id="x86:LE:32:default",
            base_address="0x401000",
            entry_offset=0,
        )
        domain_path = imported["program"]
        cli.load_project_program(target=target, domain_path=domain_path)

        function_info = _unwrap_runtime_result(
            cli.get_function_by_address(address="0x401000", target=target)
        )
        assert isinstance(function_info, dict)
        assert function_info["entry"].lower().endswith("401000")

        delete_function_result = _unwrap_runtime_result(
            cli.delete_function(address="0x401000", target=target)
        )
        create_function_result = _unwrap_runtime_result(
            cli.create_function(address="0x401000", name="runtime_manual_entry", target=target)
        )
        _log_runtime_result("delete_function(raw)", delete_function_result)
        _log_runtime_result("create_function(raw)", create_function_result)

        disassembly = _unwrap_runtime_result(
            cli.disassemble_function(address="0x401000", target=target)
        )
        assert isinstance(disassembly, list) and disassembly

        range_disassembly = _unwrap_runtime_result(
            cli.disassemble_range(start_address="0x401000", length=4, limit=5, target=target)
        )
        analyze_result = _unwrap_runtime_result(cli.analyze_program(target=target))
        reanalyze_result = _unwrap_runtime_result(cli.reanalyze_program(target=target))
        _log_runtime_result("disassemble_range(raw)", range_disassembly)
        _log_runtime_result("analyze_program(raw)", analyze_result)
        _log_runtime_result("reanalyze_program(raw)", reanalyze_result)
        assert isinstance(range_disassembly, list) and range_disassembly
        assert create_function_result["created"] is True
        assert delete_function_result["deleted"] is True
        assert isinstance(analyze_result, dict)
        assert reanalyze_result["forced"] is True
    finally:
        try:
            cli.close_session(target=target)
        except Exception:  # noqa: BLE001
            pass


def test_runtime_mutating_commands_all_success(tmp_path):
    _start_pyghidra_if_needed()
    binary_path = _resolve_runtime_binary_path()

    target = f"runtime_mut_{uuid.uuid4().hex[:8]}"
    project_dir = tmp_path / "runtime_mutating_project"
    project_name = "runtime_mutating_validation"
    _ensure_project_created(project_dir, project_name)

    try:
        cli.register_target(
            target=target,
            project_location=str(project_dir),
            project_name=project_name,
        )
        imported = cli.import_program(target=target, binary_path=binary_path)
        domain_path = imported["program"]
        cli.load_project_program(target=target, domain_path=domain_path)

        functions = _unwrap_runtime_result(cli.list_functions(offset=0, limit=10, target=target))
        assert isinstance(functions, list) and functions, "list_functions is empty"
        primary_address, primary_name, primary_decompiled = _pick_primary_function(target)
        aux = next((f for f in functions if f["entry"] != primary_address), functions[0])
        aux_address = aux["entry"]
        aux_name = aux["name"]

        data_items = _unwrap_runtime_result(cli.list_data_items(offset=0, limit=1, target=target))
        data_address = data_items[0]["address"] if data_items else primary_address

        bookmark_result = _unwrap_runtime_result(
            cli.add_bookmark(
                address=primary_address,
                category="Validation",
                comment="runtime mutating test",
                type="Info",
                target=target,
            )
        )
        _log_runtime_result("add_bookmark", bookmark_result)
        list_bookmarks_result = _unwrap_runtime_result(
            cli.list_bookmarks(address=primary_address, type="Info", category="Validation", target=target)
        )
        _log_runtime_result("list_bookmarks", list_bookmarks_result)

        decompiler_comment_result = _unwrap_runtime_result(
            cli.set_decompiler_comment(
                address=primary_address,
                comment="runtime decompiler comment",
                target=target,
            )
        )
        _log_runtime_result("set_decompiler_comment", decompiler_comment_result)

        disassembly_comment_result = _unwrap_runtime_result(
            cli.set_disassembly_comment(
                address=primary_address,
                comment="runtime disasm comment",
                target=target,
            )
        )
        _log_runtime_result("set_disassembly_comment", disassembly_comment_result)

        current_primary_info = _unwrap_runtime_result(
            cli.get_function_by_address(address=primary_address, target=target)
        )
        current_primary_name = current_primary_info["name"]
        prototype_candidates = [
            _extract_prototype(primary_decompiled),
            f"void {current_primary_name}(void)",
            f"int {current_primary_name}(void)",
        ]
        function_prototype_result = None
        prototype_error = None
        for prototype in prototype_candidates:
            if not prototype:
                continue
            try:
                function_prototype_result = _unwrap_runtime_result(
                    cli.set_function_prototype(
                        function_address=primary_address,
                        prototype=prototype,
                        target=target,
                    )
                )
                break
            except Exception as exc:  # noqa: BLE001
                prototype_error = exc
        if function_prototype_result is None:
            raise RuntimeError(f"set_function_prototype failed: {prototype_error}")
        _log_runtime_result("set_function_prototype", function_prototype_result)

        rename_variable_result, set_local_type_result = _run_variable_mutations(target, functions)
        _log_runtime_result("rename_variable", rename_variable_result)
        _log_runtime_result("set_local_variable_type", set_local_type_result)

        set_bytes_result = None
        set_bytes_error = None
        for candidate_address in [data_address, primary_address, aux_address]:
            try:
                bytes_dump = _unwrap_runtime_result(
                    cli.get_bytes(address=candidate_address, size=2, target=target)
                )
                patch_bytes = _derive_patch_bytes_from_hexdump(bytes_dump)
                set_bytes_result = _unwrap_runtime_result(
                    cli.set_bytes(address=candidate_address, bytes_hex=patch_bytes, target=target)
                )
                break
            except Exception as exc:  # noqa: BLE001
                set_bytes_error = exc
        if set_bytes_result is None:
            raise RuntimeError(f"set_bytes failed: {set_bytes_error}")
        _log_runtime_result("set_bytes", set_bytes_result)

        renamed_aux_1 = f"{aux_name}_r1"
        rename_function_result = _unwrap_runtime_result(
            cli.rename_function(old_name=aux_name, new_name=renamed_aux_1, target=target)
        )
        _log_runtime_result("rename_function", rename_function_result)

        renamed_aux_2 = f"{renamed_aux_1}_r2"
        rename_function_by_address_result = _unwrap_runtime_result(
            cli.rename_function_by_address(
                function_address=aux_address,
                new_name=renamed_aux_2,
                target=target,
            )
        )
        _log_runtime_result("rename_function_by_address", rename_function_by_address_result)

        rename_data_result = _unwrap_runtime_result(
            cli.rename_data(address=aux_address, new_name=f"{renamed_aux_2}_data", target=target)
        )
        _log_runtime_result("rename_data", rename_data_result)

        create_struct_result = _unwrap_runtime_result(
            cli.create_struct(name="__it_struct_mut", target=target)
        )
        _log_runtime_result("create_struct", create_struct_result)

        add_struct_members_result = _unwrap_runtime_result(
            cli.add_struct_members(
                struct_name="__it_struct_mut",
                members=[{"name": "field_a", "type": "int"}],
                target=target,
            )
        )
        _log_runtime_result("add_struct_members", add_struct_members_result)

        clear_struct_result = _unwrap_runtime_result(
            cli.clear_struct(struct_name="__it_struct_mut", target=target)
        )
        _log_runtime_result("clear_struct", clear_struct_result)

        _unwrap_runtime_result(
            cli.add_struct_members(
                struct_name="__it_struct_mut",
                members=[{"name": "field_b", "type": "char"}],
                target=target,
            )
        )
        remove_struct_members_result = _unwrap_runtime_result(
            cli.remove_struct_members(
                struct_name="__it_struct_mut",
                members=["field_b"],
                target=target,
            )
        )
        _log_runtime_result("remove_struct_members", remove_struct_members_result)
        list_data_types_result = _unwrap_runtime_result(
            cli.list_data_types(offset=0, limit=20, filter="__it_struct_mut", target=target)
        )
        _log_runtime_result("list_data_types", list_data_types_result)
        rename_data_type_result = _unwrap_runtime_result(
            cli.rename_data_type(
                name="__it_struct_mut",
                new_name="__it_struct_mut_renamed",
                target=target,
            )
        )
        _log_runtime_result("rename_data_type", rename_data_type_result)
        delete_struct_result = _unwrap_runtime_result(
            cli.delete_struct(struct_name="__it_struct_mut_renamed", target=target)
        )
        _log_runtime_result("delete_struct", delete_struct_result)

        create_enum_result = _unwrap_runtime_result(
            cli.create_enum(name="__it_enum_mut", target=target)
        )
        _log_runtime_result("create_enum", create_enum_result)

        add_enum_values_result = _unwrap_runtime_result(
            cli.add_enum_values(
                enum_name="__it_enum_mut",
                values=[{"name": "VALUE_A", "value": 1}],
                target=target,
            )
        )
        _log_runtime_result("add_enum_values", add_enum_values_result)

        remove_enum_values_result = _unwrap_runtime_result(
            cli.remove_enum_values(
                enum_name="__it_enum_mut",
                values=["VALUE_A"],
                target=target,
            )
        )
        _log_runtime_result("remove_enum_values", remove_enum_values_result)
        delete_enum_result = _unwrap_runtime_result(
            cli.delete_enum(enum_name="__it_enum_mut", target=target)
        )
        _log_runtime_result("delete_enum", delete_enum_result)

        create_class_result = _unwrap_runtime_result(
            cli.create_class(name="__ItRuntimeClass", target=target)
        )
        _log_runtime_result("create_class", create_class_result)

        add_class_members_result = _unwrap_runtime_result(
            cli.add_class_members(
                class_name="__ItRuntimeClass",
                members=[{"name": "member_a", "type": "int"}],
                target=target,
            )
        )
        _log_runtime_result("add_class_members", add_class_members_result)

        remove_class_members_result = _unwrap_runtime_result(
            cli.remove_class_members(
                class_name="__ItRuntimeClass",
                members=["member_a"],
                target=target,
            )
        )
        _log_runtime_result("remove_class_members", remove_class_members_result)

        set_global_data_type_result = None
        set_global_error = None
        for candidate_address in [data_address, primary_address, aux_address]:
            for clear_mode in [
                "CLEAR_ALL_CONFLICT_DATA",
                "CLEAR_ALL_DEFAULT_CONFLICT_DATA",
                "CLEAR_SINGLE_DATA",
            ]:
                try:
                    set_global_data_type_result = _unwrap_runtime_result(
                        cli.set_global_data_type(
                            address=candidate_address,
                            data_type="char",
                            length=1,
                            clear_mode=clear_mode,
                            target=target,
                        )
                    )
                    break
                except Exception as exc:  # noqa: BLE001
                    set_global_error = exc
            if set_global_data_type_result is not None:
                break
        if set_global_data_type_result is None:
            raise RuntimeError(f"set_global_data_type failed: {set_global_error}")
        _log_runtime_result("set_global_data_type", set_global_data_type_result)

        delete_bookmark_result = _unwrap_runtime_result(
            cli.delete_bookmark(
                address=primary_address,
                type="Info",
                category="Validation",
                comment="runtime mutating test",
                target=target,
            )
        )
        _log_runtime_result("delete_bookmark", delete_bookmark_result)

        runtime_results = {
            "rename_function": rename_function_result,
            "rename_function_by_address": rename_function_by_address_result,
            "rename_data": rename_data_result,
            "rename_variable": rename_variable_result,
            "set_decompiler_comment": decompiler_comment_result,
            "set_disassembly_comment": disassembly_comment_result,
            "set_function_prototype": function_prototype_result,
            "set_local_variable_type": set_local_type_result,
            "create_struct": create_struct_result,
            "add_struct_members": add_struct_members_result,
            "clear_struct": clear_struct_result,
            "delete_struct": delete_struct_result,
            "list_data_types": list_data_types_result,
            "rename_data_type": rename_data_type_result,
            "create_enum": create_enum_result,
            "add_enum_values": add_enum_values_result,
            "remove_enum_values": remove_enum_values_result,
            "delete_enum": delete_enum_result,
            "create_class": create_class_result,
            "add_class_members": add_class_members_result,
            "remove_class_members": remove_class_members_result,
            "remove_struct_members": remove_struct_members_result,
            "set_global_data_type": set_global_data_type_result,
            "set_bytes": set_bytes_result,
            "add_bookmark": bookmark_result,
            "list_bookmarks": list_bookmarks_result,
            "delete_bookmark": delete_bookmark_result,
        }

        for command_name, value in runtime_results.items():
            if command_name in {"list_data_types", "list_bookmarks"}:
                assert isinstance(value, list), f"{command_name} returned non-list value: {type(value)}"
                continue
            assert isinstance(value, dict), f"{command_name} returned non-dict value: {type(value)}"
    finally:
        try:
            cli.close_session(target)
        except Exception:
            pass
