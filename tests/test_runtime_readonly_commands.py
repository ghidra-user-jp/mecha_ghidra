from __future__ import annotations

import os
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


def _derive_search_pattern_from_hexdump(hexdump: str) -> str:
    for line in hexdump.splitlines():
        if "  " not in line:
            continue
        hex_part = line.split("  ", 1)[1]
        for token in hex_part.split():
            if len(token) == 2 and all(ch in "0123456789abcdefABCDEF" for ch in token):
                return token
    return "90"


def test_runtime_readonly_commands_all_success(tmp_path):
    _start_pyghidra_if_needed()
    binary_path = _resolve_runtime_binary_path()

    target = f"runtime_{uuid.uuid4().hex[:8]}"
    project_dir = tmp_path / "runtime_project"
    project_name = "runtime_validation"
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

        struct_result = _unwrap_runtime_result(
            cli.create_struct(name="__it_struct", target=target)
        )
        enum_result = _unwrap_runtime_result(
            cli.create_enum(name="__it_enum", target=target)
        )
        _log_runtime_result("create_struct", struct_result)
        _log_runtime_result("create_enum", enum_result)

        first_functions = _unwrap_runtime_result(
            cli.list_functions(offset=0, limit=1, target=target)
        )
        assert isinstance(first_functions, list)
        assert first_functions, "Cannot continue runtime validation because list_functions returned empty"
        first = first_functions[0]
        address = first["entry"]
        function_name = first["name"]
        _log_runtime_result("list_functions(seed)", first_functions)

        bookmark_result = _unwrap_runtime_result(
            cli.add_bookmark(
                address=address,
                category="Validation",
                comment="runtime readonly seed",
                type="Info",
                target=target,
            )
        )
        _log_runtime_result("add_bookmark(seed)", bookmark_result)

        search_result = _unwrap_runtime_result(
            cli.search_functions_by_name(
                query="main",
                offset=0,
                limit=5,
                target=target,
            )
        )
        if not search_result:
            fallback_query = (function_name or "main")[:4] or function_name or "main"
            search_result = _unwrap_runtime_result(
                cli.search_functions_by_name(
                    query=fallback_query,
                    offset=0,
                    limit=5,
                    target=target,
                )
            )
        _log_runtime_result("search_functions_by_name(seed)", search_result)

        function_info = _unwrap_runtime_result(
            cli.get_function_by_address(address=address, target=target)
        )
        label = function_info["name"]
        _log_runtime_result("get_function_by_address(seed)", function_info)

        bytes_dump = _unwrap_runtime_result(
            cli.get_bytes(address=address, size=16, target=target)
        )
        pattern = _derive_search_pattern_from_hexdump(bytes_dump)
        _log_runtime_result("get_bytes(seed)", bytes_dump)

        runtime_results = {
            "list_methods": _unwrap_runtime_result(
                cli.list_methods(offset=0, limit=5, target=target)
            ),
            "decompile_function": _unwrap_runtime_result(
                cli.decompile_function(name=function_name, target=target)
            ),
            "decompile_function_by_address": _unwrap_runtime_result(
                cli.decompile_function_by_address(address=address, target=target)
            ),
            "disassemble_function": _unwrap_runtime_result(
                cli.disassemble_function(address=address, target=target)
            ),
            "disassemble_range": _unwrap_runtime_result(
                cli.disassemble_range(start_address=address, length=32, limit=10, target=target)
            ),
            "get_callee": _unwrap_runtime_result(
                cli.get_callee(address=address, target=target)
            ),
            "get_xrefs_to": _unwrap_runtime_result(
                cli.get_xrefs_to(address=address, offset=0, limit=5, target=target)
            ),
            "get_xrefs_from": _unwrap_runtime_result(
                cli.get_xrefs_from(address=address, offset=0, limit=5, target=target)
            ),
            "get_function_xrefs": _unwrap_runtime_result(
                cli.get_function_xrefs(name=function_name, offset=0, limit=5, target=target)
            ),
            "list_segments": _unwrap_runtime_result(
                cli.list_segments(offset=0, limit=5, target=target)
            ),
            "list_imports": _unwrap_runtime_result(
                cli.list_imports(offset=0, limit=5, target=target)
            ),
            "list_exports": _unwrap_runtime_result(
                cli.list_exports(offset=0, limit=5, target=target)
            ),
            "list_classes": _unwrap_runtime_result(
                cli.list_classes(offset=0, limit=5, target=target)
            ),
            "list_namespaces": _unwrap_runtime_result(
                cli.list_namespaces(offset=0, limit=5, target=target)
            ),
            "list_data_items": _unwrap_runtime_result(
                cli.list_data_items(offset=0, limit=5, target=target)
            ),
            "list_data_types": _unwrap_runtime_result(
                cli.list_data_types(offset=0, limit=20, filter="__it_", target=target)
            ),
            "list_strings": _unwrap_runtime_result(
                cli.list_strings(offset=0, limit=5, target=target)
            ),
            "get_data_by_label": _unwrap_runtime_result(
                cli.get_data_by_label(label=label, target=target)
            ),
            "get_bytes": bytes_dump,
            "search_bytes": _unwrap_runtime_result(
                cli.search_bytes(pattern=pattern, offset=0, limit=5, target=target)
            ),
            "get_struct": _unwrap_runtime_result(
                cli.get_struct(name="__it_struct", target=target)
            ),
            "get_enum": _unwrap_runtime_result(
                cli.get_enum(name="__it_enum", target=target)
            ),
            "list_bookmarks": _unwrap_runtime_result(
                cli.list_bookmarks(address=address, type="Info", category="Validation", target=target)
            ),
        }

        for command_name, value in runtime_results.items():
            _log_runtime_result(command_name, value)

        assert isinstance(runtime_results["decompile_function"], str)
        assert isinstance(runtime_results["decompile_function_by_address"], str)
        assert isinstance(runtime_results["disassemble_function"], list)
        assert isinstance(runtime_results["disassemble_range"], list)
        assert isinstance(runtime_results["get_callee"], list)
        assert isinstance(runtime_results["list_methods"], list)
        assert isinstance(runtime_results["get_xrefs_to"], list)
        assert isinstance(runtime_results["get_xrefs_from"], list)
        assert isinstance(runtime_results["get_function_xrefs"], list)
        assert isinstance(runtime_results["list_segments"], list)
        assert isinstance(runtime_results["list_imports"], list)
        assert isinstance(runtime_results["list_exports"], list)
        assert isinstance(runtime_results["list_classes"], list)
        assert isinstance(runtime_results["list_namespaces"], list)
        assert isinstance(runtime_results["list_data_items"], list)
        assert isinstance(runtime_results["list_data_types"], list)
        assert isinstance(runtime_results["list_strings"], list)
        assert isinstance(runtime_results["get_data_by_label"], list)
        assert isinstance(runtime_results["get_bytes"], str)
        assert isinstance(runtime_results["search_bytes"], list)
        assert isinstance(runtime_results["get_struct"], dict)
        assert isinstance(runtime_results["get_enum"], dict)
        assert isinstance(runtime_results["list_bookmarks"], list)
        assert runtime_results["get_struct"].get("name") == "__it_struct"
        assert runtime_results["get_enum"].get("name") == "__it_enum"
        assert any(item.get("comment") == "runtime readonly seed" for item in runtime_results["list_bookmarks"])
    finally:
        try:
            cli.close_session(target)
        except Exception:
            pass
