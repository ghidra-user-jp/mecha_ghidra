from __future__ import annotations

import ast
from pathlib import Path

from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolExposure, get_all_tool_specs


ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "src" / "ghidra_headless" / "handlers" / "core.py"
CLI_PATH = ROOT / "src" / "ghidra_mcp" / "cli.py"


def _load_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _decorated_tool_names(cli_module: ast.Module) -> set[str]:
    names: set[str] = set()
    for fn in cli_module.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        for decorator in fn.decorator_list:
            if isinstance(decorator, ast.Call):
                target = decorator.func
            else:
                target = decorator
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "mcp"
                and target.attr == "tool"
            ):
                names.add(fn.name)
                break
    return names


def _shared_sync_registered_tool_names(cli_module: ast.Module) -> set[str]:
    for node in cli_module.body:
        if isinstance(node, ast.FunctionDef) and node.name == "register_shared_project_sync_tools":
            names: set[str] = set()
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                if not isinstance(call.func, ast.Attribute):
                    continue
                if call.func.attr != "add_tool":
                    continue
                if not isinstance(call.func.value, ast.Name) or call.func.value.id != "mcp":
                    continue
                if not call.args:
                    continue
                target = call.args[0]
                if isinstance(target, ast.Name):
                    names.add(target.id)
            return names
    raise AssertionError("register_shared_project_sync_tools が見つかりません")


def _supported_commands(core_module: ast.Module) -> dict[str, str]:
    for node in core_module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "SUPPORTED_COMMANDS" for t in node.targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        commands: dict[str, str] = {}
        for key, value in zip(node.value.keys, node.value.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and isinstance(value, ast.Name):
                commands[key.value] = value.id
        return commands
    raise AssertionError("SUPPORTED_COMMANDS が見つかりません")


def _handler_param_keys(core_module: ast.Module) -> dict[str, set[str]]:
    keys_by_handler: dict[str, set[str]] = {}
    for node in core_module.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if not node.args.args or node.args.args[0].arg != "params":
            continue

        keys: set[str] = set()

        class Visitor(ast.NodeVisitor):
            def visit_Call(self, call: ast.Call) -> None:
                if (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "get"
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "params"
                    and call.args
                    and isinstance(call.args[0], ast.Constant)
                    and isinstance(call.args[0].value, str)
                ):
                    keys.add(call.args[0].value)
                self.generic_visit(call)

            def visit_Subscript(self, subscript: ast.Subscript) -> None:
                if isinstance(subscript.value, ast.Name) and subscript.value.id == "params":
                    key = subscript.slice
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        keys.add(key.value)
                self.generic_visit(subscript)

        Visitor().visit(node)
        keys_by_handler[node.name] = keys
    return keys_by_handler


def test_tool_specs_cover_all_public_tools():
    cli_module = _load_ast(CLI_PATH)

    decorated_names = _decorated_tool_names(cli_module)
    shared_sync_registered = _shared_sync_registered_tool_names(cli_module)
    expected_public = decorated_names | shared_sync_registered

    specs = get_all_tool_specs(include_shared_sync=True)
    assert set(specs) == expected_public


def test_core_command_spec_keys_are_consumed_by_handlers():
    core_module = _load_ast(CORE_PATH)
    supported = _supported_commands(core_module)
    handler_keys = _handler_param_keys(core_module)

    specs = get_all_tool_specs(include_shared_sync=True)
    mismatches: list[str] = []

    for spec in specs.values():
        if spec.executor_kind != ExecutorKind.CORE_COMMAND:
            continue
        command = spec.command_or_method
        handler_name = supported[command]
        unknown_keys = sorted(
            key for key in spec.input_model.model_fields.keys() if key not in handler_keys.get(handler_name, set())
        )
        if unknown_keys:
            mismatches.append(f"{command} -> {handler_name} が未使用のキー: {', '.join(unknown_keys)}")

    assert not mismatches, "\n".join(mismatches)


def test_shared_sync_specs_are_gated_by_exposure():
    specs = get_all_tool_specs(include_shared_sync=True)
    shared_sync_names = {
        name
        for name, spec in specs.items()
        if spec.exposure == ToolExposure.SHARED_SYNC
    }

    assert shared_sync_names == {
        "get_project_sync_status",
        "get_version_history",
        "get_version_diff",
        "checkout_project_program",
        "add_project_program_to_version_control",
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "reload_project_program",
    }


def test_shared_sync_specs_match_registration_function():
    cli_module = _load_ast(CLI_PATH)
    shared_sync_registered = _shared_sync_registered_tool_names(cli_module)

    specs = get_all_tool_specs(include_shared_sync=True)
    shared_sync_names = {
        name
        for name, spec in specs.items()
        if spec.exposure == ToolExposure.SHARED_SYNC
    }

    assert shared_sync_registered == shared_sync_names


def test_typed_input_models_for_function_listing_slice():
    specs = get_all_tool_specs(include_shared_sync=True)

    def _assert_fields(tool_name: str, expected_fields: dict[str, tuple[type, object]]):
        model = specs[tool_name].input_model
        fields = model.model_fields
        assert set(fields.keys()) == set(expected_fields.keys())
        for key, (expected_type, expected_default) in expected_fields.items():
            assert fields[key].annotation is expected_type
            if expected_default is ...:
                assert fields[key].is_required()
            else:
                assert fields[key].default == expected_default

    _assert_fields(
        "list_methods",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_functions",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_classes",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "search_functions_by_name",
        {
            "query": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "get_function_by_address",
        {
            "address": (str, ...),
        },
    )
