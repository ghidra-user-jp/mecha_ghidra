from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "src" / "ghidra_headless" / "handlers" / "core.py"
CLI_PATH = ROOT / "src" / "ghidra_mcp" / "cli.py"


def _load_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


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


def _cli_wrappers(cli_module: ast.Module) -> dict[str, set[str] | None]:
    wrappers: dict[str, set[str] | None] = {}
    for fn in cli_module.body:
        if not isinstance(fn, ast.FunctionDef):
            continue

        call_node = None
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "call"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_registry"
            ):
                call_node = node
                break

        if call_node is None:
            continue
        if not call_node.args or not isinstance(call_node.args[0], ast.Constant):
            continue
        if not isinstance(call_node.args[0].value, str):
            continue
        command = call_node.args[0].value

        keys: set[str] | None = None
        if len(call_node.args) >= 2:
            params_expr = call_node.args[1]
            if isinstance(params_expr, ast.Dict):
                keys = {
                    key.value
                    for key in params_expr.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
            elif isinstance(params_expr, ast.Name):
                param_var = params_expr.id
                keys = set()
                for stmt in fn.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id == param_var
                                and isinstance(stmt.value, ast.Dict)
                            ):
                                keys.update(
                                    key.value
                                    for key in stmt.value.keys
                                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                                )
                    elif isinstance(stmt, ast.AnnAssign):
                        if (
                            isinstance(stmt.target, ast.Name)
                            and stmt.target.id == param_var
                            and isinstance(stmt.value, ast.Dict)
                        ):
                            keys.update(
                                key.value
                                for key in stmt.value.keys
                                if isinstance(key, ast.Constant) and isinstance(key.value, str)
                            )

                    for node in ast.walk(stmt):
                        if (
                            isinstance(node, ast.Subscript)
                            and isinstance(node.value, ast.Name)
                            and node.value.id == param_var
                        ):
                            key = node.slice
                            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                keys.add(key.value)

        wrappers[command] = keys
    return wrappers


def test_cli_and_core_commands_are_in_sync():
    core_module = _load_ast(CORE_PATH)
    cli_module = _load_ast(CLI_PATH)

    supported = _supported_commands(core_module)
    wrappers = _cli_wrappers(cli_module)

    assert set(wrappers) == set(supported)


def test_cli_wrapper_params_are_read_by_core_handlers():
    core_module = _load_ast(CORE_PATH)
    cli_module = _load_ast(CLI_PATH)

    supported = _supported_commands(core_module)
    handler_keys = _handler_param_keys(core_module)
    wrappers = _cli_wrappers(cli_module)

    mismatches: list[str] = []
    for command, cli_keys in sorted(wrappers.items()):
        if cli_keys is None:
            continue
        handler = supported[command]
        unknown_keys = sorted(key for key in cli_keys if key not in handler_keys.get(handler, set()))
        if unknown_keys:
            mismatches.append(
                f"{command} -> {handler} が未使用のキー: {', '.join(unknown_keys)}"
            )

    assert not mismatches, "\n".join(mismatches)


def test_default_operand_representation_is_called_with_operand_index():
    core_module = _load_ast(CORE_PATH)
    invalid_calls: list[str] = []

    for node in ast.walk(core_module):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "getDefaultOperandRepresentation":
            continue
        if len(node.args) != 1:
            invalid_calls.append(
                f"line {node.lineno}: 引数数={len(node.args)}"
            )

    assert not invalid_calls, "\n".join(invalid_calls)


def test_collect_has_non_positive_limit_guard():
    core_module = _load_ast(CORE_PATH)
    collect = None
    for node in core_module.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_collect":
            collect = node
            break
    assert collect is not None

    guard_found = False
    for statement in collect.body:
        if not isinstance(statement, ast.If):
            continue
        test = statement.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "limit"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.LtE)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == 0
            and statement.body
            and isinstance(statement.body[0], ast.Return)
            and isinstance(statement.body[0].value, ast.List)
            and not statement.body[0].value.elts
        ):
            guard_found = True
            break

    assert guard_found, "_collect に limit <= 0 の早期returnガードが必要です"
