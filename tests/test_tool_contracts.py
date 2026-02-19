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


def test_txn_requires_checkout_guard_for_versioned_program():
    core_module = _load_ast(CORE_PATH)
    txn = None
    for node in core_module.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_txn":
            txn = node
            break
    assert txn is not None, "_txn が見つかりません"

    guard_call_found = False
    for statement in txn.body:
        if not isinstance(statement, ast.Expr):
            continue
        call = statement.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_ensure_checkout_for_versioned_program"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "ctx"
        ):
            guard_call_found = True
            break

    assert guard_call_found, "_txn の先頭で checkout ガードを実行する必要があります"


def _find_function_def(module: ast.Module, function_name: str) -> ast.FunctionDef:
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"{function_name} が見つかりません")


def test_rename_variable_reads_parameters_for_argument_rename():
    core_module = _load_ast(CORE_PATH)
    rename_variable = _find_function_def(core_module, "rename_variable")

    has_get_parameters = False
    for node in ast.walk(rename_variable):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "getParameters"
        ):
            has_get_parameters = True
            break

    assert has_get_parameters, "rename_variable は引数リネームのため getParameters を参照する必要があります"


def test_set_function_prototype_uses_apply_function_signature_cmd():
    core_module = _load_ast(CORE_PATH)
    set_function_prototype = _find_function_def(core_module, "set_function_prototype")

    uses_apply_cmd = False
    uses_set_prototype_string = False

    for node in ast.walk(set_function_prototype):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "ApplyFunctionSignatureCmd":
            uses_apply_cmd = True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "setPrototypeString":
            uses_set_prototype_string = True

    assert uses_apply_cmd, "set_function_prototype は ApplyFunctionSignatureCmd を使う必要があります"
    assert not uses_set_prototype_string, "set_function_prototype で setPrototypeString は使わないでください"


def test_parse_data_type_does_not_call_find_data_types_directly():
    core_module = _load_ast(CORE_PATH)
    parse_data_type = _find_function_def(core_module, "_parse_data_type")

    has_direct_find_data_types = False
    for node in ast.walk(parse_data_type):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "findDataTypes"
        ):
            has_direct_find_data_types = True
            break

    assert not has_direct_find_data_types, "_parse_data_type で dtm.findDataTypes を直接呼ばないでください"


def test_set_local_variable_type_uses_high_symbol_update_path():
    core_module = _load_ast(CORE_PATH)
    set_local_variable_type = _find_function_def(core_module, "set_local_variable_type")

    uses_high_function = False
    uses_update_db_variable = False

    for node in ast.walk(set_local_variable_type):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "_decompile_high_function":
                uses_high_function = True
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "HighFunctionDBUtil"
                and node.func.attr == "updateDBVariable"
            ):
                uses_update_db_variable = True

    assert uses_high_function, "set_local_variable_type は高レベルデコンパイル結果を利用する必要があります"
    assert uses_update_db_variable, "set_local_variable_type は HighFunctionDBUtil.updateDBVariable を使う必要があります"


def test_set_global_data_type_reads_clear_mode_param():
    core_module = _load_ast(CORE_PATH)
    set_global_data_type = _find_function_def(core_module, "set_global_data_type")

    reads_clear_mode = False
    for node in ast.walk(set_global_data_type):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "params"
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "clear_mode"
        ):
            reads_clear_mode = True
            break

    assert reads_clear_mode, "set_global_data_type は clear_mode パラメータを受け取る必要があります"


def test_create_class_command_exists_in_supported_commands():
    core_module = _load_ast(CORE_PATH)
    supported = _supported_commands(core_module)
    assert "create_class" in supported
    assert supported["create_class"] == "create_class"


def test_add_class_members_does_not_create_struct_implicitly():
    core_module = _load_ast(CORE_PATH)
    add_class_members = _find_function_def(core_module, "add_class_members")

    has_strict_struct_binding = False
    for node in ast.walk(add_class_members):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "_ensure_class_struct":
            continue
        for keyword in node.keywords:
            if keyword.arg != "create_struct_if_missing":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                has_strict_struct_binding = True
                break
        if has_strict_struct_binding:
            break

    assert has_strict_struct_binding, "add_class_members はクラス構造体を暗黙作成せず既存紐付けを利用する必要があります"


def _calls_function(fn: ast.FunctionDef, function_name: str) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == function_name:
            return True
    return False


def test_list_classes_uses_namespace_iterator_helper():
    core_module = _load_ast(CORE_PATH)
    list_classes = _find_function_def(core_module, "list_classes")
    assert _calls_function(list_classes, "_iter_namespaces")


def test_list_namespaces_uses_namespace_iterator_helper():
    core_module = _load_ast(CORE_PATH)
    list_namespaces = _find_function_def(core_module, "list_namespaces")
    assert _calls_function(list_namespaces, "_iter_namespaces")


def test_list_exports_uses_export_compatibility_helper():
    core_module = _load_ast(CORE_PATH)
    list_exports = _find_function_def(core_module, "list_exports")
    assert _calls_function(list_exports, "_is_exported_symbol")


def test_get_xrefs_from_uses_iter_items_for_reference_arrays():
    core_module = _load_ast(CORE_PATH)
    get_xrefs_from = _find_function_def(core_module, "get_xrefs_from")
    assert _calls_function(get_xrefs_from, "_iter_items")


def test_find_ghidra_class_uses_iter_items_for_symbol_collections():
    core_module = _load_ast(CORE_PATH)
    find_ghidra_class = _find_function_def(core_module, "_find_ghidra_class")
    assert _calls_function(find_ghidra_class, "_iter_items")


def test_get_enum_does_not_require_concrete_enumdatatype_instance():
    core_module = _load_ast(CORE_PATH)
    get_enum = _find_function_def(core_module, "get_enum")

    uses_concrete_isinstance_check = False
    for node in ast.walk(get_enum):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "isinstance":
            continue
        if len(node.args) < 2:
            continue
        target = node.args[1]
        if isinstance(target, ast.Name) and target.id == "EnumDataType":
            uses_concrete_isinstance_check = True
            break

    assert not uses_concrete_isinstance_check, "get_enum は EnumDataType 具象型への厳格依存を避ける必要があります"


def test_execute_wraps_handler_result_with_json_safe():
    core_module = _load_ast(CORE_PATH)
    execute = _find_function_def(core_module, "execute")

    wraps_json_safe = False
    for node in ast.walk(execute):
        if not isinstance(node, ast.Return):
            continue
        call = node.value
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_json_safe"
            and call.args
            and isinstance(call.args[0], ast.Call)
            and isinstance(call.args[0].func, ast.Name)
            and call.args[0].func.id == "handler"
        ):
            wraps_json_safe = True
            break

    assert wraps_json_safe, "execute は返却値を _json_safe で正規化する必要があります"
