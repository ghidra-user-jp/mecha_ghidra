"""Every ``params.get("...")`` key a core handler reads must exist in its tool schema.

The forward direction (schema keys are consumed) already lives in
``test_tool_contracts``; this is the reverse: a handler must not read a
parameter the MCP client can never send, because ``extra="forbid"`` rejects it.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ghidra_headless.handlers.core_command_registry import COMMAND_TO_IMPL, INTERNAL_COMMAND_NAMES
from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_all_tool_specs

COMMANDS_DIR = Path(__file__).resolve().parents[1] / "src" / "ghidra_headless" / "handlers" / "commands"


def _params_keys_by_function() -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    for path in COMMANDS_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            found: set[str] = set()
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "get"
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id == "params"
                    and sub.args
                    and isinstance(sub.args[0], ast.Constant)
                    and isinstance(sub.args[0].value, str)
                ):
                    found.add(sub.args[0].value)
            keys[node.name] = found
    return keys


def test_handlers_only_read_parameters_that_clients_can_send():
    specs = {
        spec.command_or_method: set(spec.input_model.model_fields)
        for spec in get_all_tool_specs().values()
        if spec.executor_kind == ExecutorKind.CORE_COMMAND
    }
    keys_by_function = _params_keys_by_function()
    problems: list[str] = []
    for command, impl in COMMAND_TO_IMPL.items():
        if command in INTERNAL_COMMAND_NAMES:
            continue
        read_keys = keys_by_function.get(impl.__name__, set())
        # Pagination helpers read offset/limit on the handler's behalf.
        allowed = specs[command] | {"offset", "limit"}
        unreachable = sorted(read_keys - allowed)
        if unreachable:
            problems.append(f"{command} reads keys absent from its schema: {', '.join(unreachable)}")
    assert not problems, "\n".join(problems)
