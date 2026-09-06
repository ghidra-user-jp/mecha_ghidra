"""Every dict a shared-sync runtime operation returns must satisfy its tool's output schema.

The output models are ``extra="forbid"``, so a key the runtime adds without a
matching schema field turns a *completed* repository operation into a tool
error after the fact (this is exactly how ``pull_project_program`` failed on a
real Ghidra Server).  This test reads the ``return {...}`` literals out of the
runtime source and validates their key sets against the schema.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_all_tool_specs

RUNTIME_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "ghidra_mcp" / "infrastructure" / "ghidra_adapter" / "runtime"
)

# Helper methods whose dict results are returned by a public operation.
_EXTRA_SOURCES: dict[str, tuple[str, ...]] = {
    "commit_project_program": ("_handle_commit_conflict_locked", "_keep_commit_conflict_locked"),
}


def _functions_by_name() -> dict[str, ast.FunctionDef]:
    functions: dict[str, ast.FunctionDef] = {}
    for path in RUNTIME_DIR.glob("sync_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.setdefault(node.name, node)
    return functions


def _status_dict_literals(function: ast.FunctionDef) -> list[tuple[set[str], bool]]:
    """Return (literal keys, has_unpack) for each dict literal that carries a ``status`` key."""

    found: list[tuple[set[str], bool]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Dict):
            continue
        keys: set[str] = set()
        has_unpack = False
        for key in node.keys:
            if key is None:
                has_unpack = True
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
        if "status" in keys:
            found.append((keys, has_unpack))
    return found


def _shared_sync_specs():
    return [
        spec
        for spec in get_all_tool_specs().values()
        if spec.executor_kind == ExecutorKind.SHARED_SYNC_METHOD and "status" in spec.output_model.model_fields
    ]


@pytest.mark.parametrize("spec", _shared_sync_specs(), ids=lambda spec: spec.name)
def test_runtime_return_dicts_fit_the_declared_output_schema(spec):
    functions = _functions_by_name()
    sources = (spec.command_or_method, *_EXTRA_SOURCES.get(spec.command_or_method, ()))
    fields = spec.output_model.model_fields
    required = {name for name, field in fields.items() if field.is_required()}
    literals = [literal for name in sources for literal in _status_dict_literals(functions[name])]
    assert literals, f"no status dict literal found for {spec.name}"
    problems: list[str] = []
    for keys, has_unpack in literals:
        extra = sorted(keys - set(fields))
        if extra:
            problems.append(f"{spec.name}: runtime returns keys missing from the schema: {', '.join(extra)}")
        if not has_unpack:
            missing = sorted(required - keys)
            if missing:
                problems.append(f"{spec.name}: runtime omits required schema keys: {', '.join(missing)}")
    assert not problems, "\n".join(problems)
