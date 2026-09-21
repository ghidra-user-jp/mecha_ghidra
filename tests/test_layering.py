"""Architecture guard: module-level imports must follow the layer direction.

presentation -> application -> (ports) -> infrastructure -> ghidra_headless.
``domain`` and ``contracts`` import nothing from the other layers, and
``ghidra_headless`` never imports ``ghidra_mcp``.

One deliberate exception: ``ghidra_mcp.contracts`` may import
``ghidra_headless.contracts``, the JVM-free rules the core enforces, so the
tool schema and the core validate with the same code.  The exception is safe
only while that package stays free of ``jpype``/``pyghidra``/``ghidra``, which
``test_headless_contracts_import_without_the_jvm_stack`` checks.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

FORBIDDEN: dict[str, tuple[str, ...]] = {
    "ghidra_headless": ("ghidra_mcp",),
    "ghidra_mcp/domain": (
        "ghidra_mcp.application",
        "ghidra_mcp.infrastructure",
        "ghidra_mcp.presentation",
        "ghidra_headless",
        "mcp",
    ),
    "ghidra_mcp/contracts": (
        "ghidra_mcp.application",
        "ghidra_mcp.infrastructure",
        "ghidra_mcp.presentation",
        "ghidra_headless",
    ),
    "ghidra_mcp/application": ("ghidra_mcp.infrastructure", "ghidra_mcp.presentation", "ghidra_headless"),
    "ghidra_mcp/infrastructure": ("ghidra_mcp.presentation",),
}

# layer -> modules that are exempt from that layer's forbidden prefixes.
ALLOWED: dict[str, tuple[str, ...]] = {
    "ghidra_mcp/contracts": ("ghidra_headless.contracts",),
}
JVM_STACK_MODULES = ("jpype", "_jpype", "pyghidra", "ghidra")


def _module_level_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


@pytest.mark.parametrize("layer", sorted(FORBIDDEN))
def test_layer_does_not_import_forbidden_layers(layer: str):
    violations: list[str] = []
    for path in sorted((SRC / layer).rglob("*.py")):
        for imported in _module_level_imports(path):
            if any(imported == ok or imported.startswith(ok + ".") for ok in ALLOWED.get(layer, ())):
                continue
            for forbidden in FORBIDDEN[layer]:
                if imported == forbidden or imported.startswith(forbidden + "."):
                    violations.append(f"{path.relative_to(SRC)}: imports {imported}")
    assert not violations, "\n".join(violations)


def test_headless_contracts_declare_no_jvm_imports():
    """Static half of the exemption: no module under ghidra_headless.contracts names the JVM stack, even lazily."""

    violations: list[str] = []
    for path in sorted((SRC / "ghidra_headless" / "contracts").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] in JVM_STACK_MODULES:
                    violations.append(f"{path.relative_to(SRC)}:{node.lineno}: imports {name}")
    assert not violations, "\n".join(violations)


SERVER_STACK_MODULES = (*JVM_STACK_MODULES, "mcp", "uvicorn", "starlette", "anyio")


def _modules_loaded_by(*imports: str, watched: tuple[str, ...]) -> list[str]:
    """Import ``imports`` in a fresh interpreter and return the watched top-level packages that got loaded."""

    script = (
        "import json, sys\n"
        + "".join(f"import {name}\n" for name in imports)
        + "print(json.dumps(sorted({name.split('.')[0] for name in sys.modules} & set(%r))))\n" % (watched,)
    )
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    return json.loads(completed.stdout)


def test_headless_contracts_import_without_the_jvm_stack():
    """Dynamic half of the exemption: importing the package in a fresh interpreter loads no JVM module."""

    loaded = _modules_loaded_by(
        "ghidra_headless.contracts", "ghidra_headless.contracts.batch_read", watched=JVM_STACK_MODULES
    )
    assert loaded == []


@pytest.mark.parametrize(
    "leaf",
    ["ghidra_mcp.domain", "ghidra_mcp.contracts", "ghidra_mcp.contracts.batch_models", "ghidra_mcp.application.locks"],
)
def test_leaf_layers_import_without_the_server_stack(leaf: str):
    """The layer rule holds at runtime too: a leaf import must not drag in the CLI, MCP SDK or JVM bridge.

    Package ``__init__`` files resolve their re-exports lazily (``ghidra_mcp._lazy``)
    so that ``import ghidra_mcp.<leaf>`` never triggers the presentation layer.
    """

    assert _modules_loaded_by(leaf, watched=SERVER_STACK_MODULES) == []


def test_lazy_package_exports_resolve_and_are_cached():
    import ghidra_mcp
    import ghidra_mcp.application
    import ghidra_mcp.infrastructure
    import ghidra_mcp.presentation

    assert callable(ghidra_mcp.main)
    assert "main" in dir(ghidra_mcp)
    assert ghidra_mcp.presentation.dispatch_tool is ghidra_mcp.presentation.tool_dispatcher.dispatch_tool
    assert "CORE_COMMANDS" in dir(ghidra_mcp.application) and ghidra_mcp.application.CORE_COMMANDS
    assert ghidra_mcp.infrastructure.LockManager is ghidra_mcp.application.locks.LockManager
    with pytest.raises(AttributeError):
        ghidra_mcp.presentation.no_such_export  # noqa: B018


def test_compatibility_shims_still_export_the_moved_symbols():
    from ghidra_mcp import ghidra_installation
    from ghidra_mcp.infrastructure import locks
    from ghidra_mcp.infrastructure.bsim import cli_runner

    assert callable(ghidra_installation.validate_linux_arm64_decompiler_install)
    assert locks.LockManager is __import__("ghidra_mcp.application.locks", fromlist=["LockManager"]).LockManager
    assert callable(cli_runner.mask_bsim_url)
