"""Architecture guard: module-level imports must follow the layer direction.

presentation -> application -> (ports) -> infrastructure -> ghidra_headless.
``domain`` and ``contracts`` import nothing from the other layers, and
``ghidra_headless`` never imports ``ghidra_mcp``.
"""

from __future__ import annotations

import ast
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
            for forbidden in FORBIDDEN[layer]:
                if imported == forbidden or imported.startswith(forbidden + "."):
                    violations.append(f"{path.relative_to(SRC)}: imports {imported}")
    assert not violations, "\n".join(violations)


def test_compatibility_shims_still_export_the_moved_symbols():
    from ghidra_mcp import ghidra_installation
    from ghidra_mcp.infrastructure import locks
    from ghidra_mcp.infrastructure.bsim import cli_runner

    assert callable(ghidra_installation.validate_linux_arm64_decompiler_install)
    assert locks.LockManager is __import__("ghidra_mcp.application.locks", fromlist=["LockManager"]).LockManager
    assert callable(cli_runner.mask_bsim_url)
