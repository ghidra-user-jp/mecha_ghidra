from __future__ import annotations

from pathlib import Path

from ghidra_headless.handlers.core_command_registry import COMMAND_DEP_KEYS, COMMAND_NAMES
from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_all_tool_specs


ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "src" / "ghidra_headless" / "handlers" / "core.py"
PRESENTATION_CLI_PATH = ROOT / "src" / "ghidra_mcp" / "presentation" / "cli.py"
LEGACY_SERVICES_DIR = ROOT / "src" / "ghidra_mcp" / "services"


def _core_command_specs() -> dict[str, tuple[str, ...]]:
    specs = get_all_tool_specs(include_shared_sync=True)
    return {
        spec.command_or_method: tuple(spec.input_model.model_fields.keys())
        for spec in specs.values()
        if spec.executor_kind == ExecutorKind.CORE_COMMAND
    }


def test_supported_commands_are_built_from_registry_in_declared_order():
    source = CORE_PATH.read_text(encoding="utf-8")
    assert "SUPPORTED_COMMANDS = {command: _make_handler(command) for command in COMMAND_NAMES}" in source
    assert "if tuple(SUPPORTED_COMMANDS.keys()) != COMMAND_NAMES:" in source


def test_core_command_specs_match_supported_commands():
    assert set(_core_command_specs()) == set(COMMAND_NAMES)


def test_tool_spec_inputs_are_covered_by_command_dep_keys():
    mismatches: list[str] = []
    for command, input_keys in _core_command_specs().items():
        dep_keys = set(COMMAND_DEP_KEYS.get(command, ()))
        unknown = sorted(key for key in input_keys if key not in dep_keys)
        if unknown:
            mismatches.append(f"{command} has unused keys: {', '.join(unknown)}")
    assert not mismatches, "\n".join(mismatches)


def test_command_dep_keys_cover_all_supported_commands():
    assert set(COMMAND_DEP_KEYS) == set(COMMAND_NAMES)


def test_presentation_cli_does_not_import_legacy_services_module():
    source = PRESENTATION_CLI_PATH.read_text(encoding="utf-8")
    assert "ghidra_mcp.services" not in source


def test_legacy_services_directory_is_removed():
    assert not LEGACY_SERVICES_DIR.exists()
