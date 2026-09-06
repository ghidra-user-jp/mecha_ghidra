from __future__ import annotations

from typing import Any

import pytest

from ghidra_headless.handlers.core_command_registry import COMMAND_NAMES
from ghidra_mcp.application.commands import CORE_COMMANDS
from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.domain import DomainError, ErrorCode


class _RecordingGateway:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        self.calls.append((command, dict(params), target))
        return {"command": command, "target": target}


def test_core_command_catalog_matches_the_headless_registry():
    assert CORE_COMMANDS == set(COMMAND_NAMES)


@pytest.mark.parametrize("command", sorted(CORE_COMMANDS))
def test_core_command_service_forwards_every_known_command(command: str):
    gateway = _RecordingGateway()
    service = CoreCommandService(gateway)

    result = service.call(command, {"x": 1}, target="fw")

    assert result == {"command": command, "target": "fw"}
    assert gateway.calls == [(command, {"x": 1}, "fw")]


def test_core_command_service_defaults_missing_params_to_empty_dict():
    gateway = _RecordingGateway()
    CoreCommandService(gateway).call("list_functions")
    assert gateway.calls == [("list_functions", {}, "default")]


def test_core_command_service_raises_domain_error_for_unknown_command():
    gateway = _RecordingGateway()
    service = CoreCommandService(gateway)

    with pytest.raises(DomainError) as exc_info:
        service.call("unknown_command", {"x": 1}, target="fw")

    err = exc_info.value
    assert err.code == ErrorCode.CORE_EXECUTOR_UNAVAILABLE
    assert err.details == {"command": "unknown_command", "target": "fw"}
    assert gateway.calls == []
