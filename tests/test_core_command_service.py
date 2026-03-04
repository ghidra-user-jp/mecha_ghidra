from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.usecases.datatypes import DATATYPE_COMMANDS
from ghidra_mcp.application.usecases.functions import FUNCTION_COMMANDS
from ghidra_mcp.application.usecases.memory import MEMORY_COMMANDS
from ghidra_mcp.application.usecases.symbols import SYMBOL_COMMANDS
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


class _NeverCalledExecutor:
    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:  # noqa: ARG002
        raise AssertionError("CoreGateway executor should not be called when injected usecases are provided")


@dataclass
class _RecordingUseCases:
    label: str
    commands: set[str]
    calls: list[tuple[str, dict[str, Any], str]] = field(default_factory=list)

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        assert command in self.commands
        self.calls.append((command, dict(params), target))
        return {"route": self.label, "command": command, "target": target}


def _build_service() -> tuple[CoreCommandService, dict[str, _RecordingUseCases]]:
    usecases = {
        "functions": _RecordingUseCases("functions", set(FUNCTION_COMMANDS)),
        "memory": _RecordingUseCases("memory", set(MEMORY_COMMANDS)),
        "symbols": _RecordingUseCases("symbols", set(SYMBOL_COMMANDS)),
        "datatypes": _RecordingUseCases("datatypes", set(DATATYPE_COMMANDS)),
    }
    service = CoreCommandService(
        CoreGateway(_NeverCalledExecutor()),
        functions_usecases=usecases["functions"],  # type: ignore[arg-type]
        memory_usecases=usecases["memory"],  # type: ignore[arg-type]
        symbols_usecases=usecases["symbols"],  # type: ignore[arg-type]
        datatypes_usecases=usecases["datatypes"],  # type: ignore[arg-type]
    )
    return service, usecases


_COMMAND_TO_ROUTE: dict[str, str] = {}
for _command in FUNCTION_COMMANDS:
    _COMMAND_TO_ROUTE[_command] = "functions"
for _command in MEMORY_COMMANDS:
    _COMMAND_TO_ROUTE[_command] = "memory"
for _command in SYMBOL_COMMANDS:
    _COMMAND_TO_ROUTE[_command] = "symbols"
for _command in DATATYPE_COMMANDS:
    _COMMAND_TO_ROUTE[_command] = "datatypes"


@pytest.mark.parametrize("command", sorted(_COMMAND_TO_ROUTE))
def test_core_command_service_routes_all_commands_to_expected_usecase(command: str):
    service, usecases = _build_service()

    result = service.call(command, {"x": 1}, target="fw")

    expected_route = _COMMAND_TO_ROUTE[command]
    assert result == {"route": expected_route, "command": command, "target": "fw"}
    for route_name, recorder in usecases.items():
        if route_name == expected_route:
            assert recorder.calls == [(command, {"x": 1}, "fw")]
        else:
            assert recorder.calls == []


def test_core_command_service_raises_domain_error_for_unknown_command():
    service, _ = _build_service()

    with pytest.raises(DomainError) as exc_info:
        service.call("unknown_command", {"x": 1}, target="fw")

    err = exc_info.value
    assert err.code == ErrorCode.CORE_EXECUTOR_UNAVAILABLE
    assert err.details == {"command": "unknown_command", "target": "fw"}
