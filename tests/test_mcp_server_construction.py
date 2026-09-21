"""Server bootstrap: version fallback, published-schema checks, constructor surface."""

from __future__ import annotations

import importlib.metadata
import inspect

import pytest
from mcp.types import Tool, ToolAnnotations
from pydantic import BaseModel

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.mcp_server import GhidraMCPServer, create_mcp_server, package_version
from ghidra_mcp.presentation.tool_binding import ToolBinding
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


class NoArguments(BaseModel):
    pass


def _binding(name="probe", *, input_schema=None, output_schema=None) -> ToolBinding:
    definition = Tool(
        name=name,
        description="probe",
        input_schema={"type": "object"} if input_schema is None else input_schema,
        output_schema={"type": "object"} if output_schema is None else output_schema,
        annotations=ToolAnnotations(read_only_hint=True),
    )
    return ToolBinding(definition, dict, NoArguments)


def _server(bindings):
    return GhidraMCPServer(bindings=bindings, specs={}, result_store=None, instructions="probe")


def _runtime(**kwargs):
    return create_mcp_server(
        specs={"list_targets": get_tool_spec("list_targets")},
        registry_provider=lambda: None,
        dispatcher_provider=lambda: dispatch_tool,
        **kwargs,
    )


def test_package_version_falls_back_when_distribution_is_not_installed(monkeypatch):
    def missing(distribution):
        raise importlib.metadata.PackageNotFoundError(distribution)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert package_version() == "0.0.0"
    assert _runtime().mcp.version == "0.0.0"


def test_package_version_reports_installed_distribution(monkeypatch):
    monkeypatch.setattr(importlib.metadata, "version", lambda distribution: f"9.9.9+{distribution}")

    assert package_version() == "9.9.9+mecha_ghidra"
    assert _runtime().mcp.version == "9.9.9+mecha_ghidra"


@pytest.mark.parametrize("kind", ["input", "output"])
def test_invalid_published_schema_fails_at_construction(kind):
    broken = {"type": "object", "properties": {"x": {"type": "not-a-json-type"}}}
    binding = _binding("broken_tool", **{f"{kind}_schema": broken})

    with pytest.raises(ValueError, match=rf"'broken_tool' publishes an invalid {kind} schema"):
        _server([_binding("healthy"), binding])


def test_valid_published_schemas_construct():
    server = _server([_binding("healthy")])

    assert set(server.bindings) == {"healthy"}
    assert set(server.output_validators) == {"healthy"}


def test_server_does_not_carry_an_unused_log_level():
    assert "log_level" not in inspect.signature(GhidraMCPServer.__init__).parameters
    runtime = _runtime()
    assert not hasattr(runtime.mcp, "log_level")
