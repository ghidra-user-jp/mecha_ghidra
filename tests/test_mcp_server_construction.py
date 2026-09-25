"""Server bootstrap: version fallback, published-schema checks, constructor surface."""

from __future__ import annotations

import importlib.metadata
import inspect

import pytest
from jsonschema import Draft202012Validator
from mcp.types import Tool, ToolAnnotations
from pydantic import BaseModel

from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
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


@pytest.mark.parametrize("large_result_mode", ["resource", "inline"])
def test_every_published_schema_is_a_valid_json_schema(large_result_mode):
    # The server no longer checks its schemas while it starts (that took most of
    # its construction time). They depend only on the tool definitions and the
    # large-result mode, so every tool of the full profile in both modes covers
    # every schema a server can publish.
    runtime = _runtime_for(
        filter_tool_specs(profile=ToolProfile.FULL),
        presentation_config=ToolPresentationConfig(large_result_mode=large_result_mode),
    )
    for name, binding in runtime.mcp.bindings.items():
        for kind, schema in (("input", binding.definition.input_schema), ("output", binding.definition.output_schema)):
            try:
                Draft202012Validator.check_schema(schema)
            except Exception as exc:
                pytest.fail(f"{name} publishes an invalid {kind} schema: {exc}")


def _runtime_for(specs, **kwargs):
    return create_mcp_server(
        specs=specs, registry_provider=lambda: None, dispatcher_provider=lambda: dispatch_tool, **kwargs
    )


def test_valid_published_schemas_construct():
    server = _server([_binding("healthy")])

    assert set(server.bindings) == {"healthy"}
    assert set(server.output_validators) == {"healthy"}


def test_server_does_not_carry_an_unused_log_level():
    assert "log_level" not in inspect.signature(GhidraMCPServer.__init__).parameters
    runtime = _runtime()
    assert not hasattr(runtime.mcp, "log_level")
