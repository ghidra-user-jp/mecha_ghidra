"""The product's MCP server over its real HTTP stack, plus the conformance fixtures; no Ghidra needed.

    python tests/mcp_conformance/server.py <port>

The tools, the handlers and the HTTP options (stateless Streamable HTTP, JSON responses, the Host and Origin
checks) are the ones ``mecha_ghidra --transport http`` uses; ``fixtures.py`` adds what the official conformance
suite calls by name.  The product's own tools run against an empty registry here: the suite never calls them.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TESTS), str(TESTS.parent / "src")]

from ghidra_mcp.contracts.tool_spec import filter_tool_specs  # noqa: E402
from ghidra_mcp.presentation.mcp_server import create_mcp_server  # noqa: E402
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool  # noqa: E402
from ghidra_mcp.presentation.transport import run_mcp_server, streamable_http_run_kwargs  # noqa: E402
from mcp_conformance.fixtures import install_fixtures  # noqa: E402


class EmptyRegistry:
    """No targets; the conformance suite calls no product tool."""

    def list_targets(self):
        return []

    def call(self, command, params, target):
        raise LookupError(f"{command}: this registry holds no program")


def build_server():
    runtime = create_mcp_server(
        specs=filter_tool_specs(),
        registry_provider=lambda: EmptyRegistry(),
        dispatcher_provider=lambda: dispatch_tool,
    )
    install_fixtures(runtime.mcp)
    return runtime.mcp


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("port", type=int)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--log-level", default="WARNING")
    arguments = parser.parse_args(argv)
    options = argparse.Namespace(
        mcp_host=arguments.host, mcp_port=arguments.port, mcp_path="/mcp", log_level=arguments.log_level
    )
    logger = logging.getLogger("mcp_conformance")
    run_kwargs = streamable_http_run_kwargs(args=options, logger=logger, announce=False)
    run_mcp_server(build_server(), transport="http", log_level=arguments.log_level, **run_kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
