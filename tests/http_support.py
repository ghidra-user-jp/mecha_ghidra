"""The product's Streamable HTTP app called in process, for tests that look at the raw reply.

``product_app`` builds the app with the options ``mecha_ghidra --transport http`` serves with; ``post`` sends one
2026-07-28 request to it, and ``messages_in`` reads the JSON-RPC messages out of the reply, which is one JSON
body or, once a call has reported progress, a stream of server-sent events.  (The in-process transport hands the
reply over when the app has finished it, so these tests see what a stream carried, not when.)
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging

import httpx2

from ghidra_mcp.presentation.transport import streamable_http_run_kwargs

VERSION = "2026-07-28"


def product_app(server, *, streaming: bool = True):
    options = argparse.Namespace(mcp_host="127.0.0.1", mcp_port=0, mcp_path="/mcp", log_level="WARNING")
    kwargs = streamable_http_run_kwargs(
        args=options, logger=logging.getLogger("test"), announce=False, streaming=streaming
    )
    return server.streamable_http_app(**{key: value for key, value in kwargs.items() if key not in ("host", "port")})


@contextlib.asynccontextmanager
async def serving_app(server, *, streaming: bool = True):
    """An HTTP client wired to the product's app for ``server``; the server's session manager runs meanwhile."""
    app = product_app(server, streaming=streaming)  # creates the session manager that run() starts
    async with (
        server.session_manager.run(),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1", trust_env=False
        ) as client,
    ):
        yield client


async def post(
    client,
    method: str,
    params: dict | None = None,
    *,
    name: str | None = None,
    capabilities: dict | None = None,
    meta: dict | None = None,
    request_id: int = 1,
):
    """One 2026-07-28 request, the way a client sends it; ``meta`` adds to ``_meta`` (a ``progressToken``, say)."""
    envelope = {
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": capabilities or {},
        **(meta or {}),
    }
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {**(params or {}), "_meta": envelope}}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": VERSION,
        "Mcp-Method": method,
        **({"Mcp-Name": name} if name else {}),
    }
    return await client.post("/mcp", content=json.dumps(body), headers=headers)


def messages_in(response) -> list[dict]:
    """The JSON-RPC messages of a reply, in order: the one JSON body, or every event of a stream."""
    if response.headers["content-type"].startswith("application/json"):
        return [response.json()]
    messages = []
    for frame in response.text.replace("\r\n", "\n").split("\n\n"):
        data = [line.removeprefix("data:").strip() for line in frame.splitlines() if line.startswith("data:")]
        if data:
            messages.append(json.loads("".join(data)))
    return messages
