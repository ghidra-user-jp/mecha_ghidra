"""The relay of the Ghidra GUI backend without a JVM: forwarding, the fallback and its refusals (spec §10)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx2
import pytest

from ghidra_mcp.contracts.tool_spec import filter_tool_specs
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.gui_registry import FAILED, ProjectRegistry, RuntimeRecord
from ghidra_mcp.presentation.gui_relay import (
    Fallback,
    Relay,
    RuntimeConfig,
    RuntimeGone,
    _http_relay_app,
    claim_runtime,
    config_mismatch,
    derived_routing_headers,
    release_launch,
    routing_headers_of,
)
from ghidra_mcp.presentation.transport import BearerToken, RuntimeAuth

GUI_SPECS = filter_tool_specs(backend="gui")
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
}


def call(tool: str, message_id: int = 7, **arguments) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def error_of(reply: dict) -> dict:
    return reply["result"]["structuredContent"]["error"]


class FakeRuntime:
    """Answers like the runtime would, or goes away."""

    def __init__(self, *, fail: Exception | None = None, status: int = 200) -> None:
        self.record = SimpleNamespace(runtime_id="r1", token="t")
        self.calls: list[tuple[str | None, str | None]] = []
        self.headers: list[dict[str, str]] = []  # the routing headers of each request, by lowercase name
        self.fail = fail
        self.status = status

    async def post(self, body: bytes, routing):
        message = json.loads(body)
        headers = {name.lower(): value for name, value in routing}
        self.headers.append(headers)
        self.calls.append((message.get("method"), headers.get("mcp-protocol-version")))
        if self.fail is not None:
            raise self.fail
        method = message.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": {"name": "runtime", "version": "x"},
            }
        elif method == "tools/list":
            result = {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in sorted(GUI_SPECS)]}
        elif method == "tools/call":
            result = {"content": [], "structuredContent": {"result": {"from": "runtime"}}}
        else:
            return 202, b""
        return self.status, json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result}).encode()


def relay_run(scenario, *, runtime=None, refusal=None, specs=GUI_SPECS, registry=None):
    async def main():
        fallback = Fallback(specs, ToolPresentationConfig())
        async with fallback.running():
            relay = Relay(specs=specs, fallback=fallback, runtime=runtime, refusal=refusal, registry=registry)
            return await scenario(relay)

    return asyncio.run(main())


class TestForwarding:
    def test_messages_go_to_the_runtime_with_the_settled_protocol_version(self):
        runtime = FakeRuntime()

        async def scenario(relay):
            init = await relay.handle(INIT)
            notified = await relay.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
            called = await relay.handle(call("get_program_info"))
            return init, notified, called

        init, notified, called = relay_run(scenario, runtime=runtime)
        assert init["result"]["serverInfo"]["name"] == "runtime"
        assert notified is None
        assert called["result"]["structuredContent"] == {"result": {"from": "runtime"}}
        assert runtime.calls == [
            ("initialize", None),
            ("notifications/initialized", "2025-11-25"),
            ("tools/call", "2025-11-25"),
        ]

    def test_a_narrower_relay_lists_and_runs_its_own_tools_only(self):
        """A relay whose tools are a subset filters tools/list and refuses the rest itself (spec §10.3)."""
        narrow = filter_tool_specs(backend="gui", profile="readonly")
        runtime = FakeRuntime()

        async def scenario(relay):
            listed = await relay.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            refused = await relay.handle(call("show_in_gui"))
            return listed, refused

        listed, refused = relay_run(scenario, runtime=runtime, specs=narrow)
        assert {tool["name"] for tool in listed["result"]["tools"]} == set(narrow) & set(GUI_SPECS)
        assert "show_in_gui" not in narrow
        assert "Unknown or unpublished tool: show_in_gui" in json.dumps(refused)
        assert [method for method, _ in runtime.calls] == ["tools/list"]

    def test_a_parse_error_and_a_batch(self):
        async def scenario(relay):
            broken = await relay.handle_body(b"{not json")
            batch = await relay.handle_body(
                json.dumps([call("get_program_info", 1), call("get_program_info", 2)]).encode()
            )
            return json.loads(broken), json.loads(batch)

        broken, batch = relay_run(scenario, runtime=FakeRuntime())
        assert broken["error"]["code"] == -32700
        assert [reply["id"] for reply in batch] == [1, 2]


MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


class ServerAsRuntime:
    """A real MCP server of this package (the fallback's build) in the runtime's place: the SDK's own checks."""

    def __init__(self, server: Fallback) -> None:
        self.server = server
        self.record = SimpleNamespace(runtime_id="r1", token="t")

    async def post(self, body: bytes, routing):
        return await self.server.post(body, routing)


class TestRoutingHeaders:
    """From protocol 2026-07-28 on, the runtime checks the HTTP routing headers against the body (-32020)."""

    def test_a_stdio_client_s_requests_go_with_the_headers_an_http_client_sends(self):
        runtime = FakeRuntime()

        async def scenario(relay):
            await relay.handle(
                call("get_program_info") | {"params": {"name": "get_program_info", "_meta": MODERN_META}}
            )
            await relay.handle(INIT)
            await relay.handle(call("get_program_info"))

        relay_run(scenario, runtime=runtime)
        modern, init, settled = runtime.headers
        assert modern == {
            "mcp-protocol-version": "2026-07-28",
            "mcp-method": "tools/call",
            "mcp-name": "get_program_info",
        }
        assert init == {"mcp-method": "initialize"}
        assert settled["mcp-protocol-version"] == "2025-11-25" and settled["mcp-name"] == "get_program_info"

    def test_a_name_that_is_no_plain_header_text_is_base64_wrapped(self):
        message = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "ghidra://results/結果"}}
        headers = dict(derived_routing_headers(message, "2025-11-25"))
        assert headers["mcp-name"] == "=?base64?Z2hpZHJhOi8vcmVzdWx0cy/ntZDmnpw=?="

    def test_an_http_client_s_routing_headers_go_unchanged(self):
        sent = {
            "Host": "127.0.0.1", "Authorization": "Bearer x", "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call", "Mcp-Name": "get_program_info", "Mcp-Param-Region": "a",
        }  # fmt: skip
        routing = routing_headers_of(sent)
        assert [name for name, _ in routing] == ["MCP-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Param-Region"]
        runtime = FakeRuntime()

        async def scenario(relay):
            return await relay.handle(call("get_program_info"), routing)

        relay_run(scenario, runtime=runtime)
        assert runtime.headers == [{name.lower(): value for name, value in routing}]

    def test_a_real_mcp_server_takes_what_the_relays_send(self):
        async def main():
            runtime_server = Fallback(GUI_SPECS, ToolPresentationConfig())
            fallback = Fallback(GUI_SPECS, ToolPresentationConfig())
            async with runtime_server.running(), fallback.running():
                relay = Relay(specs=GUI_SPECS, fallback=fallback, runtime=ServerAsRuntime(runtime_server), refusal=None)
                discovered = await relay.exchange(
                    {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": MODERN_META}}
                )
                listed = await relay.exchange(
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": MODERN_META}}
                )
                app = _http_relay_app(relay, path="/mcp", host="127.0.0.1")
                transport = httpx2.ASGITransport(app=app)
                async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
                    body = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": MODERN_META}}
                    accept = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28"}
                    over_http = await client.post("/mcp", json=body, headers=accept | {"Mcp-Method": "tools/list"})
                    unnamed = await client.post("/mcp", json=body, headers=accept)
                return discovered, listed, over_http, unnamed

        (discovered_status, discovered), (listed_status, listed), over_http, unnamed = asyncio.run(main())
        assert discovered_status == 200 and discovered["result"]["supportedVersions"] == ["2026-07-28"]
        assert listed_status == 200 and {"read_result", "show_in_gui"} <= {t["name"] for t in listed["result"]["tools"]}
        assert over_http.status_code == 200 and "tools" in over_http.json()["result"]
        # The relay answers as the runtime does, status included.
        assert unnamed.status_code == 400 and unnamed.json()["error"]["code"] == -32020


def test_the_result_tools_the_presentation_adds_are_relayed():
    """read_result and search_result are no specs, but the relay publishes and forwards them."""
    runtime = FakeRuntime()

    async def scenario(relay):
        listed = await relay.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        await relay.handle(call("read_result", result_id="r"))
        return relay.tools, listed

    tools, _listed = relay_run(scenario, runtime=runtime)
    assert {"read_result", "search_result"} <= tools
    assert [method for method, _ in runtime.calls] == ["tools/list", "tools/call"]


class TestWhenTheRuntimeIsGone:
    def test_a_call_that_never_reached_it_left_nothing(self):
        runtime = FakeRuntime(fail=RuntimeGone("refused", reached=False))

        async def scenario(relay):
            return await relay.handle(call("create_label", address="0x1", name="ai"))

        error = error_of(relay_run(scenario, runtime=runtime))
        assert error["code"] == "RUNTIME_UNAVAILABLE"
        assert error["details"]["outcome"] == "not_run" and error["details"]["output_state"] == "absent"

    def test_a_write_it_may_have_run_is_uncertain_and_later_calls_never_go_out(self):
        runtime = FakeRuntime(fail=RuntimeGone("reset", reached=True))

        async def scenario(relay):
            first = await relay.handle(call("create_label", address="0x1", name="ai"))
            second = await relay.handle(call("get_program_info"))
            listed = await relay.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            return first, second, listed

        first, second, listed = relay_run(scenario, runtime=runtime)
        assert error_of(first)["details"]["outcome"] == "unknown"
        assert error_of(first)["details"]["output_state"] == "uncertain"
        assert error_of(second)["code"] == "RUNTIME_UNAVAILABLE"
        assert error_of(second)["details"]["reason"] == "runtime_gone"
        # The fallback lists the relay's tools, the result tools included.
        assert {tool["name"] for tool in listed["result"]["tools"]} == {*GUI_SPECS, "read_result", "search_result"}
        assert len(runtime.calls) == 1

    def test_a_token_the_runtime_refuses_means_another_runtime(self):
        runtime = FakeRuntime(status=401)

        async def scenario(relay):
            return await relay.handle(call("get_program_info"))

        assert error_of(relay_run(scenario, runtime=runtime))["code"] == "RUNTIME_UNAVAILABLE"

    def test_a_runtime_that_failed_to_start_says_why(self, tmp_path):
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        registry.write(
            RuntimeRecord(
                runtime_id="r1",
                pid=1,
                endpoint="http://127.0.0.1:1/mcp",
                token="t",
                public=False,
                project_file=str(tmp_path / "GUI.gpr"),
                ghidra_install_dir=None,
                mecha_version="x",
                fingerprint={},
                state=FAILED,
                failure={
                    "stage": "display",
                    "message": "The Ghidra GUI cannot start here",
                    "cause_type": "X",
                    "cause_message": "no display",
                },
            )
        )
        runtime = FakeRuntime(fail=RuntimeGone("refused", reached=False))

        async def scenario(relay):
            await relay.handle(call("get_program_info", 1))
            return await relay.handle(call("get_program_info", 2))

        error = error_of(relay_run(scenario, runtime=runtime, registry=registry))
        assert error["code"] == "STARTUP_FAILED" and error["details"]["stage"] == "display"


class TestConfiguration:
    @staticmethod
    def config(**fingerprint) -> RuntimeConfig:
        base = {
            "versions": {"mecha": "1"},
            "path_policy": {"project_roots": ["/p"]},
            "targets": {},
            "tools": ["a", "b"],
        }
        base.update(fingerprint)
        return RuntimeConfig(fingerprint=base, settings={})

    def record(self, config: RuntimeConfig) -> RuntimeRecord:
        return RuntimeRecord(
            runtime_id="r1", pid=1, endpoint="e", token="t", public=False, project_file="p",
            ghidra_install_dir=None, mecha_version="1", fingerprint=config.fingerprint,
        )  # fmt: skip

    def test_the_same_or_fewer_tools_match(self):
        running = self.record(self.config())
        assert config_mismatch(running, self.config()) is None
        assert config_mismatch(running, self.config(tools=["a"])) is None

    def test_other_roots_versions_targets_or_more_tools_do_not(self):
        running = self.record(self.config())
        mismatch = config_mismatch(running, self.config(path_policy={"project_roots": ["/q"]}, tools=["a", "c"]))
        assert mismatch.code.value == "RUNTIME_CONFIG_MISMATCH"
        assert mismatch.details == {"differs": ["path_policy"], "missing_tools": ["c"]}
        assert config_mismatch(running, self.config(versions={"mecha": "2"})).details == {"differs": ["versions"]}

    def test_a_refused_relay_answers_initialize_but_no_tool_call(self):
        refusal = config_mismatch(self.record(self.config()), self.config(tools=["a", "c"]))

        async def scenario(relay):
            return await relay.handle(INIT), await relay.handle(call("get_program_info"))

        init, called = relay_run(scenario, refusal=refusal)
        assert init["result"]["serverInfo"]["name"] == "mecha_ghidra"
        assert error_of(called)["code"] == "RUNTIME_CONFIG_MISMATCH"
        assert error_of(called)["details"]["missing_tools"] == ["c"]


class TestToken:
    @staticmethod
    def status(auth: RuntimeAuth, headers: list[tuple[bytes, bytes]]) -> int:
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        asyncio.run(BearerToken(app, auth)({"type": "http", "headers": headers}, receive, send))
        return sent[0]["status"]

    @pytest.mark.parametrize(
        ("public", "header", "expected"),
        [
            (False, None, 401),
            (False, b"Bearer wrong", 401),
            (False, b"Bearer right", 200),
            (True, None, 200),
            (True, b"Bearer wrong", 401),
            (True, b"Bearer right", 200),
        ],
    )
    def test_only_the_runtime_s_token_passes(self, public, header, expected):
        headers = [] if header is None else [(b"authorization", header)]
        assert self.status(RuntimeAuth("right", public=public), headers) == expected


class TestRegistration:
    def test_the_record_follows_the_startup_and_goes_when_closed(self, tmp_path):
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        registration = claim_runtime(registry, wait_for_launch=True)
        assert registration is not None and registry.runtime_alive()
        config = RuntimeConfig(fingerprint={"tools": ["a"]}, settings={"lock_timeout_seconds": 30})
        registration.publish(endpoint="http://127.0.0.1:9/mcp", public=False, config=config, ghidra_path=None)
        release_launch(registration)
        assert claim_runtime(registry, wait_for_launch=True) is None  # a second server relays instead
        assert registry.read().state == "starting" and registry.read().token == registration.token
        registration.on_startup_end("ready", None)
        assert registry.read().state == "ready"
        registration.close()
        assert registry.read() is None and not registry.runtime_alive()
