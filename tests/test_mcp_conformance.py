"""The conformance fixtures (tests/mcp_conformance) and the official suite that calls them.

The fixtures are checked in process, over the product's own Streamable HTTP app, so they need no Node.  The
official suite runs only with MECHA_CONFORMANCE=1: it needs Node and the pinned npm package
(MECHA_CONFORMANCE_COMMAND replaces the command, for an offline wrapper).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ghidra_mcp.contracts.tool_spec import filter_tool_specs
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from http_support import messages_in, post, serving_app
from mcp_conformance.fixtures import FIXTURE_TOOLS, STATIC_TEXT_URI
from mcp_conformance.server import build_server

ROOT = Path(__file__).resolve().parents[1]
ELICITATION = {"elicitation": {}}


@contextlib.asynccontextmanager
async def serving():
    async with serving_app(build_server()) as client:
        yield client


async def request(client, method: str, params: dict | None = None, *, name: str | None = None, capabilities=None):
    """One 2026-07-28 request: the HTTP status and the JSON-RPC message."""
    response = await post(client, method, params, name=name, capabilities=capabilities)
    return response.status_code, response.json()


async def call(client, tool: str, *, capabilities=None, **extra):
    return await request(
        client, "tools/call", {"name": tool, "arguments": {}, **extra}, name=tool, capabilities=capabilities
    )


def _run(coroutine):
    return asyncio.run(coroutine)


def _answer(name: str, content: dict) -> dict:
    return {"inputResponses": {name: {"action": "accept", "content": content}}}


class TestTheFixturesStayInTests:
    def test_the_product_publishes_none_of_them(self):
        runtime = create_mcp_server(
            specs=filter_tool_specs(), registry_provider=lambda: None, dispatcher_provider=lambda: dispatch_tool
        )
        names = {binding.definition.name for binding in runtime.mcp.bindings.values()}
        assert not {fixture.name for fixture in FIXTURE_TOOLS} & names
        assert not {tool.name for tool in _run(runtime.mcp.list_tools())} & {fixture.name for fixture in FIXTURE_TOOLS}

    def test_no_product_source_refers_to_them(self):
        for path in (ROOT / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "mcp_conformance" not in text and "test_simple_text" not in text, path

    def test_the_test_server_lists_both_the_products_tools_and_the_fixtures(self):
        async def check():
            async with serving() as client:
                status, reply = await request(client, "tools/list")
                names = {tool["name"] for tool in reply["result"]["tools"]}
                assert status == 200
                assert set(filter_tool_specs()) <= names and {f.name for f in FIXTURE_TOOLS} <= names
                listed = {tool["name"]: tool for tool in reply["result"]["tools"]}
                schema = listed["json_schema_2020_12_tool"]["inputSchema"]
                assert schema["$schema"].endswith("2020-12/schema") and schema["additionalProperties"] is False
                assert schema["$defs"]["address"]["$anchor"] == "addressDef" and "allOf" in schema and "if" in schema

        _run(check())


class TestContentFixtures:
    @pytest.mark.parametrize(
        ("tool", "types"),
        [
            ("test_simple_text", ["text"]),
            ("test_image_content", ["image"]),
            ("test_audio_content", ["audio"]),
            ("test_embedded_resource", ["resource"]),
            ("test_multiple_content_types", ["text", "image", "resource"]),
        ],
    )
    def test_each_returns_the_content_the_suite_asks_for(self, tool, types):
        async def check():
            async with serving() as client:
                status, reply = await call(client, tool)
                result = reply["result"]
                assert status == 200 and result["resultType"] == "complete" and not result.get("isError")
                assert [block["type"] for block in result["content"]] == types

        _run(check())

    def test_the_error_fixture_returns_an_error_result_and_not_a_protocol_error(self):
        async def check():
            async with serving() as client:
                status, reply = await call(client, "test_error_handling")
                assert status == 200 and reply["result"]["isError"] is True

        _run(check())

    def test_an_unknown_tool_is_a_protocol_error(self):
        async def check():
            async with serving() as client:
                status, reply = await call(client, "test_tool_that_is_not_built")
                assert status == 400 and reply["error"]["code"] == -32602

        _run(check())

    def test_a_call_that_needs_an_undeclared_capability_is_32021(self):
        async def check():
            async with serving() as client:
                status, reply = await call(client, "test_missing_capability")
                assert status == 400 and reply["error"]["code"] == -32021
                assert reply["error"]["data"]["requiredCapabilities"] == {"sampling": {}}
                status, reply = await call(client, "test_missing_capability", capabilities={"sampling": {}})
                assert status == 200 and "result" in reply

        _run(check())


class TestProgress:
    def test_a_call_with_a_token_streams_three_reports_then_its_result(self):
        async def check():
            async with serving() as client:
                name = "test_tool_with_progress"
                response = await post(
                    client,
                    "tools/call",
                    {"name": name, "arguments": {}},
                    name=name,
                    meta={"progressToken": "progress-test-1"},
                )
                assert response.headers["content-type"].startswith("text/event-stream")
                *reports, reply = messages_in(response)
                assert [report["method"] for report in reports] == ["notifications/progress"] * 3
                assert {report["params"]["progressToken"] for report in reports} == {"progress-test-1"}
                assert [report["params"]["progress"] for report in reports] == [0, 50, 100]
                assert reply["id"] == 1 and reply["result"]["content"][0]["text"] == "Progress test completed."

        _run(check())

    def test_the_same_call_without_a_token_sends_no_report_and_answers_plain_json(self):
        async def check():
            async with serving() as client:
                response = await post(
                    client,
                    "tools/call",
                    {"name": "test_tool_with_progress", "arguments": {}},
                    name="test_tool_with_progress",
                )
                assert response.headers["content-type"].startswith("application/json")
                assert response.json()["result"]["content"][0]["text"] == "Progress test completed."

        _run(check())


class TestResourcesPromptsAndCompletion:
    def test_resources(self):
        async def check():
            async with serving() as client:
                _, listed = await request(client, "resources/list")
                uris = {resource["uri"] for resource in listed["result"]["resources"]}
                assert {STATIC_TEXT_URI, "test://static-binary"} <= uris
                assert all(resource.get("description") for resource in listed["result"]["resources"])
                _, templates = await request(client, "resources/templates/list")
                assert "test://template/{id}/data" in {
                    t["uriTemplate"] for t in templates["result"]["resourceTemplates"]
                }
                _, text = await request(client, "resources/read", {"uri": STATIC_TEXT_URI}, name=STATIC_TEXT_URI)
                assert text["result"]["contents"][0]["text"].startswith("This is the content")
                uri = "test://template/123/data"
                _, data = await request(client, "resources/read", {"uri": uri}, name=uri)
                assert json.loads(data["result"]["contents"][0]["text"]) == {
                    "id": "123",
                    "templateTest": True,
                    "data": "Data for ID: 123",
                }
                status, missing = await request(client, "resources/read", {"uri": "test://nope"}, name="test://nope")
                assert status == 400 and missing["error"]["code"] == -32602

        _run(check())

    def test_prompts_and_completion(self):
        async def check():
            async with serving() as client:
                _, listed = await request(client, "prompts/list")
                prompts = {prompt["name"]: prompt for prompt in listed["result"]["prompts"]}
                assert "test_simple_prompt" in prompts and all(p.get("description") for p in prompts.values())
                assert [a["name"] for a in prompts["test_prompt_with_arguments"]["arguments"]] == ["arg1", "arg2"]
                name = "test_prompt_with_arguments"
                params = {"name": name, "arguments": {"arg1": "hello", "arg2": "world"}}
                _, got = await request(client, "prompts/get", params, name=name)
                text = got["result"]["messages"][0]["content"]["text"]
                assert text == "Prompt with arguments: arg1='hello', arg2='world'"
                status, bad = await request(client, "prompts/get", {"name": name, "arguments": {}}, name=name)
                assert status == 400 and bad["error"]["code"] == -32602
                status, unknown = await request(client, "prompts/get", {"name": "nope"}, name="nope")
                assert status == 400 and unknown["error"]["code"] == -32602
                params = {"ref": {"type": "ref/prompt", "name": name}, "argument": {"name": "arg1", "value": "par"}}
                _, completed = await request(client, "completion/complete", params)
                assert completed["result"]["completion"]["values"] == []

        _run(check())

    def test_the_server_advertises_what_it_now_serves(self):
        async def check():
            async with serving() as client:
                _, discovered = await request(client, "server/discover")
                capabilities = discovered["result"]["capabilities"]
                assert {"tools", "resources", "prompts", "completions"} <= set(capabilities)
                assert "logging" not in capabilities  # deprecated: not adopted

        _run(check())


class TestInputRequired:
    def test_an_elicitation_round_trip(self):
        async def check():
            async with serving() as client:
                tool = "test_input_required_result_elicitation"
                _, first = await call(client, tool, capabilities=ELICITATION)
                result = first["result"]
                assert result["resultType"] == "input_required"
                assert result["inputRequests"]["user_name"]["method"] == "elicitation/create"
                _, second = await call(
                    client, tool, capabilities=ELICITATION, **_answer("user_name", {"name": "Alice"})
                )
                assert second["result"]["resultType"] == "complete"
                assert second["result"]["content"][0]["text"] == "Hello, Alice!"
                # A wrong key asks again, and extra keys are ignored.
                _, again = await call(client, tool, capabilities=ELICITATION, **_answer("other", {"name": "Alice"}))
                assert again["result"]["resultType"] == "input_required"
                both = {
                    "inputResponses": {
                        **_answer("user_name", {"name": "Bob"})["inputResponses"],
                        "extra": {"action": "cancel"},
                    }
                }
                _, ignored = await call(client, tool, capabilities=ELICITATION, **both)
                assert ignored["result"]["content"][0]["text"] == "Hello, Bob!"

        _run(check())

    def test_the_request_state_is_sealed_and_a_tampered_one_is_refused(self):
        async def check():
            async with serving() as client:
                tool = "test_input_required_result_request_state"
                _, first = await call(client, tool, capabilities=ELICITATION)
                state = first["result"]["requestState"]
                assert state != "confirm-pending" and state.startswith("v1.")
                answer = _answer("confirm", {"ok": True})
                _, done = await call(client, tool, capabilities=ELICITATION, requestState=state, **answer)
                assert "state-ok" in done["result"]["content"][0]["text"]
                tampered = state[:-2] + ("AA" if not state.endswith("AA") else "BB")
                status, refused = await call(client, tool, capabilities=ELICITATION, requestState=tampered, **answer)
                assert status == 400 and refused["error"]["code"] == -32602

        _run(check())

    def test_a_multi_round_flow_changes_the_state_each_round(self):
        async def check():
            async with serving() as client:
                tool = "test_input_required_result_multi_round"
                _, one = await call(client, tool, capabilities=ELICITATION)
                assert list(one["result"]["inputRequests"]) == ["step1"]
                _, two = await call(
                    client,
                    tool,
                    capabilities=ELICITATION,
                    requestState=one["result"]["requestState"],
                    **_answer("step1", {"name": "A"}),
                )
                assert list(two["result"]["inputRequests"]) == ["step2"]
                assert two["result"]["requestState"] != one["result"]["requestState"]
                _, three = await call(
                    client,
                    tool,
                    capabilities=ELICITATION,
                    requestState=two["result"]["requestState"],
                    **_answer("step2", {"color": "red"}),
                )
                assert three["result"]["resultType"] == "complete"

        _run(check())

    def test_inputs_are_requested_only_for_what_the_client_declared(self):
        async def check():
            async with serving() as client:
                tool = "test_input_required_result_capabilities"
                _, asks = await call(client, tool, capabilities=ELICITATION)
                assert [r["method"] for r in asks["result"]["inputRequests"].values()] == ["elicitation/create"]
                _, none = await call(client, tool, capabilities={"sampling": {}})
                assert none["result"]["resultType"] == "complete"

        _run(check())


@pytest.mark.skipif(
    not os.environ.get("MECHA_CONFORMANCE"),
    reason="Run only when MECHA_CONFORMANCE=1 (needs Node and the pinned npm package; see tests/mcp_conformance/run.py)",
)
def test_the_official_suite_passes_against_the_baselines(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "mcp_conformance" / "run.py"), "--output-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert completed.returncode == 0, completed.stdout[-6000:] + completed.stderr[-2000:]
