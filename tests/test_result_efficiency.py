"""Behavior and work-count regressions for result retrieval optimizations."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
import regex
from mcp.types import CallToolResult, TextContent

from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.commands.query_support import page
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation import result_compaction, result_json, result_tools
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.result_errors import present_tool_error
from ghidra_mcp.presentation.result_store import ResultResourceStore, _normalize_json_surrogates
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_errors import ToolError


def stored(text, *, mime="text/plain", store=None):
    store = store or ResultResourceStore()
    entry = store.add(tool="example", target="t", text=text, mime_type=mime, result_type="string", item_count=None)
    assert entry is not None
    return store, entry


def runtime():
    return create_mcp_server(specs={}, registry_provider=lambda: None, dispatcher_provider=lambda: dispatch_tool)


def call(runtime, name, **args):
    result = asyncio.run(runtime.mcp.call_tool(name, args))
    return json.loads(result.content[0].text)


def ctx():
    program = SimpleNamespace(revision=0)
    program.getModificationNumber = lambda: program.revision
    program.getDomainFile = lambda: SimpleNamespace(getPathname=lambda: "/sample")
    return SimpleNamespace(program=program, generation="test")


def test_page_preview_has_items_cursor_and_explicit_nonprefix_offset():
    value = page(
        ctx(), "get_xrefs", {"limit": 100}, ({"from": str(i), "to": "main", "info": "x" * 100} for i in range(101))
    )
    store = ResultResourceStore()
    result = result_compaction.maybe_compact_tool_result(
        tool_name="get_xrefs", target="t", result=value, config=ToolPresentationConfig(), store=store
    )
    preview = json.loads(result.content[0].text.split("----- preview -----\n")[1])
    assert 0 < len(preview["items"]) < 100
    assert preview["items"] == value["items"][: len(preview["items"])]
    assert preview["has_more"] is True
    assert preview["next_cursor"] == value["next_cursor"]
    assert result.structured_content["continue_offset_chars"] == 0
    assert result.structured_content["preview_kind"] == "summary"
    assert json.loads(store.read_text(result.structured_content["result_id"])) == value


def test_large_dictionary_serialization_skips_pretty_threshold_pass(monkeypatch):
    original = result_compaction._delivered_inline_size
    monkeypatch.setattr(
        result_compaction, "_delivered_inline_size", lambda *a, **kw: pytest.fail("redundant pretty serialization")
    )
    result = result_compaction.maybe_compact_tool_result(
        tool_name="example",
        target="t",
        result={"data": "x" * 30000},
        config=ToolPresentationConfig(),
        store=ResultResourceStore(),
    )
    assert isinstance(result, CallToolResult)
    assert result.structured_content["truncated"]
    monkeypatch.setattr(result_compaction, "_delivered_inline_size", original)


def test_json_storage_reuses_serializer_bytes_for_hash(monkeypatch):
    monkeypatch.setattr(result_compaction, "_utf8_size_and_sha256", lambda text: pytest.fail("re-encoded JSON"))
    result = result_compaction.maybe_compact_tool_result(
        tool_name="example",
        target="t",
        result={"text": "日本語" * 10000},
        config=ToolPresentationConfig(),
        store=ResultResourceStore(),
    )
    assert isinstance(result, CallToolResult)
    assert result.structured_content["truncated"]


def test_normalization_copies_only_changed_branches():
    unchanged = ["plain", {"good": "日本語 😀"}]
    value = {"first": unchanged, "bad": ("normal", "\ud83d\ude00", "\ud800"), "last": unchanged}
    result, changed = _normalize_json_surrogates(value)
    assert changed and result is not value
    assert result["first"] is result["last"] is unchanged
    assert result["bad"] == ("normal", "😀", "\ufffd")
    assert list(result) == list(value)
    assert _normalize_json_surrogates(unchanged) == (unchanged, False)


def test_read_fast_path_measures_response_once(monkeypatch):
    _, entry = stored("x" * 10000)
    calls = []
    encode = result_tools.structured_result_wire_chars

    def recording(*a, **kw):
        calls.append(1)
        return encode(*a, **kw)

    monkeypatch.setattr(result_tools, "structured_result_wire_chars", recording)
    result = result_tools._fit_read_result_chunk(entry, offset=0, candidate=entry.text[:4000], configured_budget=12000)
    assert result["chunk_chars"] == 4000
    assert len(calls) == 1


def test_read_default_uses_budget_and_reconstructs_unicode_text():
    server = runtime()
    text = '日本語 😀 "quoted" \\ line\n' * 3000
    _, entry = stored(text, store=server.result_store)
    chunks = []
    offset = 0
    while True:
        result = call(server, "read_result", result_id=entry.result_id, offset_chars=offset)
        assert len(result_tools._json_text(result, indent=2)) <= 12000
        chunks.append(result["chunk"])
        assert result["chunk_chars"] > 0
        if not result["has_more"]:
            break
        assert result["next_offset_chars"] > offset
        offset = result["next_offset_chars"]
    assert "".join(chunks) == text


def search(entry, **args):
    return result_tools._search_stored_result(
        entry,
        pattern=args.pop("pattern", "total"),
        context_chars=args.pop("context_chars", 200),
        max_matches=args.pop("max_matches", 20),
        configured_budget=args.pop("configured_budget", 12000),
        **args,
    )


def test_merged_contexts_preserve_every_match_and_original_context():
    _, entry = stored("".join(f"total += values[{i}]; // normal output\n" for i in range(2000)))
    original = search(entry, configured_budget=50_000)
    merged = search(entry, merge_context=True, configured_budget=50_000)
    assert original["match_count"] == merged["match_count"] == 2000
    assert original["matches_shown"] == merged["matches_shown"] == 20
    assert len(merged["contexts"]) == 1
    for a, b in zip(original["matches"], merged["matches"]):
        assert a["offset_chars"] == b["offset_chars"] and a["match"] == b["match"]
        context = merged["contexts"][b["context_index"]]
        start = a["context_offset_chars"] - context["offset_chars"]
        assert context["text"][start : start + len(a["context"])] == a["context"]
    assert len(result_tools._json_text(merged)) < len(result_tools._json_text(original)) * 0.6


@pytest.mark.parametrize(
    "pattern,text",
    [("a", "a" * 80), ("(?<=x)a", "xa" * 20), ("|a", "aa"), ("$", "abc"), (r"a\K", "aaa"), (r"a\K|", "aaa")],
)
def test_search_continuation_preserves_matches_including_zero_length(pattern, text):
    _, entry = stored(text)
    expected = [m.span() for m in regex.finditer(pattern, text)]
    cursor = None
    actual = []
    for _ in range(200):
        result = search(entry, pattern=pattern, max_matches=1, count_mode="none", cursor=cursor)
        actual += [(m["offset_chars"], m["end_offset"]) for m in result["matches"]]
        cursor = result["next_cursor"]
        if cursor is None:
            break
    else:
        pytest.fail("search did not terminate")
    assert actual == expected


def test_search_cursor_does_not_skip_candidates_dropped_by_budget():
    _, entry = stored(("a" + "x" * 1000) * 30)
    first = search(entry, pattern="a", max_matches=20, context_chars=2000, configured_budget=1024)
    assert 0 < first["matches_shown"] < 20
    second = search(entry, pattern="a", cursor=first["next_cursor"], context_chars=0)
    assert second["matches"][0]["offset_chars"] == first["matches_shown"] * 1001
    with pytest.raises(ValueError, match="cursor"):
        search(entry, pattern="x", cursor=first["next_cursor"])


def test_search_early_stop_and_logarithmic_response_fitting(monkeypatch):
    _, entry = stored(("x" * 2000 + "MATCH" + "y" * 2000 + "\n") * 110)
    count = 0
    encode = result_tools.structured_result_wire_chars

    def recording(*a, **kw):
        nonlocal count
        count += 1
        return encode(*a, **kw)

    monkeypatch.setattr(result_tools, "structured_result_wire_chars", recording)
    result = search(entry, pattern="MATCH", max_matches=100, context_chars=2000)
    assert result["match_count"] == 110
    assert count < 20
    early = search(entry, pattern="MATCH", max_matches=2, count_mode="none")
    assert early["match_count"] == 2 and not early["count_complete"]
    assert early["next_cursor"]


@pytest.mark.parametrize("path", ["", "/items"])
def test_json_index_projection_is_lazy_reused_and_preserves_unicode(monkeypatch, path):
    server = runtime()
    rows = [{"name": f"日本語😀{i}", "value": [i, {"text": '\\"[,]{}'}], "unused": "x" * 1000} for i in range(100)]
    text = json.dumps(rows if path == "" else {"program": "x", "items": rows, "has_more": False}, ensure_ascii=False)
    _, entry = stored(text, mime="application/json", store=server.result_store)
    count = 0
    build = result_json.build_array_index

    def indexed(*a, **kw):
        nonlocal count
        count += 1
        return build(*a, **kw)

    monkeypatch.setattr(result_json, "build_array_index", indexed)
    before = server.result_store.accounted_memory_bytes
    for offset in (0, 20):
        page_result = call(
            server,
            "read_result",
            result_id=entry.result_id,
            mode="json",
            path=path,
            offset_items=offset,
            fields=["name", "value"],
        )
        assert page_result["items"] == [
            {k: v for k, v in row.items() if k != "unused"} for row in rows[offset : offset + 20]
        ]
        assert page_result["next_offset_items"] == offset + 20
    assert count == 1 and server.result_store.accounted_memory_bytes > before
    assert server.result_store.read_text(entry.result_id) == text


def test_json_oversized_item_advances_past_itself_and_can_be_read_as_text():
    server = runtime()
    _, entry = stored(
        json.dumps([{"name": "big", "body": "x" * 20000}, {"name": "next"}]),
        mime="application/json",
        store=server.result_store,
    )
    result = call(server, "read_result", result_id=entry.result_id, mode="json")
    assert result["item_too_large"] and result["items"] == []
    # A client looping on next_offset_items must not be trapped on the oversized item.
    assert result["has_more"] is True and result["next_offset_items"] == 1
    start = result["offset_chars"]
    assert json.loads(entry.text[start : start + result["item_chars"]])["name"] == "big"
    following = call(server, "read_result", result_id=entry.result_id, mode="json", offset_items=1)
    assert following["items"] == [{"name": "next"}]
    assert following["has_more"] is False and following["next_offset_items"] is None
    projected = call(server, "read_result", result_id=entry.result_id, mode="json", fields=["name"])
    assert projected["items"] == [{"name": "big"}, {"name": "next"}]
    with pytest.raises(ToolError, match="character offsets"):
        call(server, "read_result", result_id=entry.result_id, mode="json", offset_chars=1)

    _, single = stored(
        json.dumps([{"name": "big", "body": "x" * 20000}]), mime="application/json", store=server.result_store
    )
    last = call(server, "read_result", result_id=single.result_id, mode="json")
    assert last["item_too_large"] and last["offset_chars"] == 1
    assert last["has_more"] is False and last["next_offset_items"] is None


def test_index_eviction_and_actual_string_memory_budget():
    store = ResultResourceStore(max_entries=1)
    _, first = stored("[1,2,3]", mime="application/json", store=store)
    store.json_index(first, "")
    assert store._indexes
    _, second = stored("other", store=store)
    assert store._indexes == {} and store.accounted_memory_bytes == second.memory_size_bytes
    small = ResultResourceStore(max_bytes=2000000, max_memory_bytes=2000000)
    assert (
        small.add(
            tool="t",
            target="t",
            text="a" * 1000000 + "😀",
            mime_type="text/plain",
            result_type="string",
            item_count=None,
        )
        is None
    )


def test_large_script_error_uses_resource_and_preserves_failure_state():
    details = {
        "transaction_outcome": "rolled_back",
        "execution_state": "invalid",
        "stdout": {"text": "normal output\n" * 4000},
        "stderr": {"text": "diagnostic\n" * 4000},
    }

    class Registry:
        def run_script(self, *args, **kwargs):
            raise DomainError(ErrorCode.SCRIPT_FAILED, "failed", details=details)

    server = create_mcp_server(
        specs={"run_script": get_tool_spec("run_script")},
        registry_provider=Registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    result = asyncio.run(server.mcp.call_tool("run_script", {"target": "t", "source": "# @runtime PyGhidra\npass"}))
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == "SCRIPT_FAILED"
    assert error["details"]["execution_state"] == "invalid"
    assert error["details"]["transaction_outcome"] == "rolled_back"
    assert result_compaction._call_tool_result_wire_chars(result) <= 12000
    stored_error = json.loads(server.result_store.read_text(result.structured_content["result_id"]))["error"]
    assert stored_error["details"] == details


@pytest.mark.parametrize("limit", [0, 4000])
def test_error_preview_preserves_critical_fields_even_with_no_preview(limit):
    error = {
        "code": "SCRIPT_FAILED",
        "retryable": False,
        "details": {
            **{f"detail{i}": "x" * 2000 for i in range(32)},
            "transaction_outcome": "rolled_back",
            "execution_state": "invalid",
        },
    }
    original = CallToolResult(
        is_error=True, content=[TextContent(type="text", text=json.dumps(error))], structured_content={"error": error}
    )
    result = present_tool_error(
        tool="run_script",
        target="t",
        error=error,
        original=original,
        config=ToolPresentationConfig(large_result_preview_chars=limit),
        store=ResultResourceStore(),
    )
    assert result.is_error
    assert result.structured_content["error"]["details"]["transaction_outcome"] == "rolled_back"
    assert result.structured_content["error"]["details"]["execution_state"] == "invalid"


def test_failed_error_cache_still_reports_error(monkeypatch):
    error = {"code": "SCRIPT_FAILED", "details": {"stdout": "x" * 20000, "execution_state": "invalid"}}
    original = CallToolResult(is_error=True, content=[TextContent(type="text", text=json.dumps(error))])
    store = ResultResourceStore(max_bytes=100)
    result = present_tool_error(
        tool="run_script", target="t", error=error, original=original, config=ToolPresentationConfig(), store=store
    )
    assert result.is_error and result.structured_content["result_unavailable"]
    monkeypatch.setattr(store, "add", lambda **kw: (_ for _ in ()).throw(RuntimeError("cache failure")))
    assert (
        present_tool_error(
            tool="run_script", target="t", error=error, original=original, config=ToolPresentationConfig(), store=store
        )
        is original
    )


def test_page_converts_only_returned_rows_and_checks_revision_after_conversion():
    context = ctx()
    converted = []
    cursor = None
    for _ in range(10):
        args = {"limit": 100, "cursor": cursor}
        result = page(context, "example", args, range(1000), convert=lambda row: converted.append(row) or row)
        cursor = result["next_cursor"]
    assert converted == list(range(1000)) and cursor is None

    def change(row):
        context.program.revision += 1
        return row

    with pytest.raises(HeadlessError, match="SESSION_CHANGED"):
        page(context, "example", {}, range(3), convert=change)


def test_seek_page_starts_at_next_unreturned_row():
    context = ctx()
    scanned = []

    def rows(start):
        for i in range(int(start) if start else 0, 1000):
            scanned.append(i)
            yield i

    cursor, result_rows = None, []
    for _ in range(10):
        result = page(context, "example", {"limit": 100, "cursor": cursor}, rows, seek_key=str)
        result_rows.extend(result["items"])
        cursor = result["next_cursor"]
    assert result_rows == list(range(1000)) and len(scanned) == 1009
    context.program.revision += 1
    first = page(ctx(), "example", {"limit": 100}, rows, seek_key=str)
    with pytest.raises(HeadlessError, match="SESSION_CHANGED"):
        page(context, "example", {"cursor": first["next_cursor"]}, rows, seek_key=str)


def test_nested_container_subclass_is_materialized_once_even_when_repairing():
    class Reordered(list):
        calls = 0

        def __iter__(self):
            self.calls += 1
            assert self.calls == 1
            return iter(["normal", "\ud800"])

    original = Reordered(["storage order", "differs"])
    normalized, changed = _normalize_json_surrogates({"items": original})
    assert changed and normalized == {"items": ["normal", "\ufffd"]}
    assert original.calls == 1


def test_explicit_short_descriptions_cover_all_tools_and_keep_key_selectors():
    from ghidra_mcp.contracts.tool_descriptions import SHORT_TOOL_DESCRIPTIONS
    from ghidra_mcp.contracts.tool_spec import get_all_tool_specs

    specs = get_all_tool_specs()
    assert set(SHORT_TOOL_DESCRIPTIONS) == set(specs)
    assert all(spec.short_description == SHORT_TOOL_DESCRIPTIONS[name] for name, spec in specs.items())
    for name, selector in [
        ("run_script", "transaction_outcome"),
        ("disassemble", "function OR"),
        ("bsim_query", "scope"),
    ]:
        assert selector in specs[name].short_description


def test_json_scalar_items_empty_arrays_and_index_budget():
    for rows in ([], ['quote" slash\\', "日本語😀", None, True, 3.5, [1, 2], {"a": "[,]"}]):
        text = json.dumps(rows, ensure_ascii=False)
        spans = result_json.build_array_index(text, "")
        assert [json.loads(text[a:b]) for a, b in zip(spans[::2], spans[1::2])] == rows
    with pytest.raises(ValueError, match="index exceeds"):
        result_json.build_array_index("[0,0,0,0,0]", "", max_bytes=1)


@pytest.mark.parametrize(
    "text",
    ["[1,]", "[1]]", "[1", "[,1]", "[1 2]", "[1,,2]", '{"items": [1,]}', '{"items": [1]]}', '{"items": [1] "z"}'],
)
def test_json_index_rejects_malformed_json(text):
    with pytest.raises(ValueError):
        result_json.build_array_index(text, "/items" if text.startswith("{") else "")


def test_json_index_spans_match_decoded_items_with_escaped_quotes_brackets_and_unicode():
    rows = [{"a": 'q"[,]{}\\ \u2028'}, ["\u65e5\u672c\U0001f600", {"n": [1, {"m": "]}"}]}], "\u0000\t", None, ""]
    for ensure_ascii in (True, False):
        for text, path in (
            (json.dumps(rows, ensure_ascii=ensure_ascii), ""),
            (json.dumps({"program": "[{", "items": rows, "has_more": False}, ensure_ascii=ensure_ascii), "/items"),
        ):
            if ensure_ascii:
                assert "\\ud83d\\ude00" in text and "\\u2028" in text
            spans = result_json.build_array_index(text, path)
            pieces = [text[a:b] for a, b in zip(spans[::2], spans[1::2])]
            assert pieces == [json.dumps(row, ensure_ascii=ensure_ascii) for row in rows]
            assert [json.loads(piece) for piece in pieces] == rows
    indented = json.dumps({"items": rows}, indent=2)
    spans = result_json.build_array_index(indented, "/items")
    assert [json.loads(indented[a:b]) for a, b in zip(spans[::2], spans[1::2])] == rows
    assert all(indented[a] not in " \n" and indented[b - 1] not in " \n," for a, b in zip(spans[::2], spans[1::2]))


def test_small_dictionary_does_not_add_a_custom_serializer_evaluation():
    class Stateful:
        calls = 0

        def __str__(self):
            self.calls += 1
            return f"value {self.calls}"

    value = Stateful()
    payload = {"value": value}
    result = result_compaction.maybe_compact_tool_result(
        tool_name="example", target="t", result=payload, config=ToolPresentationConfig(), store=ResultResourceStore()
    )
    assert result is payload and value.calls == 1
