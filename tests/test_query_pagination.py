"""Pagination must reject mixed revisions and continue beyond the old offset cap."""

import base64
import json
from types import SimpleNamespace

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.commands.query_support import page


def context():
    program = SimpleNamespace(revision=0)
    program.getModificationNumber = lambda: program.revision
    program.getDomainFile = lambda: SimpleNamespace(getPathname=lambda: "/sample")
    return SimpleNamespace(generation="test", program=program)


def test_page_rejects_a_change_during_enumeration():
    ctx = context()

    def rows():
        yield 1
        ctx.program.revision += 1
        yield 2

    with pytest.raises(HeadlessError, match="SESSION_CHANGED"):
        page(ctx, "query", {"limit": 1}, rows())


def test_page_continues_above_one_million_items():
    ctx = context()
    first = page(ctx, "query", {"limit": 2}, range(1_000_005))
    values = json.loads(base64.urlsafe_b64decode(first["next_cursor"]))
    values[2] = 1_000_001
    cursor = base64.urlsafe_b64encode(json.dumps(values).encode()).decode()
    middle = page(ctx, "query", {"limit": 2, "cursor": cursor}, range(1_000_005))
    assert middle["items"] == [1_000_001, 1_000_002]
    last = page(ctx, "query", {"limit": 2, "cursor": middle["next_cursor"]}, range(1_000_005))
    assert last["items"] == [1_000_003, 1_000_004]
    assert not last["has_more"] and last["next_cursor"] is None


def test_cursor_is_bound_to_query_and_tool_but_allows_page_size_change():
    ctx = context()
    first = page(ctx, "query", {"limit": 1, "address": "1000"}, range(5))
    args = {"limit": 2, "address": "1000", "cursor": first["next_cursor"]}
    assert page(ctx, "query", args, range(5))["items"] == [1, 2]
    for tool, params in [("other", args), ("query", {**args, "address": "2000"})]:
        with pytest.raises(ValueError, match="different query"):
            page(ctx, tool, params, range(5))
