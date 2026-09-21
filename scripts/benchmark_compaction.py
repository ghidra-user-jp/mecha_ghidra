#!/usr/bin/env python3
"""Reproducible synthetic SDK response/work benchmarks; no JVM, model or network.

Run with --output FILE, optionally --baseline-ref COMMIT. The baseline executes
only selected presentation/query files from that ref in an isolated source copy,
retaining the working tree's tool contracts (including newly added script tools).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BASELINE_FILES = (
    "presentation/config.py",
    "presentation/mcp_server.py",
    "presentation/tool_registry.py",
    "presentation/result_store.py",
    "presentation/result_compaction.py",
    "presentation/result_tools.py",
    "presentation/result_resources.py",
)


def measure():
    from mcp.server.mcpserver.utilities.func_metadata import ArgModelBase, FuncMetadata

    from ghidra_headless.handlers.commands.query_support import page
    from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_tool_spec
    from ghidra_mcp.domain import DomainError, ErrorCode
    from ghidra_mcp.presentation import result_compaction as comp
    from ghidra_mcp.presentation import result_tools as retrieval
    from ghidra_mcp.presentation.config import ToolPresentationConfig
    from ghidra_mcp.presentation.mcp_server import create_mcp_server
    from ghidra_mcp.presentation.result_store import ResultResourceStore
    from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool

    serializer = FuncMetadata(arg_model=ArgModelBase)
    config = ToolPresentationConfig()

    def wire(value):
        result = serializer.convert_result(value)
        return result.model_dump_json(by_alias=True, exclude_none=True)

    def compact(value, store=None):
        return comp.maybe_compact_tool_result(
            tool_name="example", target="fw", result=value, config=config, store=store or ResultResourceStore()
        )

    def median_ms(fn):
        fn()
        samples = []
        for _ in range(9):
            start = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - start) * 1000)
        return round(statistics.median(samples), 3)

    def peak_mib(fn):
        tracemalloc.start()
        fn()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return round(peak / 1024**2, 3)

    line = "  total += values[index]; /* ordinary analysis output */\n"
    text = (line * 2000)[:100000]
    rows = [
        {
            "name": f"function_{i:06d}",
            "entry": f"0x{0x401000 + i * 16:x}",
            "signature": "int function(int value)",
            "size": 64,
        }
        for i in range(20000)
    ]
    context = SimpleNamespace(
        generation="review",
        program=SimpleNamespace(
            getModificationNumber=lambda: 1, getDomainFile=lambda: SimpleNamespace(getPathname=lambda: "/sample")
        ),
    )
    payloads = {
        "text_100k": text,
        "paged_1000": page(context, "example", {"limit": 1000}, iter(rows)),
        "paged_10000": page(context, "example", {"limit": 10000}, iter(rows)),
        "flat_20000": rows,
    }
    result = {
        "scope": "Synthetic SDK CallToolResult JSON characters, not tokens. No JVM/LLM/network timing.",
        "source": comp.__file__,
        "payloads": {},
    }
    for name, payload in payloads.items():
        first = compact(payload)
        result["payloads"][name] = {
            "inline_json_chars": len(wire(payload)),
            "first_response_json_chars": len(wire(first)),
            "compaction_and_sdk_ms": median_ms(lambda payload=payload: wire(compact(payload))),
            "extra_peak_mib": peak_mib(lambda payload=payload: wire(compact(payload))),
        }
        if name.startswith("paged"):
            preview = first.content[0].text.split("----- preview -----\n")[-1]
            result["payloads"][name]["preview_item_count"] = len(json.loads(preview).get("items", []))

    runtime = create_mcp_server(specs={}, registry_provider=lambda: None, dispatcher_provider=lambda: dispatch_tool)
    first = compact(text, store=runtime.result_store)
    entry = runtime.result_store.get(first.structured_content["result_id"])
    offset = first.structured_content.get("continue_offset_chars")
    if offset is None:
        offset = int(re.search(r"offset_chars=(\d+)", first.content[0].text).group(1))

    async def read_all():
        nonlocal offset
        calls, response_chars = 0, len(wire(first))
        while offset < len(text):
            response = await runtime.mcp.call_tool(
                "read_result", {"result_id": entry.result_id, "offset_chars": offset}
            )
            data = json.loads(response.content[0].text)
            response_chars += len(wire(response))
            calls += 1
            assert data["chunk"] == text[offset : offset + data["chunk_chars"]]
            offset += data["chunk_chars"]
            assert data["chunk_chars"] > 0
        return {"additional_calls": calls, "response_json_chars": response_chars}

    result["read_all_default"] = asyncio.run(read_all())
    with patch.object(retrieval, "_json_text", wraps=retrieval._json_text) as encoded:
        retrieval._fit_read_result_chunk(entry, offset=0, candidate=text[:4000], configured_budget=12000)
        result["read_4000_encoding_calls"] = encoded.call_count

    searchtext = "".join(f"total += values[{i}]; // ordinary analysis output\n" for i in range(2000))
    searchentry = runtime.result_store.add(
        tool="example", target="fw", text=searchtext, mime_type="text/plain", result_type="string", item_count=None
    )
    args = dict(pattern="total", context_chars=200, max_matches=20, configured_budget=12000)
    plain = retrieval._search_stored_result(searchentry, **args)
    result["search_20"] = {"plain_json_chars": len(wire(plain)), "matches": plain["matches_shown"]}
    if "merge_context" in inspect.signature(retrieval._search_stored_result).parameters:
        merged = retrieval._search_stored_result(searchentry, **args, merge_context=True)
        result["search_20"]["merged_json_chars"] = len(wire(merged))
        result["search_20"]["merged_matches"] = merged["matches_shown"]

    dense = ("x" * 2000 + "MATCH" + "y" * 2000 + "\n") * 110
    denseentry = runtime.result_store.add(
        tool="example", target="fw", text=dense, mime_type="text/plain", result_type="string", item_count=None
    )

    def dense_search():
        return retrieval._search_stored_result(
            denseentry, pattern="MATCH", context_chars=2000, max_matches=100, configured_budget=12000
        )

    with patch.object(retrieval, "_json_text", wraps=retrieval._json_text) as encoded:
        dense_search()
        result["search_100_encoding_calls"] = encoded.call_count
    result["search_100_ms"] = median_ms(dense_search)

    converted = 0

    def convert(row):
        nonlocal converted
        converted += 1
        return {"index": row}

    supports_convert = "convert" in inspect.signature(page).parameters
    cursor = None
    for _ in range(10):
        source = range(1000) if supports_convert else (convert(i) for i in range(1000))
        options = {"convert": convert} if supports_convert else {}
        response = page(context, "example", {"limit": 100, "cursor": cursor}, source, **options)
        cursor = response["next_cursor"]
    result["page_1000_row_conversions"] = converted

    class ErrorRegistry:
        def run_script(self, target, **kwargs):
            raise DomainError(
                ErrorCode.SCRIPT_FAILED,
                "diagnostic example",
                details={
                    "transaction_outcome": "rolled_back",
                    "execution_state": "valid",
                    "stdout": {"text": line * 1000},
                    "stderr": {"text": line * 1000},
                    "diagnostics": {"text": line * 1000},
                },
            )

    async def protocol():
        server = create_mcp_server(
            specs={"run_script": get_tool_spec("run_script")},
            registry_provider=ErrorRegistry,
            dispatcher_provider=lambda: dispatch_tool,
        )
        response = await server.mcp.call_tool("run_script", {"target": "fw", "source": "# @runtime PyGhidra\npass"})
        result["script_error"] = {
            "json_chars": len(wire(response)),
            "is_error": response.is_error,
            "stored": bool(response.structured_content.get("result_id")),
        }
        result["tool_definitions"] = []
        for mode in ("full", "short"):
            server = create_mcp_server(
                specs=filter_tool_specs(profile=ToolProfile.DEFAULT),
                registry_provider=lambda: None,
                dispatcher_provider=lambda: dispatch_tool,
                presentation_config=ToolPresentationConfig(description_mode=mode),
            )
            tool_list = await server.mcp.list_tools()
            count = len(
                json.dumps(
                    [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tool_list],
                    separators=(",", ":"),
                )
            )
            result["tool_definitions"].append({"mode": mode, "count": len(tool_list), "json_chars": count})

    asyncio.run(protocol())
    result["source_sha256"] = hashlib.sha256(Path(comp.__file__).read_bytes()).hexdigest()
    result["source_hashes"] = {
        name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        for name, module in tuple(sys.modules.items())
        if (
            name.startswith("ghidra_mcp.presentation.result_")
            or name
            in {
                "ghidra_mcp.presentation.mcp_server",
                "ghidra_mcp.presentation.tool_registry",
                "ghidra_mcp.presentation.config",
                "ghidra_mcp.contracts.tool_spec",
                "ghidra_headless.handlers.commands.query_support",
            }
        )
        and getattr(module, "__file__", None)
    }
    result["environment"] = {
        "python": sys.version,
        "platform": sys.platform,
        "packages": {name: importlib.metadata.version(name) for name in ("mcp", "pydantic", "pydantic-core", "regex")},
        "timing_repeats": 9,
        "timing_statistic": "median",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.baseline_ref:
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("git is required for a baseline comparison")
        commit = subprocess.check_output(  # noqa: S603 - fixed git executable, argv, no shell
            [git, "rev-parse", "--verify", "--end-of-options", args.baseline_ref + "^{commit}"], cwd=root, text=True
        ).strip()
        with tempfile.TemporaryDirectory(prefix="mecha-compaction-baseline-") as temp:
            source = Path(temp) / "src"
            shutil.copytree(root / "src", source, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            paths = ["src/ghidra_mcp/" + name for name in BASELINE_FILES]
            paths += ["src/ghidra_headless/handlers/commands/query_support.py"]
            for path in paths:
                data = subprocess.check_output([git, "show", f"{commit}:{path}"], cwd=root)  # noqa: S603 - verified commit and fixed paths
                (Path(temp) / path).write_bytes(data)
            # Preserve pre-existing script contracts but remove this change's explicit summaries.
            spec_path = source / "ghidra_mcp/contracts/tool_spec.py"
            spec_path.write_text(
                spec_path.read_text().replace(
                    "short_description or SHORT_TOOL_DESCRIPTIONS.get(name)", "short_description"
                )
            )
            subprocess.run(  # noqa: S603 - this interpreter and this benchmark script, no shell
                [sys.executable, str(Path(__file__).resolve()), "--output", str(args.output.resolve())],
                env={**os.environ, "PYTHONPATH": str(source), "COMPACTION_BASELINE_COMMIT": commit},
                check=True,
            )
        return
    data = measure()
    data["baseline_commit"] = os.environ.get("COMPACTION_BASELINE_COMMIT")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
