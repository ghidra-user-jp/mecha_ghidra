"""Real service/runtime/locks with a replaceable, benign Ghidra handle."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.cli_runtime import create_cli_runtime
from ghidra_mcp.presentation.config import ToolPresentationConfig


class FakeMonitor:
    """Stands in for the cancellable Ghidra TaskMonitor the runtime creates."""

    def __init__(self) -> None:
        self.cancelled = threading.Event()

    def cancel(self) -> None:
        self.cancelled.set()

    def isCancelled(self) -> bool:  # noqa: N802 - Ghidra TaskMonitor API
        return self.cancelled.is_set()


def make_bundle(root: Path, import_body, *, path_policy=None):
    for name in ("sample.bin", "a.bin", "b.bin", "benign.bin"):
        (root / name).write_bytes(b"\xc3")
    files = {}
    key = (str(root), "test")
    closes = []
    monitors = []

    def create_cancellable_monitor():
        monitor = FakeMonitor()
        monitors.append(monitor)
        return monitor

    handle = SimpleNamespace(
        project=SimpleNamespace(getProjectData=lambda: SimpleNamespace(getFile=files.get)),
        get_key=lambda: key,
        is_closed=lambda: False,
        import_program=import_body,
        create_cancellable_monitor=create_cancellable_monitor,
        monitors=monitors,
        close=lambda **_: closes.append("closed"),
    )
    runtime_kwargs = {"path_policy": path_policy} if path_policy is not None else {}
    bundle = create_cli_runtime(
        registered_specs={name: get_tool_spec(name) for name in ("import_program", "get_operation", "list_targets")},
        core_accessor=lambda: SimpleNamespace(clear_contexts=lambda: None),
        checkout_required_commands=set(),
        presentation_config=ToolPresentationConfig(large_result_threshold_chars=10, large_result_preview_chars=5),
        **runtime_kwargs,
    )
    store = bundle.runtime_backend._store
    store.target_projects["default"] = key
    store.project_handles[key] = handle
    store.locks["default"] = threading.RLock()
    return bundle, files, closes
