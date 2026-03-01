"""Application-layer runtime state container (no Ghidra dependencies)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

import fasteners


@dataclass(slots=True)
class RuntimeState:
    core_accessor: Callable[[], Any]
    checkout_required_commands: set[str]
    normalize_result: Callable[[Any], Any]
    sessions: dict[str, Any] = field(default_factory=dict)
    locks: dict[str, threading.RLock] = field(default_factory=dict)
    target_projects: dict[str, tuple[str, str]] = field(default_factory=dict)
    project_handles: dict[tuple[str, str], Any] = field(default_factory=dict)
    registry_lock: fasteners.ReaderWriterLock = field(default_factory=fasteners.ReaderWriterLock)


__all__ = ["RuntimeState"]
