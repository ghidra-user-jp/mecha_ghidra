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
    project_locks: dict[tuple[str, str], threading.RLock] = field(default_factory=dict)
    target_projects: dict[str, tuple[str, str]] = field(default_factory=dict)
    project_handles: dict[tuple[str, str], Any] = field(default_factory=dict)
    analyzed_loads: set[tuple[str, str]] = field(default_factory=set)
    dirty_programs: set[tuple[str, str]] = field(default_factory=set)
    # Saved changes whose shared DomainFile status has not caught up yet.
    pending_sync_programs: set[tuple[str, str]] = field(default_factory=set)
    # target name -> quarantine payload set by a failed script run/transfer.
    invalid_targets: dict[str, dict[str, Any]] = field(default_factory=dict)
    # target name -> sessions whose program consumer could not be released yet.
    orphaned_sessions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # target name -> project handles that still own programs from failed opens.
    orphan_handles: dict[str, list[Any]] = field(default_factory=dict)
    operation_lock: fasteners.ReaderWriterLock = field(default_factory=fasteners.ReaderWriterLock)
    registry_lock: fasteners.ReaderWriterLock = field(default_factory=fasteners.ReaderWriterLock)


__all__ = ["RuntimeState"]
