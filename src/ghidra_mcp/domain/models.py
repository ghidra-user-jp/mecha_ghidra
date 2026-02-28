"""Domain model objects used by application/services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TargetRef:
    name: str


@dataclass(frozen=True, slots=True)
class ProgramRef:
    target: str
    domain_path: str


@dataclass(frozen=True, slots=True)
class LockKey:
    target: str
    project: str | None = None


__all__ = ["LockKey", "ProgramRef", "TargetRef"]
