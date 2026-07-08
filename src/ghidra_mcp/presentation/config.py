"""Presentation-layer knobs for MCP tool metadata and results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ToolDescriptionMode = Literal["short", "full", "none"]
LargeResultMode = Literal["resource", "inline"]


@dataclass(frozen=True, slots=True)
class ToolPresentationConfig:
    description_mode: ToolDescriptionMode = "full"
    large_result_mode: LargeResultMode = "resource"
    large_result_threshold_chars: int = 12000
    large_result_preview_chars: int = 4000
    result_cache_max_entries: int = 512
    result_cache_max_bytes: int = 134_217_728

    def __post_init__(self) -> None:
        if self.description_mode not in {"short", "full", "none"}:
            raise ValueError(f"Unsupported tool description mode: {self.description_mode!r}")
        if self.large_result_mode not in {"resource", "inline"}:
            raise ValueError(f"Unsupported large result mode: {self.large_result_mode!r}")
        if self.large_result_threshold_chars < 1:
            raise ValueError("large_result_threshold_chars must be >= 1")
        if self.large_result_preview_chars < 0:
            raise ValueError("large_result_preview_chars must be >= 0")
        if self.large_result_preview_chars > self.large_result_threshold_chars:
            # A preview larger than the threshold would let compaction emit a
            # "truncated" result bigger than the original payload.
            raise ValueError(
                "large_result_preview_chars must be <= large_result_threshold_chars"
            )
        if self.result_cache_max_entries < 1:
            raise ValueError("result_cache_max_entries must be >= 1")
        if self.result_cache_max_bytes < 1:
            raise ValueError("result_cache_max_bytes must be >= 1")


__all__ = ["LargeResultMode", "ToolDescriptionMode", "ToolPresentationConfig"]
