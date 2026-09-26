"""Ghidra auto-analysis in one transaction, for the analysis command and for an import's post-processing."""

from __future__ import annotations

from typing import Any, Callable

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import java_bindings


def run_auto_analysis(
    program,
    flat_api,
    *,
    monitor=None,
    transaction: Callable[[str, Callable[[], Any]], Any],
    cancelled_error: str,
) -> None:
    """Analyze ``program`` and mark it analyzed, both inside ``transaction(description, operation)``.

    A cancelled analysis can return normally.  It must never be marked (or
    saved) as analyzed, so it raises ``cancelled_error`` inside the
    transaction, which rolls the analysis back.
    """
    utilities = java_bindings._ghidra_program_utilities()
    script_util = java_bindings._ghidra_script_util()
    script_util.acquireBundleHostReference()
    try:

        def _analyze():
            flat_api.analyzeAll(program)
            if monitor is not None and bool(monitor.isCancelled()):
                raise HeadlessError(cancelled_error)
            utilities.markProgramAnalyzed(program)
            return True

        transaction("Auto analysis", _analyze)
    finally:
        script_util.releaseBundleHostReference()


__all__ = ["run_auto_analysis"]
