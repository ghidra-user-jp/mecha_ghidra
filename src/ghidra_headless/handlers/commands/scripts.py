"""In-process Ghidra script execution (``run_script`` core command).

The application layer (``ScriptService``) resolves the catalog entry and builds
the request; this command runs it against the loaded
program inside an outer transaction and quarantines the target when the run
leaves the program in an unverifiable state.
"""

from __future__ import absolute_import, print_function

import logging

from ghidra_headless.errors import HeadlessError

from .query_support import program_revision

logger = logging.getLogger(__name__)


def _require_str(params, name):
    value = params.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s is required" % name)
    return value


def run_script(params, *, ensure_context, current_key):
    """Run a catalog script in this JVM and return the execution summary."""

    import os

    from ghidra_headless.scripts import providers
    from ghidra_headless.scripts.execution import run_script_with_transaction

    ctx = ensure_context()
    if ctx.execution_invalid:
        raise HeadlessError(
            "TARGET_EXECUTION_INVALID: the target is quarantined after an earlier script run; "
            "close_session(discard_changes=true) then reload the program",
            details=dict(ctx.execution_invalid),
        )
    script_path = _require_str(params, "script_path")
    runtime = _require_str(params, "runtime")
    script_id = params.get("script_id") or script_path
    previous_revision = program_revision(ctx)
    expected = params.get("expected_revision")
    if expected is not None and expected != previous_revision:
        raise HeadlessError("SESSION_CHANGED: program changed; read current state before running the script")
    request = {
        "script_id": script_id,
        "script_path": script_path,
        "runtime": runtime,
        "args": [str(item) for item in (params.get("args") or [])],
        "timeout_seconds": int(params.get("timeout_seconds") or 300),
        "output_limit_bytes": int(params.get("output_limit_bytes") or 65536),
        "snapshot_roots": [str(item) for item in (params.get("snapshot_roots") or [])],
    }
    reset_decompiler = True
    try:
        summary = run_script_with_transaction(
            program=ctx.program,
            project=ctx.project,
            description="Script: %s" % script_id,
            request=request,
        )
        revision_after = program_revision(ctx)
        reset_decompiler = not (
            summary.get("status") == "ok"
            and summary.get("transaction_outcome") == "unchanged"
            and summary.get("execution_state") == "valid"
            and not ctx.execution_invalid
            and revision_after == previous_revision
        )
    except HeadlessError as exc:
        details = exc.details or {}
        if details.get("execution_state") == "invalid":
            ctx.mark_execution_invalid(
                "script_run",
                {
                    "script_id": script_id,
                    "transaction_outcome": details.get("transaction_outcome"),
                    "open_sub_transactions": details.get("open_sub_transactions"),
                    "stray_threads": details.get("stray_threads"),
                },
            )
        raise
    finally:
        # Runs on every exit, including raw Java/Python exceptions from the
        # pre-checks or startTransaction that are not HeadlessError: the inline
        # bundle must not outlive its staging directory (ScriptService deletes
        # it next), and the sentinel/decompiler state must not go stale.
        _finish_run(ctx, params, current_key, providers, os, reset_decompiler=reset_decompiler)
    summary["revision"] = revision_after
    summary["revision_before"] = previous_revision
    return summary


__all__ = ["run_script"]


def _finish_run(ctx, params, current_key, providers, os, *, reset_decompiler) -> None:
    """Post-run housekeeping for every outcome.  Never raises: a failure here must not mask the run's result."""

    # Preserve the shared interface only after an unchanged, valid success.
    # Arbitrary edits (even rolled back ones) still invalidate cached state.
    if reset_decompiler:
        try:
            ctx.reset_decompiler()
        except Exception as exc:
            logger.debug("decompiler reset after script run failed: %s", exc)
    # A failed script may still have scheduled work; watch for its transactions too.
    try:
        ctx.arm_transaction_sentinel(current_key())
    except Exception as exc:
        logger.debug("transaction sentinel could not be armed after script run: %s", exc)
    _forget_inline_bundle(params, providers, os)


def _forget_inline_bundle(params, providers, os) -> None:
    """Inline sources live in a one-shot directory: drop its bundle so runs do not accumulate."""

    if not params.get("inline"):
        return
    try:
        providers.unregister_source_root(os.path.dirname(str(params["script_path"])))
    except Exception as exc:
        logger.debug("inline source bundle could not be unregistered: %s", exc)
