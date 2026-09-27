"""Serve MCP while Ghidra starts: the background startup and the gate ``tools/call`` waits on.

``initialize``, ``tools/list`` and the resources are built from the tool specs
and need no JVM, so the transport starts first.  ``BackgroundStartup`` then
brings up the JVM, Ghidra and the startup sessions on its own thread, and only
``tools/call`` waits for it, on ``StartupGate``.  Configuration errors that can
be found without the JVM are still reported before serving (see ``cli``).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from mcp.types import CallToolResult

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_utils import safe_cause_details, sanitize_cause_message

from .tool_registry import domain_error_result
from .waiting import POLL_SECONDS, wait_until

logger = logging.getLogger(__name__)

STARTING = "starting"
READY = "ready"
FAILED = "failed"
STARTUP_THREAD_NAME = "ghidra-startup"


@dataclass(frozen=True, slots=True)
class StartupFailure:
    """Why the startup stopped: the step, and the line the server logged for it."""

    stage: str
    message: str
    cause_type: str
    cause_message: str


class StartupGate:
    """Whether tool calls may run: ``starting`` until the startup ends ``ready`` or ``failed``."""

    def __init__(
        self,
        *,
        report_stage: bool = False,
        details_provider: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        """``report_stage`` adds the step in progress to the still-starting error, and
        ``details_provider`` more details, such as the dialogs the GUI waits on (GUI backend)."""
        self._lock = threading.Lock()
        self._state = STARTING
        self._failure: StartupFailure | None = None
        self._stage: str | None = None
        self._report_stage = report_stage
        self._details_provider = details_provider

    @property
    def state(self) -> str:
        return self._state

    @property
    def failure(self) -> StartupFailure | None:
        return self._failure

    @property
    def stage(self) -> str | None:
        """The startup step in progress (None before the first)."""
        return self._stage

    def set_stage(self, stage: str) -> None:
        self._stage = stage

    def mark_ready(self) -> None:
        with self._lock:
            if self._state == STARTING:
                self._state = READY

    def mark_failed(self, failure: StartupFailure) -> None:
        with self._lock:
            if self._state == STARTING:
                self._failure = failure
                self._state = FAILED

    async def wait(self, timeout: float) -> float:
        """Wait on the event loop, holding no thread, until the startup ends; return the seconds waited.

        Raises a retryable ``LOCK_TIMEOUT`` while Ghidra is still starting after
        ``timeout`` seconds, and ``STARTUP_FAILED`` once the startup failed.
        A call that did not have to wait gets exactly 0.
        """
        waited = 0.0
        if self._state == STARTING:
            started = time.monotonic()
            await wait_until(lambda: self._state != STARTING, timeout)
            waited = time.monotonic() - started
        if self._state == FAILED:
            raise startup_failed_error(self._failure)
        if self._state == STARTING:
            raise self._still_starting(timeout)
        return waited

    def _still_starting(self, timeout: float) -> DomainError:
        details: dict[str, object] = {"lock": "startup", "timeout": timeout}
        hint = "The server starts Ghidra in the background after it begins serving; retry in a few seconds"
        if self._report_stage and self._stage is not None:
            details["stage"] = self._stage
        if self._details_provider is not None:
            try:
                details.update(self._details_provider())
            except Exception:
                logger.debug("startup details unavailable", exc_info=True)
        dialogs = details.get("modal_dialogs")
        if dialogs:
            hint = (
                "The Ghidra GUI shows a dialog that waits for the human ("
                + ", ".join(str(title) for title in dialogs)  # type: ignore[union-attr]
                + "); retry once it is answered"
            )
        return DomainError(
            code=ErrorCode.LOCK_TIMEOUT, message="Ghidra is still starting", hint=hint, retryable=True, details=details
        )


def startup_failed_error(failure: StartupFailure) -> DomainError:
    return DomainError(
        code=ErrorCode.STARTUP_FAILED,
        message=failure.message,
        hint="The server log has the same message; every tool call returns this error until the server restarts",
        details={"stage": failure.stage, "cause_type": failure.cause_type, "cause_message": failure.cause_message},
    )


def startup_error_result(error: DomainError) -> CallToolResult:
    """The tool result for a call the gate turned away, in the usual domain-error envelope."""
    # The generic LOCK_TIMEOUT wording names a lock; this wait is for Ghidra itself.
    return domain_error_result(
        error, message=f"LOCK_TIMEOUT: {error.message}" if error.code is ErrorCode.LOCK_TIMEOUT else None
    )


@dataclass(frozen=True, slots=True)
class StartupStep:
    """One step of the startup; ``failure`` begins the line logged when it raises.

    A ``main_thread`` step runs on the event loop's thread while the startup
    thread waits for it (without a loop, on the startup thread).
    """

    name: str
    run: Callable[[], None]
    failure: str
    main_thread: bool = False


class _Stopped(Exception):
    """The transport ended before the startup finished."""


def _failure_of(step: StartupStep, exc: BaseException) -> StartupFailure:
    # The message is the line the server logs.  Every tool call returns the
    # cause, so it gets the treatment of any public cause: no host paths, capped.
    if isinstance(exc, DomainError):
        cause = {"cause_type": exc.code.value, "cause_message": sanitize_cause_message(exc.message)}
    else:
        cause = safe_cause_details(exc)
    return StartupFailure(stage=step.name, message=f"{step.failure}: {exc}", **cause)


class BackgroundStartup:
    """Run the startup steps on their own thread and publish the outcome to ``gate``.

    The steps stop at the next boundary once ``stop`` is called.  After a
    failed step, ``on_failure`` runs on the startup thread to release what the
    earlier steps opened, before the gate reports the failure.
    ``on_thread_exit`` runs last on the startup thread, whatever happened: the
    CLI detaches the thread from the JVM it may have started there.  A failed
    startup ends the transport unless ``keep_serving_on_failure`` says
    otherwise: the Ghidra GUI stays up for the human once GhidraRun started,
    and every call then reports why the server cannot run tools.
    """

    def __init__(
        self,
        steps: Sequence[StartupStep],
        gate: StartupGate,
        *,
        on_failure: Callable[[], None] | None = None,
        on_thread_exit: Callable[[], None] | None = None,
        keep_serving_on_failure: Callable[[], bool] | None = None,
    ) -> None:
        self.gate = gate
        self._steps = tuple(steps)
        self._on_failure = on_failure
        self._on_thread_exit = on_thread_exit
        self._keep_serving_on_failure = keep_serving_on_failure
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_serving: Callable[[], None] | None = None

    def start(
        self,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        stop_serving: Callable[[], None] | None = None,
    ) -> None:
        """Start the steps; ``loop`` runs the main-thread steps, ``stop_serving`` ends the transport on failure."""
        if self._thread is not None:
            raise RuntimeError("the startup has already started")
        self._loop = loop
        self._stop_serving = stop_serving
        # Daemon, so a step that never returns cannot hold interpreter exit;
        # stop() still waits for the step in progress on every normal path.
        self._thread = threading.Thread(target=self._run, name=STARTUP_THREAD_NAME, daemon=True)
        self._thread.start()

    def join(self, timeout: float | None = None) -> bool:
        """Wait for the startup thread without stopping it; True once it has ended or never started."""
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def stop(self) -> None:
        """Stop at the next step boundary, then wait for the step in progress.

        Starting the JVM and opening a program cannot be interrupted, so the
        caller's cleanup must not race with them.
        """
        self._stop.set()
        thread = self._thread
        if thread is None or thread is threading.current_thread() or not thread.is_alive():
            return
        logger.info("Waiting for the Ghidra startup step in progress before shutting down")
        thread.join()

    def _run(self) -> None:
        began = time.monotonic()
        timings: list[tuple[str, float]] = []
        failure: StartupFailure | None = None
        stopped = False
        try:
            try:
                for step in self._steps:
                    if self._stop.is_set():
                        raise _Stopped
                    step_began = time.monotonic()
                    self.gate.set_stage(step.name)
                    try:
                        if step.main_thread:
                            self._run_on_loop(step.run)
                        else:
                            step.run()
                    except _Stopped:
                        raise
                    except BaseException as exc:
                        failure = _failure_of(step, exc)
                        break
                    timings.append((step.name, time.monotonic() - step_began))
            except _Stopped:
                stopped = True
            if failure is not None:
                logger.error("%s", failure.message)
                if self._on_failure is not None:
                    try:
                        self._on_failure()
                    except Exception:
                        logger.exception("Could not release Ghidra resources after the failed startup")
        finally:
            if self._on_thread_exit is not None:
                try:
                    self._on_thread_exit()
                except Exception:
                    logger.exception("Startup thread cleanup failed")
        if stopped:
            logger.info("Ghidra startup stopped: the transport ended first")
        elif failure is not None:
            self.gate.mark_failed(failure)
            keep_serving = self._keep_serving_on_failure is not None and self._keep_serving_on_failure()
            if self._stop_serving is not None and not keep_serving:
                self._stop_serving()
        else:
            self.gate.mark_ready()
            slow = ", ".join(f"{name} {seconds:.1f} s" for name, seconds in timings if seconds >= 0.05)
            logger.info("Ghidra ready in %.1f s%s", time.monotonic() - began, f" ({slow})" if slow else "")

    def _run_on_loop(self, function: Callable[[], None]) -> None:
        loop = self._loop
        if loop is None:
            function()
            return
        done = threading.Event()
        errors: list[BaseException] = []

        def call() -> None:
            try:
                function()
            except BaseException as exc:
                errors.append(exc)
            finally:
                done.set()

        try:
            loop.call_soon_threadsafe(call)
        except RuntimeError as exc:  # closed: the transport has ended
            raise _Stopped from exc
        while not done.wait(POLL_SECONDS):
            if loop.is_closed() or not loop.is_running():
                raise _Stopped
        if errors:
            raise errors[0]


__all__ = [
    "FAILED",
    "READY",
    "STARTING",
    "STARTUP_THREAD_NAME",
    "BackgroundStartup",
    "StartupFailure",
    "StartupGate",
    "StartupStep",
    "startup_error_result",
    "startup_failed_error",
]
