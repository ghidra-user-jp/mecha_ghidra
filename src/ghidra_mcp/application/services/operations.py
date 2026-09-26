"""Process-local background jobs and deferred tool calls.

One worker thread runs the queued jobs (imports, analyses and scripts) in
submission order. A tool call that outlives its reply keeps running on its own
thread and records its outcome here as well, and so does a call sent with a
request_id, whose resends get its reply (claim_call). Records live in memory only:
losing the process loses the records, not necessarily the Ghidra data. The
manager lock never encloses runtime or Ghidra calls.
"""

from __future__ import annotations

import collections
import contextlib
import contextvars
import copy
import hashlib
import json
import logging
import queue
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ghidra_mcp.application.locks import CallLocks
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.domain import DomainError, ErrorCode, get_lock_timeout_seconds
from ghidra_mcp.domain.error_mapping import to_domain_error
from ghidra_mcp.domain.identifiers import canonical_uuid
from ghidra_mcp.domain.output_state import (
    ABSENT,
    CREATED,
    UNCERTAIN,
    output_state_for_outcome,
    retryable_after,
)

logger = logging.getLogger(__name__)

IMPORT = "import_program"
ANALYSIS = "analyze_program"
SCRIPT = "run_script"
PENDING_STATES = frozenset({"queued", "running"})

_ARGUMENT_LIMIT_BYTES = 16_384
# Room for a 256 KiB inline source and 64 KiB of args once JSON escapes them;
# ScriptService enforces the exact limits with precise messages.
_SCRIPT_ARGUMENT_LIMIT_BYTES = 1024 * 1024
_QUEUE_LIMIT = 16
# Finished jobs whose program was released are evicted oldest first beyond
# this count; a job that still holds a reservation is never evicted.
_HISTORY_LIMIT = 4096
# Results and errors the records keep, in total. Oversized ones normally move
# to the result store first; this bounds the inline large-result mode.
_PAYLOAD_LIMIT_BYTES = 128 * 1024 * 1024
_POLL_AFTER_MS = 1000
_IDLE_EXIT_SECONDS = 2.0
_LOCK_RETRY_SECONDS = 0.5
_DETAILS_LIMIT_BYTES = 4096
# Cleanup evidence kept even when other diagnostics must be truncated.
_CLEANUP_KEYS = frozenset(
    {
        "partial_import",
        "rollback_deleted",
        "cleanup_error",
        "imported_domain_path",
        "output_created",
        "existing_domain_path",
        "transaction_outcome",
        "execution_state",
        "output_state",
        "cancelled",
    }
)
_NOT_STARTED = "Server is shutting down; the job was not started"
_CANCELLED_BEFORE_START = "cancel_operation stopped the job before it started"
# Set by replay_only.
_REPLAY_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar("replay_only", default=False)

# What a job returns and what a failed job reports, after the presentation
# layer moved oversized values to the result store.
Presenter = Callable[
    [str, str, Any, "dict[str, Any] | None"],
    "tuple[Any, dict[str, Any] | None]",
]


class ReplayMissed(BaseException):
    """A request submitted under ``replay_only`` whose request_id names no record now; nothing was admitted.

    A BaseException, so the tool layers between the caller and the manager
    pass it through unchanged.
    """


@contextlib.contextmanager
def replay_only() -> Iterator[None]:
    """Answer only resends in this block: a request whose record is gone raises ReplayMissed instead of being admitted.

    Admission resolves paths and takes registry locks, which the MCP event
    loop must not wait for; a resend's answer is in memory.
    """
    token = _REPLAY_ONLY.set(True)
    try:
        yield
    finally:
        _REPLAY_ONLY.reset(token)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truncate(text: str, limit: int) -> str:
    return text.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


def _detached(snapshot: dict[str, Any]) -> dict[str, Any]:
    """A record snapshot the caller may change, copied after the manager lock is released.

    A record's result, error and other nested values are replaced when they
    change, never changed in place, so this copy needs no lock.
    """
    return copy.deepcopy(snapshot)


def _json_safe(value: Any, depth: int = 0) -> Any:
    """Plain JSON data only; non-string keys and foreign objects become strings."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if depth < 8 and isinstance(value, dict):
        return {str(key): _json_safe(item, depth + 1) for key, item in value.items()}
    if depth < 8 and isinstance(value, (list, tuple)):
        return [_json_safe(item, depth + 1) for item in value]
    return str(value)


def _payload_size(value: Any) -> int:
    if value is None:
        return 0
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode())
    except (TypeError, ValueError):
        return len(str(value).encode())


def _kept_details(details: Any) -> dict[str, Any]:
    kept = {
        key: value[:512] if isinstance(value, str) else value
        for key, value in (details if isinstance(details, dict) else {}).items()
        if key in _CLEANUP_KEYS and isinstance(value, (str, bool))
    }
    kept["diagnostics_truncated"] = True
    return kept


def _worker_failed() -> dict[str, Any]:
    return {
        "code": ErrorCode.OPERATION_WORKER_FAILED.value,
        "message": "Job worker or result conversion failed; inspect project state before retrying",
        "retryable": False,
        "hint": None,
        "details": {"cleanup_error": True},
    }


def _error_payload(
    exc: BaseException,
    kind: str,
    public_error: Callable[[DomainError], dict[str, Any]] | None = None,
    *,
    keep_details: bool = False,
) -> dict[str, Any]:
    """Reuse domain classification; never retain exceptions, tracebacks or JVM objects.

    ``keep_details`` leaves large diagnostics for the presentation layer to
    store instead of truncating them: a failed script's output is what the
    client needs to fix it.
    """
    if not isinstance(exc, Exception):
        return _worker_failed()
    try:
        error = to_domain_error(exc, operation=kind)
        payload = (
            public_error(error)
            if public_error is not None
            else {
                "message": error.message,
                "code": error.code.value,
                "retryable": error.retryable,
                "hint": error.hint,
                "details": error.details,
            }
        )
        details = _json_safe(payload.get("details") or {})
        if not keep_details and len(json.dumps(details).encode()) > _DETAILS_LIMIT_BYTES:
            details = _kept_details(details)
        return {
            "code": payload["code"],
            "message": _truncate(str(payload["message"]), 2048),
            "retryable": bool(payload.get("retryable")),
            "hint": _truncate(str(payload["hint"]), 512) if payload.get("hint") else None,
            "details": details,
        }
    except Exception:
        logger.exception("Could not convert a job failure; reporting OPERATION_WORKER_FAILED")
        return _worker_failed()


def _output_state(kind: str, executing: bool, details: dict[str, Any]) -> str:
    """What a failed job left in the project: absent, created or uncertain."""
    if not executing:
        return ABSENT
    if details.get("cleanup_error"):
        # The failure could not be converted or cleaned up after.
        return UNCERTAIN
    if kind == ANALYSIS:
        # The analysis runs in one transaction, and a failure inside it aborts
        # the transaction: only a failure after the commit leaves changes.
        return CREATED if details.get("output_created") is True else ABSENT
    if kind == SCRIPT:
        # A script starts executing only when its transaction starts, and every
        # failure after that reports how the transaction ended. An invalid
        # execution left work running (stray threads, analysis) that may still
        # change the program after the rollback.
        if details.get("execution_state") == "invalid":
            return UNCERTAIN
        if details.get("output_created") is True:
            return CREATED
        return output_state_for_outcome(details.get("transaction_outcome"))
    if details.get("rollback_deleted") is True or details.get("output_created") is False:
        return ABSENT
    if details.get("partial_import") is True:
        return CREATED
    return UNCERTAIN


def _terminal_error(error: dict[str, Any], output_state: str) -> dict[str, Any]:
    """Keep the original code, message and hint; state what the failure left behind."""
    return {
        **error,
        "retryable": retryable_after(bool(error.get("retryable")), output_state),
        "details": {**(error.get("details") or {}), "output_state": output_state},
    }


def _is_lock_timeout(exc: BaseException) -> bool:
    return isinstance(exc, DomainError) and exc.code == ErrorCode.LOCK_TIMEOUT


def _call_quietly(callback: Callable[[], None]) -> None:
    try:
        callback()
    except Exception:
        logger.exception("Could not cancel the running job")


@dataclass
class _Operation:
    snapshot: dict[str, Any]
    # Runtime arguments; dropped once the job is finished.
    arguments: dict[str, Any] | None
    # SHA-256 of the canonical request, compared on resends.
    fingerprint: str
    # (project key, program path): the name an import writes, the program an
    # analysis or a script changes, or the program a deferred call was using.
    resource: tuple[str, str]
    # The job's claim: one pending import per name, one pending analysis per
    # program session, and one pending script per identical request. The kinds
    # never block each other; the single worker already runs one at a time.
    reservation: tuple[Any, ...]
    request_ids: list[str] = field(default_factory=list)
    # True while the job holds its target/project locks.
    holds_locks: bool = False
    # Ordinary calls observe their actual acquisitions, including time before
    # a slow call gets a record. Queued jobs use control.check_active instead.
    call_locks: CallLocks | None = None
    cancel: Callable[[], None] | None = None
    # Set once the job is to stop: "client" (cancel_operation) or "shutdown".
    cancel_reason: str | None = None
    # A tool call running on its own thread, not a queued job: one that
    # outlived its reply, or one sent with a request_id (see claim_call).
    deferred: bool = False
    # Bytes of result, error and reply this record keeps.
    payload_bytes: int = 0
    # The reply a call sent with a request_id gave, as JSON, for its resends.
    reply: dict[str, Any] | None = None

    @property
    def kind(self) -> str:
        return self.snapshot["kind"]

    @property
    def executing(self) -> bool:
        """Whether the job began changing the program (control.begin), or the call is running."""
        return self.snapshot["phase"] == "executing"

    @property
    def cancel_requested(self) -> bool:
        return self.cancel_reason is not None


class _Control:
    """The ``OperationControl`` one job hands to the runtime."""

    def __init__(self, manager: OperationManager, record: _Operation) -> None:
        self._manager = manager
        self._record = record
        self.expected_project_key = record.resource[0]
        self.expected_generation = (record.arguments or {}).get("generation")

    def check_active(self) -> None:
        self._manager._check_active(self._record)

    def begin(self) -> None:
        self._manager._begin(self._record)

    def bind_cancel(self, cancel: Callable[[], None] | None) -> None:
        self._manager._bind_cancel(self._record, cancel)


class OperationManager:
    def __init__(
        self,
        target_service: TargetService,
        *,
        script_service: Any | None = None,
        queue_limit: int = _QUEUE_LIMIT,
        history_limit: int = _HISTORY_LIMIT,
        payload_limit_bytes: int = _PAYLOAD_LIMIT_BYTES,
        public_error: Callable[[DomainError], dict[str, Any]] | None = None,
        present: Presenter | None = None,
    ) -> None:
        if queue_limit < 1 or history_limit < 1 or payload_limit_bytes < 1:
            raise ValueError("Job capacity must be positive")
        self.server_instance_id = str(uuid4())
        self._service = target_service
        self._scripts = script_service
        self._public_error = public_error
        # Set by the presentation layer once its result store exists.
        self.present = present
        self._history_limit = history_limit
        self._payload_limit = payload_limit_bytes
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._stop = threading.Event()
        # Unbounded: a cancelled job's id stays until the worker skips it, so
        # the limit counts the jobs still queued instead.
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._queue_limit = queue_limit
        self._queued = 0
        self._records: dict[str, _Operation] = {}
        self._requests: dict[str, str] = {}
        self._reservations: dict[tuple[Any, ...], str] = {}
        self._released: collections.deque[str] = collections.deque()
        # Records that keep a payload, oldest first (a dict used as an ordered set).
        self._payload_order: dict[str, None] = {}
        self._payload_bytes = 0
        # Deferred calls still running, oldest first.
        self._running_calls: dict[str, _Operation] = {}
        # Tool calls running on their own threads, deferred or not.
        self._calls_in_flight = 0
        self._thread: threading.Thread | None = None
        # The job the worker is running; there is only one worker.
        self._current: _Operation | None = None
        self._stopping = False
        self._broken = False

    # -- public API -----------------------------------------------------------

    def has_request(self, request_id: Any) -> bool:
        """Fast replay routing; full argument comparison still follows."""
        try:
            request_id = canonical_uuid(request_id)
        except ValueError:
            return False
        with self._lock:
            return request_id in self._requests

    def submit_import(
        self,
        target: str,
        *,
        binary_path: str,
        request_id: str | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        def resolve(_fingerprint: str) -> tuple[tuple[str, str], tuple[Any, ...], dict[str, Any]]:
            path, project_key = self._service.prepare_import(target, binary_path)
            resource = (project_key, "/" + Path(path).name)
            return resource, (IMPORT, *resource), {"binary_path": path, **options}

        return _detached(self._submit(IMPORT, target, request_id, {"binary_path": binary_path, **options}, resolve))

    def submit_analysis(self, target: str, *, force: bool = False, request_id: str | None = None) -> dict[str, Any]:
        def resolve(_fingerprint: str) -> tuple[tuple[str, str], tuple[Any, ...], dict[str, Any]]:
            # Registry state only: no Ghidra lock, so a queued job never waits here.
            program = self._service.prepare_analysis(target)
            resource = (program.project_key, program.domain_path)
            # Keyed by session too: after a reload, a new request is a new job, not
            # a copy of an older one that will end with SESSION_CHANGED.
            reservation = (ANALYSIS, *resource, program.generation)
            return resource, reservation, {"force": force, "generation": program.generation}

        return _detached(self._submit(ANALYSIS, target, request_id, {"force": force}, resolve))

    def submit_script(self, target: str, *, request_id: str | None = None, **arguments: Any) -> dict[str, Any]:
        if self._scripts is None:
            raise self._error(ErrorCode.SCRIPTS_DISABLED, "Script execution is not configured on this server")

        def resolve(fingerprint: str) -> tuple[tuple[str, str], tuple[Any, ...], dict[str, Any]]:
            # Catalog, runtime and argument checks, and the loaded program:
            # no Ghidra lock and no file is written until the job runs.
            program = self._scripts.prepare_run(target, **arguments)
            resource = (program.project_key, program.domain_path)
            # An identical request joins the pending job; any other script queues behind it.
            reservation = (SCRIPT, *resource, program.generation, fingerprint)
            return resource, reservation, {**arguments, "generation": program.generation}

        return _detached(self._submit(SCRIPT, target, request_id, dict(arguments), resolve))

    def get(self, *, operation_id: str | None = None, request_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            snapshot = self._snapshot_locked(self._lookup_locked(operation_id=operation_id, request_id=request_id))
        return _detached(snapshot)

    def handle(self, operation_id: str) -> dict[str, Any]:
        """The record's operation_id, kind, state and poll_after_ms, without its result."""
        with self._lock:
            return self._handle_locked(self._lookup_locked(operation_id=operation_id, request_id=None))

    def reply_for(self, operation_id: str) -> dict[str, Any] | None:
        """The reply a finished call sent with a request_id gave, as JSON; None once it is dropped.

        The record's own copy: it is never changed once stored, and the
        caller must not change it either.
        """
        with self._lock:
            record = self._records.get(operation_id)
            return None if record is None else record.reply

    def is_pending(self, operation_id: str) -> bool:
        try:
            operation_id = canonical_uuid(operation_id)
        except ValueError:
            return False
        with self._lock:
            return self._pending_locked(operation_id)

    def wait_for(self, operation_id: str, timeout: float) -> dict[str, Any]:
        """Wait up to ``timeout`` seconds for the job to finish; return its latest record.

        A record still pending after the wait reports ``poll_after_ms=0``: the
        caller already waited, so the next lookup may follow at once.
        """
        try:
            operation_id = canonical_uuid(operation_id)
        except ValueError as exc:
            raise self._error(ErrorCode.VALIDATION_ERROR, f"operation_id {exc}") from None
        with self._changed:
            self._changed.wait_for(lambda: not self._pending_locked(operation_id), timeout=max(0.0, timeout))
            snapshot = self._snapshot_locked(self._lookup_locked(operation_id=operation_id, request_id=None))
        if snapshot["state"] in PENDING_STATES:
            snapshot["poll_after_ms"] = 0
        return _detached(snapshot)

    def cancel(self, operation_id: str) -> dict[str, Any]:
        """Stop a queued or running job; return its record.

        A job that has not started changing the program ends at once, even
        while its worker still waits for a lock: it will not run, and a wait
        the runtime bound a cancel to (the script barrier) ends now. A job
        that has started is cancelled through its monitor and ends at the
        command's next checkpoint, so its record may still say running.
        """
        with self._lock:
            record = self._lookup_locked(operation_id=operation_id, request_id=None)
            operation_id = record.snapshot["operation_id"]
            if record.deferred:
                raise self._error(
                    ErrorCode.VALIDATION_ERROR,
                    "A tool call cannot be cancelled, only a job; wait for it with get_operation",
                    operation_id=operation_id,
                )
            state = record.snapshot["state"]
            if state not in PENDING_STATES:
                raise self._error(ErrorCode.VALIDATION_ERROR, "The job has already finished", operation_id=operation_id)
            if not record.cancel_requested:
                record.cancel_reason = "client"
            if not record.executing:
                # Its worker refuses to begin once it gets the locks.
                self._fail_one_locked(record, self._error(ErrorCode.OPERATION_CANCELLED, _CANCELLED_BEFORE_START))
            cancel = record.cancel
            snapshot = self._snapshot_locked(record)
        if cancel is not None:
            _call_quietly(cancel)
        return _detached(snapshot)

    def lock_holder(self, target: str | None, *, any_target: bool = False) -> str | None:
        """The job or deferred call holding the locks a ``LOCK_TIMEOUT`` on ``target`` waited for.

        A call still waiting for its locks is not a holder, and neither is a
        job that has already ended (cancelled while its worker still waits):
        waiting for it would return at once. A project lock blocks the
        project's other targets too. ``any_target`` matches across targets,
        for the runtime-wide locks everything shares.
        """
        project_key = None
        if target is not None and not any_target:
            try:
                project_key = self._service.project_key(target)
            except Exception:
                project_key = None

        def holds(record: _Operation | None) -> bool:
            if record is None or record.snapshot["state"] not in PENDING_STATES:
                return False
            if record.deferred:
                held = record.call_locks.held_by_other_thread() if record.call_locks is not None else frozenset()
            else:
                held = {"target", "project"} if record.holds_locks else set()
            return (
                (any_target and bool(held & {"target", "project"}))
                or ("target" in held and record.snapshot["target"] == target)
                or ("project" in held and bool(project_key) and record.resource[0] == project_key)
            )

        with self._lock:
            if holds(self._current):
                return self._current.snapshot["operation_id"]
            for record in self._running_calls.values():
                if holds(record):
                    return record.snapshot["operation_id"]
            return None

    # -- deferred tool calls ---------------------------------------------------

    @contextlib.contextmanager
    def tracked_call(self, *, call_locks: CallLocks | None = None) -> Iterator[None]:
        """Count a tool call running on its own thread, so shutdown waits for it before closing Ghidra."""
        with self._lock:
            self._calls_in_flight += 1
        try:
            with call_locks.observe() if call_locks is not None else contextlib.nullcontext():
                yield
        finally:
            with self._lock:
                self._calls_in_flight -= 1
                self._changed.notify_all()

    def defer_call(
        self, tool: str, target: str, *, started_at: str, call_locks: CallLocks | None = None
    ) -> dict[str, Any]:
        """Record a tool call that did not finish before its reply; its thread keeps running.

        ``target`` is empty for a tool that takes none, such as a BSim database
        query; such a call holds no target, project or runtime lock.
        """
        target = target or ""
        project_key = self._project_key_of(target)
        with self._lock:
            record = self._start_call_locked(tool, target, project_key, started_at)
            record.call_locks = call_locks
            return self._handle_locked(record)

    def bind_call_locks(self, operation_id: str, call_locks: CallLocks) -> None:
        """Connect a claimed request to its worker's lock observations before it starts."""
        with self._lock:
            self._running_calls[operation_id].call_locks = call_locks

    def claim_call(
        self, tool: str, target: str, *, request_id: str, fingerprint: str, started_at: str | None = None
    ) -> tuple[dict[str, Any], bool]:
        """Record a call sent with a ``request_id`` before it runs; return its handle and whether it is new.

        A resend with the same request_id and arguments gets the first call's
        record, running or finished, instead of a new one: the caller replies
        with that call's outcome and does not run the tool again.  Other
        arguments with the request_id fail with REQUEST_ID_CONFLICT.  Like a
        deferred call, the record is kept in memory only.  The handle is the
        record without its result (see ``handle``).
        """
        try:
            request_id = canonical_uuid(request_id)
        except ValueError as exc:
            raise self._error(ErrorCode.VALIDATION_ERROR, f"request_id {exc}") from None
        target = target or ""
        project_key = self._project_key_of(target)
        with self._lock:
            known = self._requests.get(request_id)
            if known is not None:
                record = self._records[known]
                if record.fingerprint != fingerprint:
                    raise self._error(
                        ErrorCode.REQUEST_ID_CONFLICT, "request_id already identifies a call with different arguments"
                    )
                return self._handle_locked(record), False
            record = self._start_call_locked(
                tool, target, project_key, started_at or _now(), request_id=request_id, fingerprint=fingerprint
            )
            return self._handle_locked(record), True

    def _project_key_of(self, target: str) -> str:
        try:
            return (self._service.project_key(target) if target else None) or ""
        except Exception:
            return ""

    def _start_call_locked(
        self,
        tool: str,
        target: str,
        project_key: str,
        started_at: str,
        *,
        request_id: str | None = None,
        fingerprint: str = "",
    ) -> _Operation:
        record = self._new_record(tool, target, request_id, {}, fingerprint, (project_key, ""), ())
        operation_id = record.snapshot["operation_id"]
        record.deferred = True
        record.snapshot.update(state="running", phase="executing", started_at=started_at)
        self._records[operation_id] = record
        self._running_calls[operation_id] = record
        if request_id is not None:
            self._requests[request_id] = operation_id
            record.request_ids.append(request_id)
        self._changed.notify_all()
        return record

    def finish_call(
        self,
        operation_id: str,
        *,
        result: Any = None,
        error: dict[str, Any] | None = None,
        reply: dict[str, Any] | None = None,
        source: dict[str, Any] | None = None,
        forget_request: bool = False,
    ) -> None:
        """Store what a tool call returned: its result, or the error the tool reported.

        ``reply`` is the whole reply as JSON.  Only a call sent with a
        request_id keeps it, to answer a resend exactly as the first time.
        ``source`` is the program state a core command's reply named; the
        record keeps it beside the result.  ``forget_request`` frees the
        request_id for a new call, for a call that never ran.
        """
        size = _payload_size(result) + _payload_size(error) + _payload_size(source)
        reply_size = _payload_size(reply)
        with self._lock:
            record = self._running_calls.pop(operation_id, None)
            if record is None:
                return
            if record.request_ids and reply is not None:
                record.reply = reply
                size += reply_size
            now = _now()
            record.call_locks = None
            record.snapshot.update(
                state="succeeded" if error is None else "failed",
                result=result if error is None else None,
                operation_error=error,
                updated_at=now,
                finished_at=now,
            )
            if source is not None and error is None:
                record.snapshot["source"] = source
            if forget_request:
                # A resend already waiting still gets this reply; later ones run the call.
                for request_id in record.request_ids:
                    if self._requests.get(request_id) == operation_id:
                        del self._requests[request_id]
            self._keep_payload_locked(record, size)
            self._release_locked(record)
            self._changed.notify_all()

    def shutdown(self) -> None:
        cancels: list[Callable[[], None]] = []
        script_running = False
        with self._lock:
            if not self._stopping:
                self._stopping = True
                self._stop.set()
                self._fail_queued_locked(
                    self._error(ErrorCode.OPERATION_SHUTDOWN, "Server is shutting down; queued job was not started")
                )
                for record in self._records.values():
                    if record.snapshot["state"] == "running" and not record.deferred:
                        record.cancel_reason = record.cancel_reason or "shutdown"
                        if record.cancel is not None:
                            cancels.append(record.cancel)
                if self._thread is not None and not self._broken:
                    self._queue.put_nowait(None)
            thread = self._thread
            script_running = self._current is not None and self._current.kind == SCRIPT
        # Cancelling stops a running job at its next checkpoint; the runtime
        # then rolls the half-done work back before returning.
        for cancel in cancels:
            _call_quietly(cancel)
        if thread is not None:
            if script_running:
                # A script that never checks its monitor cannot be stopped: wait
                # as long as a lock would, then let close_all close the projects
                # the script does not hold. The process itself still cannot exit
                # normally while the script runs; a signal or restart ends it.
                thread.join(timeout=get_lock_timeout_seconds())
                if thread.is_alive():
                    logger.warning("A running script ignored cancellation; closing Ghidra projects it does not hold")
            while thread.is_alive() and not script_running:
                thread.join(timeout=30)
                if thread.is_alive():
                    logger.warning("Waiting for the job worker to stop before closing Ghidra projects")
        with self._changed:
            # Deferred calls are not cancelled, like any call in progress.
            while self._calls_in_flight:
                if not self._changed.wait(timeout=30):
                    logger.warning(
                        "Waiting for %d tool call(s) to finish before closing Ghidra projects", self._calls_in_flight
                    )

    # -- admission helpers ------------------------------------------------------

    def _error(self, code: ErrorCode, message: str, *, retryable: bool = False, **details: Any) -> DomainError:
        return DomainError(
            code, message, retryable=retryable, details={"server_instance_id": self.server_instance_id, **details}
        )

    def _payload(self, exc: BaseException, kind: str) -> dict[str, Any]:
        return _error_payload(exc, kind, self._public_error, keep_details=kind == SCRIPT)

    def _submit(
        self,
        kind: str,
        target: str,
        request_id: str | None,
        request: dict[str, Any],
        resolve: Callable[[str], tuple[tuple[str, str], tuple[Any, ...], dict[str, Any]]],
    ) -> dict[str, Any]:
        try:
            request_id = None if request_id is None else canonical_uuid(request_id)
        except ValueError as exc:
            raise self._error(ErrorCode.VALIDATION_ERROR, f"request_id {exc}") from None
        # UTF-8 size: ASCII escapes would count each non-ASCII character six times.
        encoded = json.dumps(
            {"kind": kind, "target": target, **request}, sort_keys=True, default=str, ensure_ascii=False
        ).encode()
        limit = _SCRIPT_ARGUMENT_LIMIT_BYTES if kind == SCRIPT else _ARGUMENT_LIMIT_BYTES
        if len(encoded) > limit:
            raise self._error(ErrorCode.VALIDATION_ERROR, f"Job arguments exceed {limit // 1024} KiB")
        fingerprint = hashlib.sha256(encoded).hexdigest()
        if request_id is not None:
            # A replay touches neither the filesystem nor the target registry,
            # so it works after the input disappears or the target changes.
            with self._lock:
                replay = self._replay_locked(request_id, fingerprint)
            if replay is not None:
                return replay
        if _REPLAY_ONLY.get():
            raise ReplayMissed
        resource, reservation, arguments = resolve(fingerprint)
        with self._lock:
            if request_id is not None:
                replay = self._replay_locked(request_id, fingerprint)
                if replay is not None:
                    return replay
            if self._stopping or self._broken:
                raise self._error(ErrorCode.OPERATION_WORKER_UNAVAILABLE, "Job worker is stopping or unavailable")
            holder_id = self._reservations.get(reservation)
            # A job being cancelled takes nobody along: another analysis or
            # script queues behind it, and an import waits (_join_holder_locked).
            if holder_id is not None and (kind == IMPORT or not self._records[holder_id].cancel_requested):
                return self._join_holder_locked(holder_id, request_id, fingerprint)
            record = self._new_record(kind, target, request_id, arguments, fingerprint, resource, reservation)
            operation_id = record.snapshot["operation_id"]
            if self._thread is None:
                thread = threading.Thread(target=self._work, name="ghidra-jobs", daemon=False)
                thread.start()
                self._thread = thread
            if self._queued >= self._queue_limit:
                raise self._error(
                    ErrorCode.OPERATION_QUEUE_FULL, "Job queue is full; nothing was accepted", retryable=True
                )
            self._queue.put_nowait(operation_id)
            self._queued += 1
            # Registered only once queued, so a failed admission leaves nothing behind.
            self._records[operation_id] = record
            self._reservations[reservation] = operation_id
            if request_id is not None:
                self._requests[request_id] = operation_id
                record.request_ids.append(request_id)
            return self._response_locked(record, replayed=False)

    def _replay_locked(self, request_id: str, fingerprint: str) -> dict[str, Any] | None:
        operation_id = self._requests.get(request_id)
        if operation_id is None:
            return None
        record = self._records[operation_id]
        if fingerprint != record.fingerprint:
            raise self._error(ErrorCode.REQUEST_ID_CONFLICT, "request_id already identifies different job arguments")
        return self._response_locked(record, replayed=True)

    def _join_holder_locked(self, holder_id: str, request_id: str | None, fingerprint: str) -> dict[str, Any]:
        """A request for a program a job of the same kind holds joins that job or is refused."""
        holder = self._records[holder_id]
        if holder.snapshot["state"] not in PENDING_STATES:
            # Only an import keeps its name after failing, and only when it may have left a program behind.
            raise self._error(
                ErrorCode.IMPORT_OUTPUT_UNCERTAIN,
                "An earlier import of this program did not clean up",
                operation_id=holder_id,
            )
        if holder.cancel_requested:
            # It may still leave a program behind, which the name must then keep.
            raise self._error(
                ErrorCode.IMPORT_IN_PROGRESS,
                "The import of this program is being cancelled; retry once it ends",
                retryable=True,
                operation_id=holder_id,
            )
        if holder.fingerprint != fingerprint:
            if holder.kind == ANALYSIS:
                raise self._error(
                    ErrorCode.ANALYSIS_IN_PROGRESS,
                    "Another analysis of this program is queued or running",
                    operation_id=holder_id,
                )
            raise self._error(
                ErrorCode.IMPORT_IN_PROGRESS,
                "Another import is writing this program",
                operation_id=holder_id,
            )
        # The same request resent (a lost reply, a regenerated call): same job.
        if request_id is not None:
            self._requests[request_id] = holder_id
            holder.request_ids.append(request_id)
        return self._response_locked(holder, replayed=True)

    def _new_record(
        self,
        kind: str,
        target: str,
        request_id: str | None,
        arguments: dict[str, Any],
        fingerprint: str,
        resource: tuple[str, str],
        reservation: tuple[Any, ...],
    ) -> _Operation:
        now = _now()
        return _Operation(
            snapshot={
                "operation_id": str(uuid4()),
                "kind": kind,
                "request_id": request_id,
                "server_instance_id": self.server_instance_id,
                "target": target,
                "state": "queued",
                "phase": "queued",
                "created_at": now,
                "updated_at": now,
                "started_at": None,
                "finished_at": None,
                "result": None,
                "operation_error": None,
            },
            arguments=arguments,
            fingerprint=fingerprint,
            resource=resource,
            reservation=reservation,
        )

    def _lookup_locked(self, *, operation_id: str | None, request_id: str | None) -> _Operation:
        if (operation_id is None) == (request_id is None):
            raise self._error(ErrorCode.VALIDATION_ERROR, "Supply exactly one of operation_id or request_id")
        try:
            key = (
                canonical_uuid(operation_id)
                if operation_id is not None
                else self._requests.get(canonical_uuid(request_id))
            )
        except ValueError as exc:
            raise self._error(ErrorCode.VALIDATION_ERROR, f"identifier {exc}") from None
        record = self._records.get(key) if key is not None else None
        if record is None:
            raise self._error(
                ErrorCode.OPERATION_NOT_FOUND,
                "No record in this server process; absence does not mean the job never ran",
            )
        return record

    def _pending_locked(self, operation_id: str) -> bool:
        record = self._records.get(operation_id)
        return record is not None and record.snapshot["state"] in PENDING_STATES

    def _snapshot_locked(self, record: _Operation) -> dict[str, Any]:
        """The record's fields; its nested values stay shared until ``_detached`` copies them."""
        snapshot = dict(record.snapshot)
        snapshot["poll_after_ms"] = _POLL_AFTER_MS if snapshot["state"] in PENDING_STATES else 0
        return snapshot

    def _handle_locked(self, record: _Operation) -> dict[str, Any]:
        state = record.snapshot["state"]
        return {
            "operation_id": record.snapshot["operation_id"],
            "kind": record.kind,
            "state": state,
            "poll_after_ms": _POLL_AFTER_MS if state in PENDING_STATES else 0,
        }

    def _response_locked(self, record: _Operation, *, replayed: bool) -> dict[str, Any]:
        return {**self._snapshot_locked(record), "replayed": replayed}

    # -- worker ---------------------------------------------------------------------

    def _refusal_locked(self, record: _Operation) -> DomainError | None:
        """Why the job must not go on, if it must not: a cancellation or shutdown."""
        if record.cancel_reason == "client":
            return self._error(ErrorCode.OPERATION_CANCELLED, _CANCELLED_BEFORE_START)
        if self._stopping:
            return self._error(ErrorCode.OPERATION_SHUTDOWN, _NOT_STARTED)
        return None

    def _check_active(self, record: _Operation) -> None:
        with self._lock:
            refusal = self._refusal_locked(record)
            if refusal is not None:
                raise refusal
            record.holds_locks = True

    def _begin(self, record: _Operation) -> None:
        with self._lock:
            refusal = self._refusal_locked(record)
            if refusal is not None:
                raise refusal
            record.snapshot.update(phase="executing", updated_at=_now())
            self._changed.notify_all()

    def _bind_cancel(self, record: _Operation, cancel: Callable[[], None] | None) -> None:
        with self._lock:
            record.cancel = cancel
            run_now = cancel is not None and record.cancel_requested
        if run_now:
            _call_quietly(cancel)

    def _work(self) -> None:
        record = None
        try:
            while True:
                try:
                    operation_id = self._queue.get(timeout=_IDLE_EXIT_SECONDS)
                except queue.Empty:
                    # An idle worker exits, so a process that never calls
                    # shutdown() is not kept alive; a new job starts a new one.
                    with self._lock:
                        if self._queue.empty():
                            if self._thread is threading.current_thread():
                                self._thread = None
                            return
                    continue
                try:
                    if operation_id is None:
                        return
                    with self._lock:
                        record = self._records.get(operation_id)
                        if record is None:
                            logger.warning("Job worker skipped unknown operation %s", operation_id)
                            continue
                        if self._stopping or record.snapshot["state"] != "queued":
                            # shutdown() or cancel_operation() has already ended it.
                            record = None
                            continue
                        self._queued -= 1
                        now = _now()
                        record.snapshot.update(
                            state="running", phase="waiting_for_lock", started_at=now, updated_at=now
                        )
                        self._current = record
                        self._changed.notify_all()
                    self._run(record)
                finally:
                    self._queue.task_done()
                    with self._lock:
                        self._current = None
                record = None
        except BaseException as exc:
            # Covers dequeue, lookup and finalization, not just the runtime call.
            logger.exception("Job worker stopped unexpectedly")
            with self._lock:
                self._broken = True
                if record is not None and record.snapshot["state"] in PENDING_STATES:
                    # A job the runtime had started may have left changes behind.
                    output_state = UNCERTAIN if record.executing else ABSENT
                    now = _now()
                    record.snapshot.update(
                        state="failed",
                        result=None,
                        operation_error=_terminal_error(self._payload(exc, record.kind), output_state),
                        updated_at=now,
                        finished_at=now,
                    )
                    record.arguments = None
                    if output_state == ABSENT or record.kind != IMPORT:
                        self._release_locked(record)
                self._fail_queued_locked(
                    self._error(ErrorCode.OPERATION_WORKER_FAILED, "Job worker stopped; the job was not started")
                )
                self._changed.notify_all()

    def _run(self, record: _Operation) -> None:
        operation_id = record.snapshot["operation_id"]
        kind = record.kind
        target = record.snapshot["target"]
        control = _Control(self, record)
        result = error = None
        while True:
            try:
                result = self._execute(record, control)
                break
            except Exception as exc:
                if _is_lock_timeout(exc) and not record.executing:
                    # Nothing was written: stay queued behind the lock holder
                    # instead of failing a job the client already handed off.
                    with self._lock:
                        record.holds_locks = False
                        refusal = self._refusal_locked(record)
                    if refusal is None and not self._stop.wait(_LOCK_RETRY_SECONDS):
                        continue
                    exc = refusal or self._error(ErrorCode.OPERATION_SHUTDOWN, _NOT_STARTED)
                logger.debug("Job %s failure detail", operation_id, exc_info=exc)
                error = self._payload(exc, kind)
                break
        with self._lock:
            record.holds_locks = False
            if record.snapshot["state"] not in PENDING_STATES:
                # cancel_operation ended it before it began; nothing ran.
                return
            # Only a job the runtime had started was cancelled mid-way; one that
            # never started keeps its own "not started" error.
            if error is not None and record.cancel_requested and record.executing:
                error = self._cancelled_error(record, error)
        output_state = None if error is None else _output_state(kind, record.executing, error.get("details") or {})
        result, error = self._presented(kind, target, result, error)
        size = _payload_size(result) + _payload_size(error)
        with self._lock:
            if record.snapshot["state"] not in PENDING_STATES:
                # cancel_operation ended it while the outcome was presented; it
                # had not begun, and the client was told it was cancelled.
                return
            self._finish_locked(record, result, error, output_state, size)
        if error is None:
            logger.info("Job %s (%s) finished: %s", operation_id, kind, record.resource[1])
        else:
            logger.warning("Job %s (%s) failed: %s (output %s)", operation_id, kind, error["code"], output_state)

    def _presented(
        self, kind: str, target: str, result: Any, error: dict[str, Any] | None
    ) -> tuple[Any, dict[str, Any] | None]:
        """Let the presentation layer move oversized values to the result store."""
        if self.present is None:
            return result, error
        try:
            return self.present(kind, target, result, error)
        except Exception:
            logger.exception("Could not present the outcome of a %s job; keeping it in the record", kind)
            return result, error

    def _execute(self, record: _Operation, control: _Control) -> Any:
        arguments = dict(record.arguments or {})
        target = record.snapshot["target"]
        if record.kind == IMPORT:
            binary_path = arguments.pop("binary_path")
            program = self._service.import_program(target, binary_path, control=control, **arguments)
            if not isinstance(program, str):
                raise TypeError("Import returned an invalid program path")
            return {"program": program}
        if record.kind == SCRIPT:
            arguments.pop("generation", None)
            outcome = self._scripts.run_script(target, control=control, **arguments)
            if not isinstance(outcome, dict):
                raise TypeError("Script run returned an invalid result")
            return outcome
        outcome = self._service.analyze_program(target, force=arguments["force"], control=control)
        if not isinstance(outcome, dict) or not isinstance(outcome.get("analyzed"), bool):
            raise TypeError("Analysis returned an invalid result")
        return {"program": record.resource[1], "analyzed": outcome["analyzed"], "forced": bool(outcome.get("forced"))}

    def _cancelled_error(self, record: _Operation, error: dict[str, Any]) -> dict[str, Any]:
        """Report a job cancelled mid-way by the client or by shutdown, keeping its cleanup evidence."""
        if record.cancel_reason == "client":
            reason = self._error(ErrorCode.OPERATION_CANCELLED, "cancel_operation stopped the running job")
        else:
            reason = self._error(ErrorCode.OPERATION_SHUTDOWN, "Server shut down during the job; it was cancelled")
        cancelled = self._payload(reason, record.kind)
        return {**cancelled, "details": {**error["details"], **cancelled["details"], "cancelled": True}}

    def _finish_locked(
        self,
        record: _Operation,
        result: Any,
        error: dict[str, Any] | None,
        output_state: str | None,
        size: int,
    ) -> None:
        """Record the outcome. Caller holds the manager lock; the runtime has released its locks."""
        now = _now()
        record.snapshot.update(
            state="failed" if error else "succeeded",
            result=None if error else result,
            operation_error=None if error is None else _terminal_error(error, output_state or UNCERTAIN),
            updated_at=now,
            finished_at=now,
        )
        record.arguments = None
        record.cancel = None
        self._keep_payload_locked(record, size)
        # Success releases an import's name too: a later import of it fails in
        # the runtime with PROGRAM_ALREADY_IMPORTED instead. Analyses and
        # scripts never create a program, so they never keep it reserved.
        if error is None or output_state == ABSENT or record.kind != IMPORT:
            self._release_locked(record)
        self._changed.notify_all()

    def _keep_payload_locked(self, record: _Operation, size: int) -> None:
        """Count what the record keeps; beyond the limit, drop the oldest results first."""
        record.payload_bytes = size
        if not size:
            return
        self._payload_bytes += size
        self._payload_order[record.snapshot["operation_id"]] = None
        if size > self._payload_limit:
            # Dropping the others would not make room for this one.
            self._drop_payload_locked(record)
            return
        while self._payload_bytes > self._payload_limit and self._payload_order:
            self._drop_payload_locked(self._records[next(iter(self._payload_order))])

    def _drop_payload_locked(self, record: _Operation) -> None:
        self._payload_bytes -= record.payload_bytes
        record.payload_bytes = 0
        self._payload_order.pop(record.snapshot["operation_id"], None)
        record.reply = None
        snapshot = record.snapshot
        snapshot["result"] = None
        error = snapshot["operation_error"]
        if error is not None:
            # A failed batch_read's error holds its result too (structured_error).
            kept = {key: value for key, value in error.items() if key != "result"}
            snapshot["operation_error"] = {**kept, "details": _kept_details(error.get("details"))}
        snapshot["result_discarded"] = True

    def _release_locked(self, record: _Operation) -> None:
        operation_id = record.snapshot["operation_id"]
        if self._reservations.get(record.reservation) == operation_id:
            del self._reservations[record.reservation]
        self._released.append(operation_id)
        while len(self._released) > self._history_limit:
            evicted = self._records.pop(self._released.popleft(), None)
            if evicted is None:
                continue
            self._payload_bytes -= evicted.payload_bytes
            evicted.payload_bytes = 0
            self._payload_order.pop(evicted.snapshot["operation_id"], None)
            for request_id in evicted.request_ids:
                if self._requests.get(request_id) == evicted.snapshot["operation_id"]:
                    del self._requests[request_id]

    def _fail_one_locked(self, record: _Operation, error: DomainError) -> None:
        if record.snapshot["state"] == "queued":
            self._queued -= 1
        now = _now()
        record.snapshot.update(
            state="failed",
            operation_error=_terminal_error(self._payload(error, record.kind), ABSENT),
            updated_at=now,
            finished_at=now,
        )
        record.arguments = None
        self._release_locked(record)
        self._changed.notify_all()

    def _fail_queued_locked(self, error: DomainError) -> None:
        for record in list(self._records.values()):
            if record.snapshot["state"] == "queued":
                self._fail_one_locked(record, error)
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
            self._queue.task_done()
        self._changed.notify_all()


__all__ = ["ANALYSIS", "IMPORT", "PENDING_STATES", "SCRIPT", "OperationManager", "ReplayMissed", "replay_only"]
