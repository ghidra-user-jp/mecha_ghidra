"""Runtime context management extracted from legacy core handler."""

from __future__ import absolute_import, print_function

import contextlib
import threading
import uuid

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor

_CONTEXTS = {}
_THREAD_STATE = threading.local()


class HeadlessContext(object):
    def __init__(self, program, project=None):
        self.generation = uuid.uuid4().hex
        self.program = program
        # ghidra.framework.model.Project owning the program (None when unknown).
        # Scripts see it as GhidraState.getProject().
        self.project = project
        # Set by run_script when a run left the program in an unverifiable state
        # (leaked transaction, stray worker).  Mutating commands are refused
        # until the target is closed with discard_changes=true and reloaded.
        self.execution_invalid = None
        self._execution_state_lock = threading.Lock()
        self._transaction_sentinel = None
        self.flat_api = FlatProgramAPI(program)
        self.symbol_table = program.getSymbolTable()
        self.function_manager = program.getFunctionManager()
        self.namespace_manager = program.getNamespaceManager()
        self.address_factory = program.getAddressFactory()
        self.listing = program.getListing()
        self.reference_manager = program.getReferenceManager()
        # A DecompInterface owns a native decompiler process.  Creating one per
        # call costs a process spawn every time, so the context keeps a single
        # open interface and only replaces it after a failure.  Core commands on
        # one target are serialized by the target lock, so no two threads use
        # the same interface concurrently.
        self._decompiler = None

    def monitor(self):
        # ConsoleTaskMonitor prints progress to Java's System.out, which shares
        # fd 1 with the MCP stdio transport and would corrupt the JSON-RPC stream.
        return TaskMonitor.DUMMY

    def decompiler(self, factory):
        """Return the shared decompiler, opening one with ``factory`` when needed."""
        if self._decompiler is None:
            interface = factory()
            if not interface.openProgram(self.program):
                interface.dispose()
                return None
            self._decompiler = interface
        return self._decompiler

    def reset_decompiler(self):
        interface, self._decompiler = self._decompiler, None
        if interface is not None:
            with contextlib.suppress(Exception):
                interface.dispose()

    def dispose(self):
        self.reset_decompiler()
        self.disarm_transaction_sentinel()

    def mark_execution_invalid(self, reason, details=None):
        # Listener callbacks and the script command may report independently.
        # A newer reason must not discard the evidence needed to refuse close.
        with self._execution_state_lock:
            previous = self.execution_invalid or {}
            payload = {**previous, "reason": reason, **(details or {})}
            threads = {}
            for entry in [*(previous.get("stray_threads") or []), *((details or {}).get("stray_threads") or [])]:
                kind = entry.get("kind")
                identity = entry.get("token") if kind == "python" else entry.get("id")
                threads[(kind, identity)] = dict(entry)
            if threads:
                payload["stray_threads"] = list(threads.values())
            self.execution_invalid = payload

    def arm_transaction_sentinel(self, key):
        """Flag transactions started by work a script left running.

        In headless mode ``TransactionListener`` callbacks run synchronously on
        the thread that called ``startTransaction``.  The runtime drives the
        program from its own Python threads (core commands carry this target's
        key in ``_THREAD_STATE``; saves and lifecycle calls carry no key).  A
        thread created on the Java side (a Java/Jython script's helper thread,
        a Ghidra task) reaches Python as a ``_DummyThread``: a transaction
        started there, or under another target's key, is stray.  Only top-level
        starts notify, so this is a detector, not a complete guard (nested
        starts and Python threads a PyGhidra script spawned are silent here;
        the thread scan at the end of the run reports the latter).
        """
        if self._transaction_sentinel is not None:
            return
        try:
            from jpype import JImplements, JOverride
        except Exception:
            return
        context = self

        @JImplements("ghidra.framework.model.TransactionListener")
        class _Sentinel(object):
            @JOverride
            def transactionStarted(self, domain_object, transaction):
                current = threading.current_thread()
                # ``_DummyThread`` is CPython's (private, but stable since 2.x) type for a
                # thread that was not started by ``threading``: here, a Java thread calling
                # back into Python.  The stdlib exposes no public predicate for it.
                java_origin = isinstance(current, threading._DummyThread)
                active_key = getattr(_THREAD_STATE, "current_key", None)
                if not java_origin and active_key in (None, key):
                    return
                description = None
                with contextlib.suppress(Exception):
                    description = str(transaction.getDescription())
                context.mark_execution_invalid(
                    "stray_transaction",
                    {"description": description, "thread": current.name, "java_origin": java_origin},
                )

            @JOverride
            def transactionEnded(self, domain_object):
                return None

            @JOverride
            def undoStackChanged(self, domain_object):
                return None

            @JOverride
            def undoRedoOccurred(self, domain_object):
                return None

        sentinel = _Sentinel()
        try:
            self.program.addTransactionListener(sentinel)
        except Exception:
            return
        self._transaction_sentinel = sentinel

    def disarm_transaction_sentinel(self):
        sentinel, self._transaction_sentinel = self._transaction_sentinel, None
        if sentinel is not None:
            with contextlib.suppress(Exception):
                self.program.removeTransactionListener(sentinel)


def initialize(program, key="default", project=None):
    # Construct first so a failed initialization leaves the existing context
    # usable for lifecycle rollback. Target locks serialize replacements.
    context = HeadlessContext(program, project=project)
    previous = _CONTEXTS.get(key)
    if previous is not None:
        previous.dispose()
    _CONTEXTS[key] = context
    return context


def remove_context(key):
    ctx = _CONTEXTS.pop(key, None)
    if ctx is not None:
        ctx.dispose()
    if getattr(_THREAD_STATE, "current_key", None) == key:
        delattr(_THREAD_STATE, "current_key")


def clear_contexts():
    for ctx in list(_CONTEXTS.values()):
        ctx.dispose()
    _CONTEXTS.clear()
    if hasattr(_THREAD_STATE, "current_key"):
        delattr(_THREAD_STATE, "current_key")


def _ensure_context_for_key(key):
    if key not in _CONTEXTS:
        raise RuntimeError("Context is not initialized: %s" % key)
    return _CONTEXTS[key]


def ensure_context():
    key = getattr(_THREAD_STATE, "current_key", None)
    if key is None:
        raise RuntimeError("Context key is not set")
    return _ensure_context_for_key(key)


def describe_state(key="default"):
    ctx = _ensure_context_for_key(key)
    return {
        "programName": ctx.program.getName(),
        "languageID": str(ctx.program.getLanguageID()),
    }


def bind_project(key, project):
    """Attach the owning ``ghidra.framework.model.Project`` to an initialized context."""
    ctx = _CONTEXTS.get(key)
    if ctx is not None:
        ctx.project = project


def execution_state(key="default"):
    """Return the quarantine payload for ``key`` (None when the target is valid or unknown)."""
    ctx = _CONTEXTS.get(key)
    if ctx is None:
        return None
    return ctx.execution_invalid


__all__ = [
    "HeadlessContext",
    "_CONTEXTS",
    "_THREAD_STATE",
    "initialize",
    "remove_context",
    "clear_contexts",
    "_ensure_context_for_key",
    "ensure_context",
    "describe_state",
    "execution_state",
    "bind_project",
]
