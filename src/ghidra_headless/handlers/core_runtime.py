"""Runtime context management extracted from legacy core handler."""

from __future__ import absolute_import, print_function

import contextlib
import threading

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor

_CONTEXTS = {}
_THREAD_STATE = threading.local()


class HeadlessContext(object):
    def __init__(self, program):
        self.program = program
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


def initialize(program, key="default"):
    _CONTEXTS[key] = HeadlessContext(program)
    return _CONTEXTS[key]


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
]
