"""Runtime context management extracted from legacy core handler."""

from __future__ import absolute_import, print_function

import threading

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor

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

    def monitor(self):
        return ConsoleTaskMonitor()


def initialize(program, key="default"):
    _CONTEXTS[key] = HeadlessContext(program)
    return _CONTEXTS[key]


def remove_context(key):
    _CONTEXTS.pop(key, None)
    if getattr(_THREAD_STATE, "current_key", None) == key:
        delattr(_THREAD_STATE, "current_key")


def clear_contexts():
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
