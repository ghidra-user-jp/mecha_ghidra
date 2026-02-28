"""Thin facade for headless handlers with backward-compatible public entrypoints."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.core_compat import SUPPORTED_COMMANDS
from ghidra_headless.handlers.core_helpers import _json_safe
from ghidra_headless.handlers.core_runtime import (
    _THREAD_STATE,
    _ensure_context_for_key,
    clear_contexts,
    describe_state,
    initialize,
    remove_context,
)


def execute(command, params, key="default"):
    handler = SUPPORTED_COMMANDS.get(command)
    if handler is None:
        raise KeyError("未対応のコマンド: %s" % command)
    _ensure_context_for_key(key)
    previous = getattr(_THREAD_STATE, "current_key", None)
    _THREAD_STATE.current_key = key
    try:
        return _json_safe(handler(params or {}))
    finally:
        if previous is None:
            if hasattr(_THREAD_STATE, "current_key"):
                delattr(_THREAD_STATE, "current_key")
        else:
            _THREAD_STATE.current_key = previous


HANDLERS = {
    "initialize": initialize,
    "execute": execute,
    "describe_state": describe_state,
    "remove_context": remove_context,
    "clear_contexts": clear_contexts,
}


__all__ = [
    "SUPPORTED_COMMANDS",
    "initialize",
    "remove_context",
    "clear_contexts",
    "execute",
    "describe_state",
    "HANDLERS",
]
