"""Start the Ghidra JVM the way every entry point must: headless.

mcp 2.x runs tool handlers in worker threads.  On macOS the first AWT
initialization from a non-main thread blocks forever waiting for the AppKit
main thread, and PyGhidra sets ``java.awt.headless`` only after the JVM is up,
which is too late for ``GraphicsEnvironment.isHeadless()``.  The flag therefore
has to be a JVM argument, and every code path that starts the JVM must go
through this module so it cannot be forgotten.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pyghidra
from pyghidra.launcher import HeadlessPyGhidraLauncher

from ghidra_headless.errors import HeadlessError

logger = logging.getLogger(__name__)

HEADLESS_VM_ARG = "-Djava.awt.headless=true"


def jvm_is_headless() -> bool:
    """Return whether the running JVM's AWT is in headless mode."""

    from java.awt import GraphicsEnvironment

    return bool(GraphicsEnvironment.isHeadless())


def start_headless_jvm(
    install_dir: str | Path | None = None,
    *,
    verbose: bool = False,
) -> HeadlessPyGhidraLauncher | None:
    """Start Ghidra with ``java.awt.headless=true`` set before the JVM boots.

    Returns the launcher, or ``None`` when the JVM was already running.  An
    already-running JVM that is not headless is rejected: the flag cannot be
    applied retroactively, and continuing would trade a clear start-up error
    for a silent deadlock on the first worker-thread call.
    """

    if pyghidra.started():
        if not jvm_is_headless():
            raise HeadlessError(
                "JVM_NOT_HEADLESS: the JVM was started elsewhere without "
                f"{HEADLESS_VM_ARG}; tool calls from worker threads would block on AWT. "
                "Start the JVM through ghidra_headless.launcher.start_headless_jvm."
            )
        logger.debug("JVM already running in headless mode; reusing it")
        return None

    launcher = HeadlessPyGhidraLauncher(verbose=verbose, install_dir=install_dir)
    launcher.add_vmargs(HEADLESS_VM_ARG)
    launcher.start()
    if not jvm_is_headless():
        raise HeadlessError(
            f"JVM_NOT_HEADLESS: the JVM ignored {HEADLESS_VM_ARG}; refusing to serve tools from worker threads"
        )
    return launcher


__all__ = ["HEADLESS_VM_ARG", "jvm_is_headless", "start_headless_jvm"]
