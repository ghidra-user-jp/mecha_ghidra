"""Start the Ghidra JVM the way every entry point must: headless.

mcp 2.x runs tool handlers in worker threads.  On macOS the first AWT
initialization from a non-main thread blocks forever waiting for the AppKit
main thread, and PyGhidra sets ``java.awt.headless`` only after the JVM is up,
which is too late for ``GraphicsEnvironment.isHeadless()``.  The flag therefore
has to be a JVM argument, and every code path that starts the JVM must go
through this module so it cannot be forgotten.

The thread that starts the JVM becomes its non-daemon ``main`` thread.  A
thread other than the Python main thread that starts it must call
``detach_current_thread`` before it ends: otherwise JPype's exit handler
(``DestroyJavaVM``) waits for that thread forever and the process never exits.

The JVM also starts with ``-Xrs``, the option the JVM provides for programs
that embed it and handle signals themselves.  Without it the JVM replaces the
process's SIGTERM, SIGINT and SIGHUP handlers while it boots, and a signal then
ends the process at once, before Python has cancelled a running job or closed
its projects.  ``jcmd`` and ``jstack`` still attach: under ``-Xrs`` the JVM
starts its attach listener at boot instead of on SIGQUIT.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import jpype
import pyghidra
from pyghidra.launcher import HeadlessPyGhidraLauncher

from ghidra_headless.errors import HeadlessError

logger = logging.getLogger(__name__)

HEADLESS_VM_ARG = "-Djava.awt.headless=true"
# Leave SIGTERM, SIGINT, SIGHUP and SIGQUIT to Python (see the module docstring).
REDUCE_SIGNAL_USAGE_VM_ARG = "-Xrs"


def jvm_is_headless() -> bool:
    """Return whether the running JVM's AWT is in headless mode."""

    from java.awt import GraphicsEnvironment

    return bool(GraphicsEnvironment.isHeadless())


def prepare_headless_launcher(
    install_dir: str | Path | None = None,
    *,
    verbose: bool = False,
) -> HeadlessPyGhidraLauncher | None:
    """Check the installation and build the headless launcher without starting the JVM.

    The checks are PyGhidra's own (installation layout, PyGhidra module,
    supported Ghidra version) and read only a few files, so a caller can report
    a bad installation before anything else.  Returns ``None`` when the JVM is
    already running; an already-running JVM that is not headless is rejected:
    the flag cannot be applied retroactively, and continuing would trade a
    clear start-up error for a silent deadlock on the first worker-thread call.
    """

    if pyghidra.started():
        if not jvm_is_headless():
            raise HeadlessError(
                "JVM_NOT_HEADLESS: the JVM was started elsewhere without "
                f"{HEADLESS_VM_ARG}; tool calls from worker threads would block on AWT. "
                "Start the JVM through ghidra_headless.launcher.start_headless_jvm."
            )
        return None
    launcher = HeadlessPyGhidraLauncher(verbose=verbose, install_dir=install_dir)
    launcher.add_vmargs(HEADLESS_VM_ARG, REDUCE_SIGNAL_USAGE_VM_ARG)
    launcher.check_ghidra_version()
    return launcher


def start_headless_jvm(
    install_dir: str | Path | None = None,
    *,
    verbose: bool = False,
    launcher: HeadlessPyGhidraLauncher | None = None,
) -> HeadlessPyGhidraLauncher | None:
    """Start Ghidra with ``java.awt.headless=true`` set before the JVM boots.

    ``launcher`` is one ``prepare_headless_launcher`` built; without it the
    launcher is prepared here.  Returns the launcher, or ``None`` when the JVM
    was already running.
    """

    if launcher is None:
        launcher = prepare_headless_launcher(install_dir, verbose=verbose)
        if launcher is None:
            logger.debug("JVM already running in headless mode; reusing it")
            return None
    launcher.start()
    if not jvm_is_headless():
        raise HeadlessError(
            f"JVM_NOT_HEADLESS: the JVM ignored {HEADLESS_VM_ARG}; refusing to serve tools from worker threads"
        )
    return launcher


def detach_current_thread() -> None:
    """Detach the calling thread from the JVM before it ends (see the module docstring).

    Does nothing on the Python main thread, before the JVM starts or when the
    thread is not attached.  A later Java call from the same thread attaches it
    again, as a daemon thread.
    """

    if threading.current_thread() is threading.main_thread() or not jpype.isJVMStarted():
        return
    java_thread = jpype.java.lang.Thread
    if java_thread.isAttached():
        java_thread.detach()


__all__ = [
    "HEADLESS_VM_ARG",
    "REDUCE_SIGNAL_USAGE_VM_ARG",
    "detach_current_thread",
    "jvm_is_headless",
    "prepare_headless_launcher",
    "start_headless_jvm",
]
