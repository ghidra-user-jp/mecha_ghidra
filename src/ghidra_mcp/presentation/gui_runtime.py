"""The GUI backend's runtime: Ghidra's GUI and this MCP server in one process (spec §3.3, §4.4, §4.5).

Threads:

- **main**: the JVM and the GUI (``GuiLaunch.run``).  On macOS it stays in
  CFRunLoop for good, so it never runs Python signal handlers again;
- **mcp-server**: the MCP server over HTTP (``run_mcp_server``), whose event
  loop also runs the startup's ``main_thread`` steps;
- **ghidra-startup**: the startup steps, which wait for the GUI to come up;
- **gui-signals**: turns SIGINT and SIGTERM into Ghidra's own exit, which asks
  about unsaved changes and can be cancelled; SIGHUP leaves the GUI running.

Once the GUI runs, Ghidra ends the process with ``System.exit`` when the human
exits it; no Python cleanup is relied on after that.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import signal
import sys
import threading
from collections.abc import Callable
from typing import Any

from ghidra_headless.errors import HeadlessError
from ghidra_headless.gui.launch import GuiLaunch, request_gui_exit
from ghidra_headless.gui.readiness import (
    GuiStartupStatus,
    StartupStopped,
    wait_for_check,
    wait_for_code_browser,
    wait_for_front_end,
    wait_for_jvm,
    wait_for_project,
)
from ghidra_mcp.domain.error_mapping import to_domain_error

from .startup import StartupStep, _Stopped

logger = logging.getLogger(__name__)

_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
# How long the main thread waits for the MCP server to stop after the GUI was not started.
_SERVER_STOP_SECONDS = 30.0
# How long the main thread waits for the exiting JVM to end the process.
_JVM_EXIT_SECONDS = 30.0
# How often the runtime looks whether the human closed its project (spec §5.1).
_CLOSURE_POLL_SECONDS = 1.0


def _detach_from_terminal() -> None:
    """Point stdout and stderr, Python's and the JVM's (one process), at /dev/null."""
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):  # the terminal may be gone already
            stream.flush()
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
    finally:
        os.close(devnull)


def _ignore_signal(_signum, _frame) -> None:
    """Registered so Python's C-level handler writes the signal to the wakeup fd; the watcher acts on it."""


def _stoppable(function: Callable[[], Any]) -> Callable[[], None]:
    """A startup step whose wait ends when the server shuts down, reported as stopped, not failed."""

    @functools.wraps(function)
    def step() -> None:
        try:
            function()
        except StartupStopped as exc:
            raise _Stopped from exc
        except HeadlessError as exc:
            # Its code (PROJECT_LOCKED, ...) becomes STARTUP_FAILED's details.cause_type.
            raise to_domain_error(exc, operation="startup") from exc

    return step


class GuiRuntime:
    """One process: the Ghidra GUI on the main thread and the MCP server beside it."""

    def __init__(self, *, ghidra_path: str | None, project_location: str, project_name: str) -> None:
        self.project_location = project_location
        self.project_name = project_name
        self.launch = GuiLaunch(ghidra_path, project_location=project_location, project_name=project_name)
        self.status = GuiStartupStatus()
        self._server_thread: threading.Thread | None = None
        self._project = None
        self._server_stopped = threading.Event()

    def prepare(self) -> None:
        """Check the Ghidra installation's version without a JVM (raises on a misconfiguration)."""
        self.launch.prepare()

    def details(self) -> dict[str, object]:
        """Extra details for a call that finds the server still starting: the GUI's modal dialogs."""
        return self.status.details()

    def startup_steps(
        self,
        *,
        session_steps: list[StartupStep],
        prepare_event_loop_thread: Callable[[], None],
        load_core: Callable[[], Any],
        mark_jvm_started: Callable[[], None],
    ) -> list[StartupStep]:
        """The startup thread's steps; their names are the stages the still-starting error reports."""

        def jvm() -> None:
            wait_for_jvm(self.launch, self.status)
            mark_jvm_started()

        def project_open() -> None:
            self._project = wait_for_project(self.status, self.project_location, self.project_name)

        return [
            StartupStep("gui_jvm", _stoppable(jvm), "Failed to start the JVM for the Ghidra GUI"),
            StartupStep(
                "display",
                _stoppable(functools.partial(wait_for_check, self.launch, self.status, "display")),
                "The Ghidra GUI cannot start here",
            ),
            StartupStep(
                "project_lock",
                _stoppable(functools.partial(wait_for_check, self.launch, self.status, "project_lock")),
                "The Ghidra GUI cannot open the project",
            ),
            StartupStep(
                "event_loop_thread",
                prepare_event_loop_thread,
                "Failed to prepare the event loop thread for Ghidra",
                main_thread=True,
            ),
            StartupStep(
                "front_end",
                _stoppable(functools.partial(wait_for_front_end, self.status, self.launch)),
                "The Ghidra GUI did not show its project window",
            ),
            StartupStep("project_open", _stoppable(project_open), "The Ghidra GUI did not open the project"),
            StartupStep(
                "code_browser",
                _stoppable(lambda: wait_for_code_browser(self.status, self._project)),
                "The Ghidra GUI could not start a CodeBrowser",
            ),
            StartupStep(
                "core", functools.partial(self._load_core, load_core), "Failed to load the Ghidra command handlers"
            ),
            *session_steps,
        ]

    @staticmethod
    def _load_core(load_core: Callable[[], Any]) -> None:
        """Load the handlers and make their writes follow the GUI rules (spec §6.2)."""
        from ghidra_headless.gui.write_boundary import install_gui_write_boundary
        from ghidra_mcp.domain.policies import get_lock_timeout_seconds

        load_core()
        install_gui_write_boundary(lock_timeout_seconds=get_lock_timeout_seconds())

    def run(self, serve: Callable[[], None]) -> int:
        """Serve MCP on its own thread and run the GUI on this (main) thread; the exit code if the GUI never ran."""
        self._watch_signals()
        self._server_thread = threading.Thread(target=self._serve, args=(serve,), name="mcp-server", daemon=True)
        self._server_thread.start()
        self.launch.run()
        # Back here only when the GUI was not started (a failed check), or the JVM is exiting.
        if self.launch.failure is None:
            self.status.stop.set()
            self._await_jvm_exit()
            return 0
        # The startup thread reports the failure to every call, then stops the server.
        self._server_stopped.wait(_SERVER_STOP_SECONDS)
        return 1

    @staticmethod
    def _await_jvm_exit() -> None:
        """Let Ghidra's ``System.exit`` end the process instead of returning to the CLI's cleanup.

        The JVM ends the process once its shutdown hooks have run.  The cleanup
        would call into the JVM meanwhile, and a call that fails then makes
        JPype abort the process.  Ghidra has closed the programs and the project
        itself, so nothing is left for Python to close.
        """
        threading.Event().wait(_JVM_EXIT_SECONDS)
        logger.warning("The JVM did not end the process %g s after Ghidra exited; exiting", _JVM_EXIT_SECONDS)
        logging.shutdown()
        os._exit(0)

    def stop(self) -> None:
        """Stop the startup waits (the server is shutting down)."""
        self.status.stop.set()

    def watch_project_closure(self, on_closed: Callable[[], None]) -> None:
        """Call ``on_closed`` once the human closes this runtime's project or opens another (spec §5.1).

        The runtime is CLOSED from then on: its registry record goes, so a new
        relay starts a new runtime, while this process stays a plain Ghidra
        until the human exits it.  Started once the startup is ready.
        """

        def watch() -> None:
            from ghidra_headless.gui.project_handle import runtime_project

            while not self.status.stop.wait(_CLOSURE_POLL_SECONDS):
                try:
                    closed = runtime_project() is None
                except Exception:  # the JVM is going down
                    return
                if closed:
                    logger.info("The Ghidra GUI closed this server's project: the runtime is CLOSED")
                    on_closed()
                    return

        threading.Thread(target=watch, name="gui-project-closure", daemon=True).start()

    def ghidra_is_running(self) -> bool:
        """Whether GhidraRun started: a later startup failure leaves the GUI up, and the server keeps
        answering every call with STARTUP_FAILED until the human exits Ghidra (spec §12)."""
        return self.launch.ghidra_run_started.is_set()

    def _serve(self, serve: Callable[[], None]) -> None:
        try:
            serve()
        except BaseException:
            logger.exception("The MCP server stopped with an error")
        finally:
            self._server_stopped.set()
            self.status.stop.set()
            if not self.launch.abort() and not self.launch.finished.is_set():
                logger.error("The MCP server stopped; the Ghidra GUI stays open without it")

    def _watch_signals(self) -> None:
        """Route SIGINT, SIGTERM and SIGHUP to a watcher thread (spec §4.5).

        Python runs signal handlers on the main thread only, which the GUI
        holds (on macOS for good).  Python's C-level handler still writes each
        signal to the wakeup fd; the handlers themselves do nothing, so a
        signal is acted on once, by the watcher, on every OS.
        """
        read_fd, write_fd = os.pipe()
        os.set_blocking(write_fd, False)
        for signum in _SIGNALS:
            if signal.getsignal(signum) is not signal.SIG_IGN:
                signal.signal(signum, _ignore_signal)
        signal.set_wakeup_fd(write_fd, warn_on_full_buffer=False)
        threading.Thread(target=self._signal_watcher, args=(read_fd,), name="gui-signals", daemon=True).start()

    def _signal_watcher(self, read_fd: int) -> None:
        while True:
            try:
                received = os.read(read_fd, 64)
            except OSError:
                return
            for number in received:
                self._on_signal(number)

    def _on_signal(self, number: int) -> None:
        try:
            name = signal.Signals(number).name
        except ValueError:
            return
        if number == signal.SIGHUP:
            # The terminal is gone: the GUI keeps running, and nothing is written to the terminal any more
            # (spec §4.5).  This version keeps no log file, so later log lines are dropped.
            logger.info("Received SIGHUP: the Ghidra GUI keeps running; terminal output stops")
            _detach_from_terminal()
            return
        if number not in (signal.SIGINT, signal.SIGTERM):
            return
        if self.launch.ghidra_run_started.is_set():
            try:
                if request_gui_exit():
                    logger.info("Received %s: asking the Ghidra GUI to exit (it may ask about unsaved changes)", name)
                    return
            except Exception:
                logger.exception("Could not ask the Ghidra GUI to exit")
        # Before the GUI's project window exists there is nothing to save.
        logger.info("Received %s before the Ghidra GUI was up: exiting", name)
        os._exit(128 + number)


if __name__ == "__main__":
    # The Ghidra GUI runtime a relay starts detached (spec §4.1, §10.6): not a public entry point.
    from ghidra_mcp.presentation.cli import main

    sys.exit(main(sys.argv[1:], detached=True))
