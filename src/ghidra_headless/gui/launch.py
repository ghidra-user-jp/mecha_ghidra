"""Start Ghidra's GUI in this process, on the Python main thread (spec §4.4, steps 5 to 9).

This is the one exception to ``ghidra_headless.launcher``'s rule that every
JVM starts headless: the GUI backend needs AWT, so the JVM starts without
``-Djava.awt.headless=true``.  It still starts with ``-Xrs``, so SIGINT,
SIGTERM and SIGHUP stay with Python.

PyGhidra's ``GuiPyGhidraLauncher`` starts the JVM and then, in ``_launch``,
runs ``ghidra.GhidraRun`` on a Java thread and parks the main thread: in
macOS's CFRunLoop, which AppKit needs and which never returns, and elsewhere
in a wait for the JVM to exit.  ``_launch`` is a private PyGhidra name, so it
is overridden only here (checked with PyGhidra 3.2.0): the override runs the
display check and the project-lock check before GhidraRun, because GhidraRun
exits the process without a display and only shows a dialog for a locked
project.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from ghidra_headless.errors import HeadlessError
from ghidra_headless.launcher import REDUCE_SIGNAL_USAGE_VM_ARG

from .edt import plain_text

logger = logging.getLogger(__name__)

# The name the Dock and the menu bar show on macOS; otherwise a Python that is
# not a framework build shows its bin directory's name (spec §16.1, S1c).
APP_NAME = "Ghidra (Mecha)"
APP_NAME_VM_ARG = f"-Dapple.awt.application.name={APP_NAME}"


@dataclass(frozen=True, slots=True)
class LaunchFailure:
    """Why the GUI was not started: the startup stage and the message."""

    stage: str
    message: str
    code: str


class GuiLaunch:
    """The GUI's start on the main thread, and what the startup thread waits for.

    ``run`` blocks the calling (main) thread for the life of the GUI.  The
    events tell the startup thread how far it got: the JVM is up (Ghidra
    classes import), the display and project-lock checks passed, GhidraRun
    started.  A check that fails sets ``failure`` and ``finished`` instead,
    and ``run`` returns without starting GhidraRun.
    """

    def __init__(self, install_dir: str | None, *, project_location: str, project_name: str) -> None:
        self.install_dir = install_dir
        self.project_location = project_location
        self.project_name = project_name
        self.jvm_ready = threading.Event()
        self.checks_passed = threading.Event()
        self.ghidra_run_started = threading.Event()
        self.finished = threading.Event()
        self._abort = threading.Event()
        self._lock = threading.Lock()
        self._failure: LaunchFailure | None = None
        self._launcher = None

    @property
    def gpr_path(self) -> Path:
        return Path(self.project_location) / f"{self.project_name}.gpr"

    @property
    def failure(self) -> LaunchFailure | None:
        with self._lock:
            return self._failure

    def prepare(self) -> None:
        """Build the launcher and check the Ghidra version; no JVM yet."""
        self._launcher = _launcher_class()(install_dir=self.install_dir, gui_launch=self)
        self._launcher.add_vmargs(REDUCE_SIGNAL_USAGE_VM_ARG)
        if sys.platform == "darwin":
            self._launcher.add_vmargs(APP_NAME_VM_ARG)
        self._launcher.args = [str(self.gpr_path)]
        self._launcher.check_ghidra_version()

    def abort(self) -> bool:
        """Do not start GhidraRun if it has not started yet (the MCP server stopped first); whether in time."""
        with self._lock:
            self._abort.set()
            return not self.ghidra_run_started.is_set()

    def run(self) -> None:
        """Start the JVM and the GUI on this thread; returns only if the GUI was not started or has ended."""
        if self._launcher is None:
            self.prepare()
        try:
            self._launcher.start()
        except Exception as exc:  # the JVM did not start: the startup thread reports it to every call
            logger.exception("The Ghidra GUI launcher failed")
            self._launch_failed(str(exc))
        finally:
            self.finished.set()

    def _fail(self, failure: LaunchFailure) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = failure
        logger.error("%s", failure.message)
        self.finished.set()

    def _before_ghidra_run(self) -> bool:
        """On the main thread, with the JVM up: run the checks; True to go on with GhidraRun."""
        self.jvm_ready.set()
        try:
            problem = display_problem()
        except Exception as exc:
            problem = f"could not check the display: {exc}"
        if problem is not None:
            self._fail(LaunchFailure("display", f"No display for the Ghidra GUI: {problem}", "STARTUP_FAILED"))
            return False
        try:
            lock_problem = project_lock_problem(self.project_location, self.project_name)
        except Exception as exc:
            lock_problem = ("STARTUP_FAILED", f"could not check the project lock: {exc}")
        if lock_problem is not None:
            code, problem = lock_problem
            message = f"PROJECT_LOCKED: {problem}" if code == "PROJECT_LOCKED" else problem
            self._fail(LaunchFailure("project_lock", message, code))
            return False
        with self._lock:  # abort() either sees GhidraRun started or keeps it from starting
            aborted = self._abort.is_set()
            if not aborted:
                self.checks_passed.set()
                self.ghidra_run_started.set()
        if aborted:
            self._fail(LaunchFailure("gui", "The MCP server stopped before the Ghidra GUI started", "STARTUP_FAILED"))
            return False
        logger.info("Starting the Ghidra GUI with project %s", self.gpr_path)
        return True

    def _launch_failed(self, message: str) -> None:
        self._fail(LaunchFailure("gui", f"The Ghidra GUI could not start: {message}", "STARTUP_FAILED"))


def _launcher_class():
    from pyghidra.launcher import GuiPyGhidraLauncher

    class _MechaGuiLauncher(GuiPyGhidraLauncher):
        """GuiPyGhidraLauncher with the checks before GhidraRun and no Tk error dialog."""

        def __init__(self, *args, gui_launch: GuiLaunch, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self._gui_launch = gui_launch

        def _launch(self) -> None:
            if self._gui_launch._before_ghidra_run():
                super()._launch()

        @classmethod
        def _report_fatal_error(cls, title: str, msg: str, cause: Exception) -> NoReturn:
            # PyGhidra's GUI launcher shows a Tk dialog and exits; the server
            # reports the failure instead.  PyGhidra calls this from class
            # methods too (_validate_install_dir) and relies on it not returning.
            logger.error("%s: %s", title, msg)
            raise cause

    return _MechaGuiLauncher


def display_problem() -> str | None:
    """Why the GUI cannot show a window here, or None (spec §4.4, step 6).

    ``isHeadless()`` is false whenever ``DISPLAY`` is set on Linux, even when
    no X server answers; GhidraRun then neither exits nor shows a window.  So
    the screen devices are opened too.  On macOS that would start AppKit
    before the main thread runs its loop, so the window server session is
    asked instead.
    """
    from java.awt import GraphicsEnvironment

    if bool(GraphicsEnvironment.isHeadless()):
        return "Java reports no display (java.awt.GraphicsEnvironment.isHeadless() is true; check DISPLAY)"
    if sys.platform == "darwin":
        return None if _macos_window_server_session() else "this process has no macOS window server session"
    try:
        devices = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices()
    except BaseException as exc:  # java.awt.AWTError is an Error, not an Exception
        return f"the display cannot be opened: {exc}"
    return None if len(devices) else "the display has no screen"


def _macos_window_server_session() -> bool:
    """Whether this process can reach the macOS window server (CGSessionCopyCurrentDictionary)."""
    path = ctypes.util.find_library("CoreGraphics") or ctypes.util.find_library("ApplicationServices")
    if path is None:
        return True  # cannot tell; let Ghidra try
    core_graphics = ctypes.cdll.LoadLibrary(path)
    copy_session = core_graphics.CGSessionCopyCurrentDictionary
    copy_session.restype = ctypes.c_void_p
    session = copy_session()
    if not session:
        return False
    core_foundation = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))
    core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
    core_foundation.CFRelease(session)
    return True


def project_lock_problem(project_location: str, project_name: str) -> tuple[str, str] | None:
    """Try Ghidra's project lock and release it at once; (code, why) when it fails, or None (spec §4.4, step 7).

    The code is PROJECT_LOCKED when another process holds the lock, and
    STARTUP_FAILED when no lock file can be written (a read-only directory).

    Uses the lock Ghidra itself takes (``ProjectLock`` delegates to the same
    ``FileLocker``).  A lock file left by a process that died holds no channel
    lock, so it is taken over, as Ghidra does when it opens the project.

    This runs before GhidraRun has initialized Ghidra's ``Application``, so no
    ``ProjectLocator`` yet (it builds a ghidra: URL): the lock file is
    ``<location>/<name>.lock``, as ``ProjectLocator.getProjectLockFile`` names
    it.  The lock file records an ID, so the ID generator is initialized first
    (GhidraRun's own initialization then leaves it as it is).
    """
    from generic.util import LockFactory
    from ghidra.util import UniversalIdGenerator
    from java.io import File

    UniversalIdGenerator.initialize()
    lock_file = File(project_location, f"{project_name}.lock")
    locker = LockFactory.createFileLocker(lock_file)
    if bool(locker.lock()):
        locker.release()
        return None
    if not bool(lock_file.exists()):
        return (
            "STARTUP_FAILED",
            f"cannot create the lock file of the project {project_name}; check that its directory is writable",
        )
    holder = plain_text(str(locker.getExistingLockFileInformation() or ""))
    if holder:
        return ("PROJECT_LOCKED", f"the project {project_name} is open in another process ({holder})")
    return ("PROJECT_LOCKED", f"the project {project_name} is open in another process")


def request_gui_exit() -> bool:
    """Ask Ghidra to exit the way File > Exit does (it asks about unsaved changes); False before the FrontEnd exists.

    ``FrontEndTool.close()`` checks running tasks, plugins and unsaved programs
    first, and the human can cancel (spec §4.5).
    """
    from ghidra.framework.main import AppInfo

    from .edt import post_to_edt

    try:
        front_end = AppInfo.getFrontEndTool()
    except Exception:  # AppInfo asserts there is one; there is none before GhidraRun made it
        return False
    if front_end is None:
        return False
    if not _EXIT_REQUEST.begin():
        return True  # Ghidra is already asking about this exit; a second prompt would stack on it

    def close() -> None:
        try:
            front_end.close()
        finally:
            _EXIT_REQUEST.end()  # cancelled, or the JVM is exiting

    post_to_edt(close, label="Closing the Ghidra GUI")
    return True


class _ExitRequest:
    """Whether a posted FrontEndTool.close() is still running (its prompt may be up)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending = False

    def begin(self) -> bool:
        with self._lock:
            if self._pending:
                return False
            self._pending = True
            return True

    def end(self) -> None:
        with self._lock:
            self._pending = False


_EXIT_REQUEST = _ExitRequest()


def launch_failure_error(failure: LaunchFailure) -> HeadlessError:
    """The error the startup step raises for ``failure`` (its code is the cause the gate reports)."""
    if failure.code == "PROJECT_LOCKED":
        return HeadlessError(failure.message)
    return HeadlessError(f"STARTUP_FAILED: {failure.message}")
