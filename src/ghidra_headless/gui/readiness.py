"""The startup thread's checks while the Ghidra GUI comes up (spec §4.4, steps 10 and 11).

Each check waits for one thing (the JVM, the FrontEnd, the requested project,
a CodeBrowser) and meanwhile records the modal dialogs the GUI shows, such as
the user agreement, so a tool call that finds the server still starting can
say which dialog is waiting for the human.  None of the waits has a time
limit where a human may be answering a dialog: the server is serving
already, and calls get ``LOCK_TIMEOUT`` with the stage in the meantime.
"""

from __future__ import annotations

import logging
import threading
import time

from ghidra_headless.errors import HeadlessError

from .edt import modal_dialog_titles, run_on_edt
from .launch import GuiLaunch, launch_failure_error
from .programs import DialogAwareDeadline, ensure_code_browser
from .project_handle import active_gui_project, bind_runtime_project, is_same_project

logger = logging.getLogger(__name__)

_POLL_SECONDS = 0.1
# The JVM start and Ghidra's class search take seconds; a JVM that is not up
# after this long did not start.
JVM_START_TIMEOUT_SECONDS = 300.0
# How long the FrontEnd may be up with no project, no dialog and no progress
# before the GUI is taken to have failed to open the project.
PROJECT_OPEN_GRACE_SECONDS = 60.0
# How long the EDT may take to finish opening the project (restoring its tools).
OPEN_STEP_TIMEOUT_SECONDS = 300.0
# How long GhidraRun may show neither its FrontEnd nor a dialog, once its own startup thread has ended,
# before it is taken to have failed.
FRONT_END_GRACE_SECONDS = 180.0
# How often the FrontEnd wait looks for GhidraRun's startup thread before it has found it.
_STARTUP_THREAD_LOOK_SECONDS = 1.0


class StartupStopped(Exception):
    """The server is shutting down; the startup must not wait any longer."""


class GuiStartupStatus:
    """What the GUI shows while starting (the modal dialogs), and the flag that stops the waits."""

    def __init__(self) -> None:
        self.stop = threading.Event()

    @staticmethod
    def update() -> list[str]:
        """The modal dialogs on screen now; a wait counts them as progress (a human is answering)."""
        return modal_dialog_titles()

    def details(self) -> dict[str, object]:
        """Read when a call finds the server still starting: the dialogs on screen now, in any step."""
        dialogs = modal_dialog_titles()
        return {"modal_dialogs": dialogs} if dialogs else {}


def _check_stop(status: GuiStartupStatus) -> None:
    if status.stop.is_set():
        raise StartupStopped


def wait_for_jvm(launch: GuiLaunch, status: GuiStartupStatus) -> None:
    """The main thread started the JVM and PyGhidra's class loader is in place."""
    deadline = time.monotonic() + JVM_START_TIMEOUT_SECONDS
    while not launch.jvm_ready.wait(_POLL_SECONDS):
        if launch.finished.is_set():
            break
        _check_stop(status)
        if time.monotonic() > deadline:
            raise HeadlessError(f"STARTUP_FAILED: the JVM did not start within {JVM_START_TIMEOUT_SECONDS:g} s")
    failure = launch.failure
    if failure is not None and failure.stage == "gui":
        raise launch_failure_error(failure)
    if not launch.jvm_ready.is_set():
        raise HeadlessError("STARTUP_FAILED: the Ghidra GUI launcher ended before the JVM started")


def wait_for_check(launch: GuiLaunch, status: GuiStartupStatus, stage: str) -> None:
    """The main thread's check for ``stage`` (``display`` or ``project_lock``) passed."""
    while not launch.checks_passed.wait(_POLL_SECONDS):
        # The launcher's own outcome first: it may end the server right after failing.
        failure = launch.failure
        if failure is not None:
            if stage == "display" and failure.stage == "project_lock":
                return  # the display check passed; the next step reports the lock
            raise launch_failure_error(failure)
        if launch.finished.is_set():
            raise HeadlessError("STARTUP_FAILED: the Ghidra GUI launcher ended before GhidraRun")
        _check_stop(status)


class _GhidraStartupThread:
    """GhidraRun's own "Ghidra" thread, which initializes the application before it posts the FrontEnd.

    ``GhidraRun.launch`` starts it in a ``GhidraThreadGroup``; while it runs,
    Ghidra is still starting (the class search alone takes seconds, minutes on
    a slow machine), so the FrontEnd wait counts it as progress.
    """

    def __init__(self) -> None:
        self._thread = None
        self._looked = 0.0

    def running(self) -> bool:
        if self._thread is None and time.monotonic() - self._looked >= _STARTUP_THREAD_LOOK_SECONDS:
            self._looked = time.monotonic()
            self._thread = _find_ghidra_startup_thread()
        return self._thread is not None and bool(self._thread.isAlive())


def _find_ghidra_startup_thread():
    from java.lang import Thread

    for thread in Thread.getAllStackTraces().keySet():
        group = thread.getThreadGroup()
        if str(thread.getName()) == "Ghidra" and group is not None and "GhidraThreadGroup" in str(group.getClass()):
            return thread
    return None


def wait_for_front_end(status: GuiStartupStatus, launch: GuiLaunch):
    """Ghidra's FrontEnd (the project window) exists; dialogs before it, such as the user agreement, may wait.

    GhidraRun runs on a Java thread whose failure never reaches the launcher,
    so a long stretch with neither the FrontEnd, a dialog, nor GhidraRun's
    startup thread at work is a failure too.
    """
    from ghidra.framework.main import AppInfo

    startup_thread = _GhidraStartupThread()
    quiet_since = time.monotonic()
    while True:
        _check_stop(status)
        failure = launch.failure
        if failure is not None:
            raise launch_failure_error(failure)
        if launch.finished.is_set():
            raise HeadlessError("STARTUP_FAILED: the Ghidra GUI launcher ended before the FrontEnd appeared")
        try:
            front_end = AppInfo.getFrontEndTool()
        except Exception:
            front_end = None
        if front_end is not None:
            return front_end
        if status.update() or startup_thread.running():
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since > FRONT_END_GRACE_SECONDS:
            raise HeadlessError(
                f"STARTUP_FAILED: the Ghidra GUI showed no project window within {FRONT_END_GRACE_SECONDS:g} s "
                "after its startup thread ended; the server log has GhidraRun's error"
            )
        time.sleep(_POLL_SECONDS)


def wait_for_project(status: GuiStartupStatus, project_location: str, project_name: str):
    """The GUI's active project is the requested one (spec §4.4, step 10; STARTUP_FAILED stage project_open)."""
    quiet_since = time.monotonic()
    while True:
        _check_stop(status)
        project = active_gui_project()
        if project is not None:
            if not is_same_project(project, project_location, project_name):
                raise HeadlessError(
                    f"STARTUP_FAILED: the Ghidra GUI opened the project {project.getProjectLocator().getName()} "
                    f"instead of {project_name}"
                )
            # GhidraRun opens the project on the EDT and restores the tools that
            # were running at the last exit in the same step; the project can be
            # seen before that step ends.  Waiting for the EDT once more lets the
            # restore finish, so the next step does not start a second CodeBrowser.
            run_on_edt(lambda: None, start_timeout=OPEN_STEP_TIMEOUT_SECONDS)
            _wait_for_workspace(status, project)
            bind_runtime_project(project)
            return project
        if status.update():
            quiet_since = time.monotonic()
        elif time.monotonic() - quiet_since > PROJECT_OPEN_GRACE_SECONDS:
            raise HeadlessError(
                f"STARTUP_FAILED: the Ghidra GUI did not open the project {project_name} "
                f"within {PROJECT_OPEN_GRACE_SECONDS:g} s"
            )
        time.sleep(_POLL_SECONDS)


def _wait_for_workspace(status: GuiStartupStatus, project) -> None:
    """The project's restore has set its active workspace, which launching a tool needs.

    The round trip above is not enough when opening takes long: Ghidra's
    "Opening Project" dialog then runs a modal event loop, which serves the
    round trip before the restore ends.  The restore sets the active workspace
    last, after the tools it brings back (``ToolManagerImpl.restoreFromXml``).
    """
    # The restore can ask first (crash recovery, an upgrade, the analysis prompt): no limit while it does.
    deadline = DialogAwareDeadline(OPEN_STEP_TIMEOUT_SECONDS)
    while True:
        tool_manager = project.getToolManager()
        if tool_manager is None or tool_manager.getActiveWorkspace() is not None:
            return
        _check_stop(status)
        if deadline.expired():
            raise HeadlessError(
                f"STARTUP_FAILED: the Ghidra GUI did not finish opening the project {project.getName()} "
                f"within {OPEN_STEP_TIMEOUT_SECONDS:g} s"
            )
        status.update()
        time.sleep(_POLL_SECONDS)


def wait_for_code_browser(status: GuiStartupStatus, project) -> None:
    """A CodeBrowser-like tool runs, the one AI loads open in (launched if needed)."""
    _check_stop(status)
    tool = ensure_code_browser(project, timeout=OPEN_STEP_TIMEOUT_SECONDS, failure_code="STARTUP_FAILED")
    logger.info("Ghidra GUI ready: project %s, tool %s", project.getName(), tool.getName())
