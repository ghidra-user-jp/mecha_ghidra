"""Programs owned by the GUI's ProgramManager: find, open (spec §5.2) and save (spec §6.4)."""

from __future__ import annotations

import logging
import threading
import time

from ghidra_headless.errors import HeadlessError

from .edt import is_edt_busy, modal_dialog_titles, post_to_edt, run_on_edt

logger = logging.getLogger(__name__)

# How long a load waits for the GUI to register a program it was asked to open.
OPEN_REGISTRATION_TIMEOUT_SECONDS = 30.0
# How long a load waits for a CodeBrowser it had to start.
TOOL_LAUNCH_TIMEOUT_SECONDS = 30.0
# How long a wait goes on, dialogs aside, while the work it posted keeps the EDT
# busy: a slow machine takes the EDT for tens of seconds to open a program or a
# tool, and posted work cannot be taken back once it runs.
POSTED_WORK_LIMIT_SECONDS = 300.0
# How long a load that registered its program waits for the open to end or for its prompt.
PROMPT_SETTLE_SECONDS = 2.0
# How long a save waits for the program to show no unsaved changes.
SAVE_TIMEOUT_SECONDS = 120.0
_POLL_SECONDS = 0.05


class PostedWork:
    """Work posted to the EDT that its caller waits for: begun, ended, or given up before it began.

    Once the work runs it cannot be taken back, so a caller that stops waiting
    gives it up only if it has not begun (``abandon``); it then does nothing
    when its turn comes, and no program or tool opens after the caller's error.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._abandoned = False
        self.started = False
        self.done = False

    def begin(self) -> bool:
        """The work's first step, on the EDT: False if the caller gave it up (do nothing then)."""
        with self._lock:
            if self._abandoned:
                return False
            self.started = True
            return True

    def end(self) -> None:
        self.done = True

    def abandon(self) -> bool:
        """Give up the work if it has not begun; False if it runs or ran."""
        with self._lock:
            if not self.started:
                self._abandoned = True
            return self._abandoned

    @property
    def running(self) -> bool:
        return self.started and not self.done


class DialogAwareDeadline:
    """A deadline that stops counting while a human answers a modal dialog, or while the caller's work runs.

    Opening a program or a tool can ask first (a checkout, crash recovery, an
    upgrade, new plugins); the wait resumes counting once no dialog is up.
    While ``work`` keeps the EDT busy with no dialog up, the wait goes on for
    up to POSTED_WORK_LIMIT_SECONDS instead: ending it then would leave the
    work to finish unobserved.
    """

    def __init__(self, seconds: float, *, work: PostedWork | None = None) -> None:
        self._left = float(seconds)
        self._busy_left = POSTED_WORK_LIMIT_SECONDS
        self._last = time.monotonic()
        self._work = work

    def expired(self) -> bool:
        now = time.monotonic()
        elapsed, self._last = now - self._last, now
        if not modal_dialog_titles():
            if self._work is not None and self._work.running:
                self._busy_left -= elapsed
            else:
                self._left -= elapsed
        return self._left <= 0 or self._busy_left <= 0


def running_program_tools(project) -> list:
    """The running tools that manage programs (CodeBrowser-like), CodeBrowsers first."""
    from ghidra.app.services import ProgramManager

    tools = []
    for tool in project.getToolManager().getRunningTools():
        if tool.getService(ProgramManager) is not None:
            tools.append(tool)
    # The tool's kind, not its instance name ("CodeBrowser(2)" for a second one).
    tools.sort(key=lambda tool: 0 if str(tool.getToolName()) == "CodeBrowser" else 1)
    return tools


def _open_programs(tool) -> list:
    from ghidra.app.services import ProgramManager

    manager = tool.getService(ProgramManager)
    return [] if manager is None else list(run_on_edt(lambda: list(manager.getAllOpenPrograms())))


def _same_file(program, domain_file) -> bool:
    """The project's own file, not a past version (a proxy) or another project's file at the same path."""
    try:
        program_file = program.getDomainFile()
    except Exception:
        return False
    return program_file is not None and bool(program_file.equals(domain_file))


def find_open_program(project, domain_file):
    """The Program for ``domain_file`` that a GUI tool has open, and that tool; (None, None) if none."""
    for tool in running_program_tools(project):
        for program in _open_programs(tool):
            if _same_file(program, domain_file) and not program.isClosed():
                return program, tool
    return None, None


def is_open_in_gui(project, program) -> bool:
    """Whether some GUI tool still has ``program`` open (spec §5.2: otherwise the target has expired)."""
    try:
        if program.isClosed():
            return False
    except Exception:
        return False
    for tool in running_program_tools(project):
        if any(candidate == program for candidate in _open_programs(tool)):
            return True
    return False


def ensure_code_browser(
    project, *, timeout: float = TOOL_LAUNCH_TIMEOUT_SECONDS, failure_code: str = "PROGRAM_OPEN_FAILED"
):
    """The first running CodeBrowser-like tool, launching the default one if none runs.

    The launch is posted, not waited for: a new tool can show a modal dialog
    while it comes up ("New Plugins Found!", "Error Restoring Plugins"), and
    the caller holds Mecha's locks.  The tool counts once the project lists it
    as running; a dialog it shows then waits for the human, not for us.
    """
    tools = running_program_tools(project)
    if tools:
        return tools[0]
    from java.util import List as JList

    launched: dict[str, object] = {}
    work = PostedWork()

    def launch(launched: dict[str, object] = launched) -> None:
        if not work.begin():
            return
        try:
            launched["tool"] = project.getToolServices().launchTool("CodeBrowser", JList.of())
        finally:
            launched.setdefault("tool", None)
            work.end()

    post_to_edt(launch, label="Starting a CodeBrowser in the Ghidra GUI")
    deadline = DialogAwareDeadline(timeout, work=work)
    while not deadline.expired():
        tools = running_program_tools(project)
        if tools:
            return tools[0]
        if work.done and launched.get("tool") is None:
            break  # the launch ended without a tool
        time.sleep(_POLL_SECONDS)
    work.abandon()  # a launch that has not begun never will
    dialogs = modal_dialog_titles()
    raise HeadlessError(
        f"{failure_code}: the Ghidra GUI did not start a CodeBrowser"
        + (f" (modal dialogs: {', '.join(dialogs)})" if dialogs else ""),
        details={"modal_dialogs": dialogs},
    )


def open_in_gui(project, domain_file, *, timeout: float = OPEN_REGISTRATION_TIMEOUT_SECONDS):
    """The GUI's Program for ``domain_file``, opening it as a CodeBrowser tab if no tool has it.

    The tab opens with ``OPEN_VISIBLE``, so the human's current tab stays
    (a tool's first program becomes current anyway).  The open is posted to
    the EDT and not waited for: opening an unanalyzed program shows the
    auto-analysis prompt inside the open call.  The load returns once the
    ProgramManager has registered the program.  While the open itself keeps
    the EDT busy, a look at the ProgramManager may not get its turn: the wait
    goes on (see ``DialogAwareDeadline``).
    """
    program, _tool = find_open_program(project, domain_file)
    if program is not None:
        return program
    from ghidra.app.services import ProgramManager
    from ghidra.framework.model import DomainFile

    tool = ensure_code_browser(project)
    manager = tool.getService(ProgramManager)
    path = str(domain_file.getPathname())
    work = PostedWork()

    def open_tab() -> None:
        if not work.begin():
            return
        try:
            manager.openProgram(domain_file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE)
        finally:
            work.end()

    post_to_edt(open_tab, label=f"Opening {path} in the Ghidra GUI")
    deadline = DialogAwareDeadline(timeout, work=work)
    unseen = False  # the last look did not get the EDT's turn
    while not deadline.expired():
        done = work.done  # read before looking, so a registration just before it is not missed
        try:
            candidates = _open_programs(tool)
        except HeadlessError as exc:
            if not is_edt_busy(exc):
                raise
            unseen = True
            continue  # the EDT did not get to the look (the open, most likely, keeps it busy)
        unseen = False
        for candidate in candidates:
            if _same_file(candidate, domain_file):
                if not done:
                    _await_prompt_or_end(work)
                return candidate
        if done:
            break  # the open ended without registering the program (failed or cancelled)
        time.sleep(_POLL_SECONDS)
    abandoned = work.abandon()
    dialogs = modal_dialog_titles()
    if work.done:
        why = " (the GUI stayed too busy to show it)" if unseen else " (the open ended without it)"
    elif abandoned:
        why = f" within {timeout:g} s"  # it had not begun, and now never will
    else:
        why = f" while the GUI stayed busy opening it for {POSTED_WORK_LIMIT_SECONDS:g} s (it may still open)"
    raise HeadlessError(
        f"PROGRAM_OPEN_FAILED: the Ghidra GUI did not open {path}"
        + why
        + (f" (modal dialogs: {', '.join(dialogs)})" if dialogs else ""),
        details={"modal_dialogs": dialogs},
    )


def _await_prompt_or_end(work: PostedWork, seconds: float = PROMPT_SETTLE_SECONDS) -> None:
    """Registered, but the open is still running: a tool's first program becomes current and Ghidra may be
    about to ask whether to analyze it.  Wait a moment for that dialog or the end, so the load can name it."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not work.done and not modal_dialog_titles():
        time.sleep(_POLL_SECONDS)


def save_in_gui(project, program, *, timeout: float = SAVE_TIMEOUT_SECONDS) -> None:
    """Save ``program`` the way the GUI's File > Save does, and confirm it has no unsaved changes.

    Rule 1 first (spec §6.4): a save while another transaction is open makes
    Ghidra offer to force it ("Save Program (Busy)"), and forcing rolls that
    transaction back.  The EDT checks again right before saving.  A program
    that cannot be saved in place would make Ghidra ask for Save As; that is an
    error instead.
    """
    from ghidra_headless.session.write_boundary import write_boundary

    domain_file = program.getDomainFile()
    if not bool(program.canSave()) or domain_file is None or bool(domain_file.isReadOnly()):
        raise HeadlessError(
            "SAVE_FAILED: the program cannot be saved in place (read-only, or a version that is not checked out); "
            "use Save As in the Ghidra GUI"
        )
    tool = None
    for candidate in running_program_tools(project):
        if any(open_program == program for open_program in _open_programs(candidate)):
            tool = candidate
            break
    if tool is None:
        raise HeadlessError(
            "PROGRAM_NOT_OPEN: the program is no longer open in the Ghidra GUI", details={"reason": "closed_in_gui"}
        )
    from ghidra.app.services import ProgramManager

    manager = tool.getService(ProgramManager)
    deadline = time.monotonic() + timeout
    seen: list[str] = []
    while True:
        write_boundary().wait_until_idle(program)  # LOCK_TIMEOUT(program_transaction), nothing saved
        outcome: dict[str, object] = {}

        def save(outcome: dict[str, object] = outcome) -> None:
            busy = program.getCurrentTransactionInfo()
            if busy is not None:
                outcome["busy"] = str(busy.getDescription())
                return
            try:
                manager.saveProgram(program)
            finally:
                outcome["done"] = True

        post_to_edt(save, label=f"Saving {domain_file.getPathname()}")
        while not outcome and time.monotonic() < deadline:
            for title in modal_dialog_titles():
                if title not in seen:
                    seen.append(title)
            time.sleep(_POLL_SECONDS)
        if "busy" not in outcome:
            break
        if time.monotonic() >= deadline:
            raise HeadlessError(
                f"LOCK_TIMEOUT: the program has another transaction open ({outcome['busy']}); nothing was saved",
                details={"lock": "program_transaction", "transaction": outcome["busy"]},
            )
    if "done" not in outcome:
        raise HeadlessError(
            f"SAVE_FAILED: the Ghidra GUI did not finish saving within {timeout:g} s"
            + (f" (dialogs seen: {', '.join(seen)})" if seen else ""),
            details={"modal_dialogs": modal_dialog_titles()},
        )
    if bool(program.isChanged()):
        raise HeadlessError(
            "SAVE_FAILED: the Ghidra GUI's save ended with the program still changed (cancelled or failed; "
            "the server log has the GUI's error)" + (f" (dialogs seen: {', '.join(seen)})" if seen else ""),
            details={"modal_dialogs": modal_dialog_titles()},
        )
