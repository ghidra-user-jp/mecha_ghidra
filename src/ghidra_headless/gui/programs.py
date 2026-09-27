"""Programs owned by the GUI's ProgramManager: find, open (spec §5.2) and save (spec §6.4)."""

from __future__ import annotations

import logging
import time

from ghidra_headless.errors import HeadlessError

from .edt import modal_dialog_titles, post_to_edt, run_on_edt

logger = logging.getLogger(__name__)

# How long a load waits for the GUI to register a program it was asked to open.
OPEN_REGISTRATION_TIMEOUT_SECONDS = 30.0
# How long a load waits for a CodeBrowser it had to start.
TOOL_LAUNCH_TIMEOUT_SECONDS = 30.0
# How long a load that registered its program waits for the open to end or for its prompt.
PROMPT_SETTLE_SECONDS = 2.0
# How long a save waits for the program to show no unsaved changes.
SAVE_TIMEOUT_SECONDS = 120.0
_POLL_SECONDS = 0.05


class DialogAwareDeadline:
    """A deadline that stops counting while Ghidra shows a modal dialog: a human is answering it.

    Opening a program or a tool can ask first (a checkout, crash recovery, an
    upgrade, new plugins); the wait resumes counting once no dialog is up.
    """

    def __init__(self, seconds: float) -> None:
        self._left = float(seconds)
        self._last = time.monotonic()

    def expired(self) -> bool:
        now = time.monotonic()
        if not modal_dialog_titles():
            self._left -= now - self._last
        self._last = now
        return self._left <= 0


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

    def launch(launched: dict[str, object] = launched) -> None:
        try:
            launched["tool"] = project.getToolServices().launchTool("CodeBrowser", JList.of())
        finally:
            launched.setdefault("tool", None)

    post_to_edt(launch, label="Starting a CodeBrowser in the Ghidra GUI")
    deadline = DialogAwareDeadline(timeout)
    while not deadline.expired():
        tools = running_program_tools(project)
        if tools:
            return tools[0]
        if "tool" in launched and launched["tool"] is None:
            break  # the launch ended without a tool
        time.sleep(_POLL_SECONDS)
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
    ProgramManager has registered the program.
    """
    program, _tool = find_open_program(project, domain_file)
    if program is not None:
        return program
    from ghidra.app.services import ProgramManager
    from ghidra.framework.model import DomainFile

    tool = ensure_code_browser(project)
    manager = tool.getService(ProgramManager)
    path = str(domain_file.getPathname())
    opened: dict[str, object] = {}

    def open_tab(opened: dict[str, object] = opened) -> None:
        try:
            manager.openProgram(domain_file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE)
        finally:
            opened["done"] = True

    post_to_edt(open_tab, label=f"Opening {path} in the Ghidra GUI")
    deadline = DialogAwareDeadline(timeout)
    while not deadline.expired():
        done = "done" in opened  # read before looking, so a registration just before it is not missed
        for candidate in _open_programs(tool):
            if _same_file(candidate, domain_file):
                if not done:
                    _await_prompt_or_end(opened)
                return candidate
        if done:
            break  # the open ended without registering the program (failed or cancelled)
        time.sleep(_POLL_SECONDS)
    dialogs = modal_dialog_titles()
    raise HeadlessError(
        f"PROGRAM_OPEN_FAILED: the Ghidra GUI did not open {path}"
        + (" (the open ended without it)" if "done" in opened else f" within {timeout:g} s")
        + (f" (modal dialogs: {', '.join(dialogs)})" if dialogs else ""),
        details={"modal_dialogs": dialogs},
    )


def _await_prompt_or_end(opened: dict[str, object], seconds: float = PROMPT_SETTLE_SECONDS) -> None:
    """Registered, but the open is still running: a tool's first program becomes current and Ghidra may be
    about to ask whether to analyze it.  Wait a moment for that dialog or the end, so the load can name it."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and "done" not in opened and not modal_dialog_titles():
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
