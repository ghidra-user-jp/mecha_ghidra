"""What the GUI shows, and showing a target's program there (spec §8 ``show_in_gui``, §9 ``get_gui_context``).

Reading GUI state runs on the EDT with ``run_on_edt`` (short, no dialogs).
Changing the view is posted with ``post_to_edt`` and then confirmed with a
bounded poll, because selecting a program can open the auto-analysis prompt.
Neither changes the program, saves, starts analysis or rebinds a target.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from ghidra_headless.errors import HeadlessError

from .edt import modal_dialog_titles, post_to_edt, run_on_edt
from .programs import running_program_tools

# How long show_in_gui waits for the GUI to show what it asked for.
SHOW_CONFIRM_SECONDS = 5.0
_POLL_SECONDS = 0.05
# get_gui_context's selection summary stays small.
SELECTION_RANGE_LIMIT = 8


class _ToolIds:
    """Runtime-stable ``tool-N`` ids for GUI tool instances (a tool's name can repeat)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ids: list[tuple[Any, str]] = []

    def of(self, tool) -> str:
        with self._lock:
            for known, tool_id in self._ids:
                if known is tool or known == tool:
                    return tool_id
            tool_id = f"tool-{len(self._ids) + 1}"
            self._ids.append((tool, tool_id))
            return tool_id


_TOOL_IDS = _ToolIds()
# The tool show_in_gui last used, per program path: shown there again (spec §8.2).
_LAST_TOOL: dict[str, Any] = {}


def _first_dialog() -> str | None:
    dialogs = modal_dialog_titles()
    return dialogs[0] if dialogs else None


def _manager(tool):
    from ghidra.app.services import ProgramManager

    return tool.getService(ProgramManager)


def _code_viewer(tool):
    from ghidra.app.services import CodeViewerService

    return tool.getService(CodeViewerService)


def _program_path(program) -> str | None:
    try:
        domain_file = program.getDomainFile()
    except Exception:
        return None
    return None if domain_file is None else str(domain_file.getPathname())


def _describe_tool(tool) -> dict[str, Any]:
    manager = _manager(tool)
    current = None if manager is None else manager.getCurrentProgram()
    return {
        "tool": str(tool.getName()),
        "tool_id": _TOOL_IDS.of(tool),
        "program": None if current is None else _program_path(current),
    }


def _active_tool(tools: list):
    """The tool with the active window, or else the visible one the human used last.

    The human usually talks to the AI in another application, and then no
    Ghidra window is active; Ghidra's docking managers still record the order
    in which their windows were last active.
    """
    from docking import DockingWindowManager
    from java.awt import KeyboardFocusManager

    active_window = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow()
    if active_window is not None:
        for tool in tools:
            try:
                frame = tool.getToolFrame()
            except Exception:
                continue
            if frame is not None and (frame == active_window or active_window.getOwner() == frame):
                return tool
    # Ordered from least to most recently active.
    for manager in reversed(list(DockingWindowManager.getAllDockingWindowManagers())):
        for tool in tools:
            if tool.getWindowManager() == manager and bool(tool.isVisible()):
                return tool
    return None


def _location_of(tool, program) -> dict[str, Any] | None:
    viewer = _code_viewer(tool)
    location = None if viewer is None else viewer.getCurrentLocation()
    if location is None or location.getProgram() != program:
        return None
    address = location.getAddress()
    function = program.getFunctionManager().getFunctionContaining(address)
    return {
        "address": str(address),
        "function": None
        if function is None
        else {"name": str(function.getName(True)), "entry": str(function.getEntryPoint())},
    }


def _selection_of(tool, program) -> dict[str, Any] | None:
    viewer = _code_viewer(tool)
    selection = None if viewer is None else viewer.getCurrentSelection()
    if selection is None or selection.isEmpty() or getattr(selection, "getNumAddressRanges", None) is None:
        return None
    ranges = []
    iterator = selection.getAddressRanges()
    while iterator.hasNext() and len(ranges) < SELECTION_RANGE_LIMIT:
        address_range = iterator.next()
        ranges.append({"start": str(address_range.getMinAddress()), "end": str(address_range.getMaxAddress())})
    return {
        "range_count": int(selection.getNumAddressRanges()),
        "ranges": ranges,
        "truncated": int(selection.getNumAddressRanges()) > len(ranges),
        "size": int(selection.getNumAddresses()),
    }


def gui_context(project, targets_for) -> dict[str, Any]:
    """What the human sees: tools, the active tool's program and location (spec §9).

    ``targets_for(program)`` names the targets bound to a program and their
    revisions.  Nothing is loaded, selected or rebound.
    """

    def read() -> dict[str, Any]:
        tools = running_program_tools(project)
        active = _active_tool(tools)
        program = None
        if active is not None:
            manager = _manager(active)
            program = None if manager is None else manager.getCurrentProgram()
        context: dict[str, Any] = {
            "tools": [_describe_tool(tool) for tool in tools],
            "active_tool": None if active is None else _describe_tool(active),
            "active_known": active is not None,
            "program": None
            if program is None
            else {"domain_path": _program_path(program), "name": str(program.getName())},
            "location": None if program is None else _location_of(active, program),
            "selection": None if program is None else _selection_of(active, program),
        }
        context["_program"] = program
        return context

    context = run_on_edt(read)
    program = context.pop("_program")
    targets = [] if program is None else targets_for(program)
    context["targets"] = [target["target"] for target in targets]
    context["revision"] = targets[0]["revision"] if targets else None
    context["modal_dialog"] = _first_dialog()
    return context


def resolve_location(program, *, address: str | None, name: str | None, find_function_by_name):
    """The address ``address`` names in ``program``, or ``name``'s entry; None if neither (validated before showing)."""
    if address:
        resolved = program.getAddressFactory().getAddress(address)
        if resolved is None:
            raise HeadlessError(f"VALIDATION_ERROR: Invalid address: {address}")
        if not program.getMemory().contains(resolved):
            raise HeadlessError(f"NOT_FOUND: address {address} is not in the program's memory")
        return resolved
    if name:
        function = find_function_by_name(name)
        if function is None:
            raise HeadlessError(f"NOT_FOUND: Function not found: {name}")
        return function.getEntryPoint()
    return None


def show_program(project, program, *, address=None, requested: dict[str, Any], target: str) -> dict[str, Any]:
    """Show ``program`` (and ``address``) in a CodeBrowser, adding a tab only if no tool has it (spec §8.2)."""
    from ghidra.app.services import ProgramManager

    path = _program_path(program)
    tools = running_program_tools(project)
    showing = [tool for tool in tools if any(open_program == program for open_program in _open_programs(tool))]
    remembered = _LAST_TOOL.get(path or "")
    tool = remembered if remembered is not None and remembered in showing else (showing[0] if showing else None)
    created_tab = launched_tool = False
    if tool is None:
        from .programs import ensure_code_browser

        launched_tool = not tools
        tool = ensure_code_browser(project)
        manager = _manager(tool)
        # The target's own object, which the caller holds open: no second copy of the file.
        post_to_edt(
            lambda: manager.openProgram(program, ProgramManager.OPEN_VISIBLE),
            label=f"Opening {path} in the Ghidra GUI",
        )
        created_tab = True
    manager = _manager(tool)
    _LAST_TOOL[path or ""] = tool

    moved: dict[str, bool] = {}

    def select_and_move(moved: dict[str, bool] = moved) -> None:
        try:
            manager.setCurrentProgram(program)
            if address is not None:
                from ghidra.app.services import GoToService

                go_to = tool.getService(GoToService)
                if go_to is not None:
                    go_to.goTo(address, program)
            tool.toFront()
        finally:
            moved["done"] = True

    # The listing puts the cursor on the start of the code unit holding the address.
    wanted = None
    if address is not None:
        unit = program.getListing().getCodeUnitContaining(address)
        wanted = {str(address), str(unit.getMinAddress()) if unit is not None else str(address)}
    post_to_edt(select_and_move, label=f"Showing {path} in the Ghidra GUI")
    deadline = time.monotonic() + SHOW_CONFIRM_SECONDS
    shown = navigated = False
    actual = None
    while True:
        finished = "done" in moved  # read before looking at the view
        state = run_on_edt(lambda: _view_state(tool, program))
        shown, actual = state["shown"], state["address"]
        navigated = wanted is None or actual in wanted
        if (finished and shown and navigated) or time.monotonic() >= deadline:
            break
        time.sleep(_POLL_SECONDS)
    # Still pending: a dialog opened by showing the program (the analysis prompt) waits for the human,
    # and the move follows once it is answered (spec §8.2, step 7): unconfirmed, not failed.
    pending = not finished
    result = {
        "target": target,
        "program": path,
        "tool": str(tool.getName()),
        "tool_id": _TOOL_IDS.of(tool),
        "shown": True if shown else (None if pending else False),
        "created_tab": created_tab,
        "launched_tool": launched_tool,
        "navigated": (True if navigated else (None if pending else False)) if address is not None else False,
        "requested": requested,
        "actual_address": actual,
        "focus_requested": True,
        "focus_confirmed": None if pending else run_on_edt(lambda: _frame_active(tool)),
        "modal_dialog": _first_dialog(),
    }
    if not pending and shown and address is not None and not navigated:
        raise HeadlessError(
            f"GUI_NAVIGATION_FAILED: {path} is shown, but the view did not move to {address}",
            details={key: result[key] for key in ("program", "tool", "shown", "created_tab", "actual_address")},
        )
    return result


def _open_programs(tool) -> list:
    manager = _manager(tool)
    return [] if manager is None else list(run_on_edt(lambda: list(manager.getAllOpenPrograms())))


def _view_state(tool, program) -> dict[str, Any]:
    manager = _manager(tool)
    current = None if manager is None else manager.getCurrentProgram()
    shown = current is not None and current == program
    location = _location_of(tool, program) if shown else None
    return {"shown": shown, "address": None if location is None else location["address"]}


def _frame_active(tool) -> bool | None:
    try:
        frame = tool.getToolFrame()
    except Exception:
        return None
    return None if frame is None else bool(frame.isActive())
