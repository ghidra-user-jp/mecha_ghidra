"""Drive a ``--backend gui`` server from inside its own process (spec §14.2).

Usage: python tests/gui_driver.py <scenario> <results.jsonl> <port> -- <server arguments>

The real CLI runs on the main thread, as in production (on macOS the GUI keeps
that thread in CFRunLoop).  A driver thread talks MCP to the server over HTTP,
simulates the human on Swing's EDT with Ghidra commands (``PluginTool.execute``),
checks Java object identity where the spec asks for it, and writes one JSON
line per check: {"check": "G11", "ok": true, ...}.  tests/test_gui_integration.py
runs this script and asserts on the lines.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import NamedTuple

SCENARIO, RESULTS, PORT = sys.argv[1], Path(sys.argv[2]), int(sys.argv[3])
SERVER_ARGS = sys.argv[sys.argv.index("--") + 1 :]
URL = f"http://127.0.0.1:{PORT}/mcp"
# A slow machine (an emulated Windows VM needs minutes to bring the GUI up) stretches the harness's
# own waits; what a check accepts stays as it is, except where noted.
TIME_SCALE = float(os.environ.get("GHIDRA_GUI_TEST_TIME_SCALE") or "1")
_write_lock = threading.Lock()
_startup_failed = threading.Event()


def record(check: str, ok: bool, **detail) -> None:
    with _write_lock, RESULTS.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"check": check, "ok": bool(ok), **detail}, default=str) + "\n")


class Driver:
    def __init__(self, client) -> None:
        self.client = client
        self.human_names: set[str] = set()  # the undo names the simulated human's commands leave
        self.deferred: list[str] = []  # the calls a slow machine deferred (40 s) and the driver followed

    # ---- MCP ----------------------------------------------------------------

    async def call(self, name: str, arguments: dict | None = None):
        response = await self.client.call_tool(name, arguments or {})
        content = response.structured_content or {}
        if isinstance(content, dict) and content.get("deferred") is True:
            self.deferred.append(name)
            return await self._follow(content["operation"]["operation_id"])
        error = content.get("error") if isinstance(content, dict) else None
        return (None if error else content.get("result", content)), error

    async def _follow(self, operation_id: str):
        """A deferred call's outcome, fetched with get_operation as a client does (docs/usage.md#long-calls)."""
        deadline = time.monotonic() + 600 * TIME_SCALE
        while True:
            reply = await self.client.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 30})
            job = (reply.structured_content or {}).get("result") or {}
            if job.get("state") == "succeeded":
                return job.get("result"), None
            if job.get("state") == "failed":
                return None, job.get("operation_error")
            if time.monotonic() > deadline:
                raise AssertionError(f"the deferred call {operation_id} did not end: {job}")

    async def until_ready(self, timeout: float = 180.0) -> None:
        deadline = time.monotonic() + timeout * TIME_SCALE
        while True:
            _result, error = await self.call("list_targets")
            if error is None:
                return
            if error.get("code") != "LOCK_TIMEOUT" or time.monotonic() > deadline:
                raise AssertionError(f"the server did not become ready: {error}")
            await asyncio.sleep(0.5)

    async def full(self, result):
        """A result the server stored as a large result (a preview with resource_uri), read back in full."""
        if not isinstance(result, dict) or not result.get("resource_uri"):
            return result
        read = await self.client.read_resource(result["resource_uri"])
        return json.loads("".join(getattr(item, "text", "") or "" for item in getattr(read, "contents", read)))

    async def revision(self, target: str = "default") -> str | None:
        result, _error = await self.call("get_program_info", {"target": target})
        return None if result is None else result.get("revision")

    # ---- the GUI, in-process -------------------------------------------------

    @staticmethod
    def on_edt(function):
        from ghidra_headless.gui.edt import EDT_START_TIMEOUT_SECONDS, run_on_edt

        # The simulated human waits for a slow machine's EDT as long as it takes.
        return run_on_edt(function, start_timeout=EDT_START_TIMEOUT_SECONDS * TIME_SCALE)

    @staticmethod
    def post(function):
        from ghidra_headless.gui.edt import post_to_edt

        post_to_edt(function, label="test")

    @staticmethod
    def project():
        from ghidra.framework.main import AppInfo

        return AppInfo.getActiveProject()

    def project_location(self) -> str:
        """The project's directory as a path of this OS (Ghidra writes a Windows one as /C:/...)."""
        from ghidra_headless.gui.project_handle import native_project_location

        return str(Path(native_project_location(str(self.project().getProjectLocator().getLocation()))))

    def tools(self):
        from ghidra_headless.gui.programs import running_program_tools

        return running_program_tools(self.project())

    def tool(self):
        return self.tools()[0]

    def manager(self, tool=None):
        from ghidra.app.services import ProgramManager

        return (tool or self.tool()).getService(ProgramManager)

    def open_programs(self, tool=None):
        manager = self.manager(tool)
        return list(self.on_edt(lambda: list(manager.getAllOpenPrograms())))

    def gui_program(self, path: str):
        for tool in self.tools():
            for program in self.open_programs(tool):
                if str(program.getDomainFile().getPathname()) == path:
                    return program
        return None

    def current_path(self, tool=None) -> str | None:
        manager = self.manager(tool)
        current = self.on_edt(manager.getCurrentProgram)
        return None if current is None else str(current.getDomainFile().getPathname())

    def location(self, tool=None) -> str | None:
        from ghidra.app.services import CodeViewerService

        viewer = (tool or self.tool()).getService(CodeViewerService)
        location = self.on_edt(viewer.getCurrentLocation)
        return None if location is None else str(location.getAddress())

    @staticmethod
    def settle(program, timeout: float = 5.0) -> None:
        """Wait until the program has no open transaction (a GUI command's background task ends).

        The task can start its transaction a moment after the command returns, later on a slow
        machine: no transaction must be seen for a while.
        """
        deadline = time.monotonic() + timeout * TIME_SCALE
        quiet_needed = 0.2 * TIME_SCALE
        quiet_since = None
        while time.monotonic() < deadline:
            if program.getCurrentTransactionInfo() is None:
                quiet_since = quiet_since or time.monotonic()
                if time.monotonic() - quiet_since >= quiet_needed:
                    return
            else:
                quiet_since = None
            time.sleep(0.02)

    @staticmethod
    def quiet_edt(program, *, quiet: float = 1.0, timeout: float = 10.0) -> bool:
        """Send the program's pending change events, then wait until the EDT answers quickly for a while.

        A program sends its change events up to half a second after a change, and the GUI's views
        answer them on the EDT, some later still.  False if the EDT did not quiet down in time.
        """
        from java.lang import Thread
        from javax.swing import SwingUtilities

        program.flushEvents()
        deadline = time.monotonic() + timeout * TIME_SCALE
        quiet_since = time.monotonic()
        while time.monotonic() < deadline:
            began = time.perf_counter()
            SwingUtilities.invokeAndWait(Thread())
            if (time.perf_counter() - began) * 1000 >= 20:
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= quiet * TIME_SCALE:
                return True
            time.sleep(0.02)
        return False

    def human(self, command, program) -> bool:
        tool = self.tool()
        self.human_names.add(str(command.getName()))
        done = bool(self.on_edt(lambda: tool.execute(command, program)))
        self.settle(program)
        return done

    def human_comment(self, program, address, text: str, kind: str = "EOL") -> bool:
        from ghidra.app.cmd.comments import SetCommentCmd
        from ghidra.program.model.listing import CommentType

        return self.human(SetCommentCmd(address, getattr(CommentType, kind), text), program)

    @staticmethod
    def comment(program, address, kind: str = "EOL") -> str | None:
        from ghidra.program.model.listing import CommentType

        value = program.getListing().getComment(getattr(CommentType, kind), address)
        return None if value is None else str(value)


def function_with_parameters(program, *, prefer):
    """``prefer`` if it has a parameter, else the first function that has one."""
    if prefer.getParameterCount() > 0:
        return prefer
    functions = program.getFunctionManager().getFunctions(True)
    while functions.hasNext():
        function = functions.next()
        if function.getParameterCount() > 0 and not function.isThunk():
            return function
    raise AssertionError("the sample has no function with a parameter")


def entry_and_biggest(program):
    functions = program.getFunctionManager().getFunctions(True)
    biggest = None
    entry = None
    while functions.hasNext():
        function = functions.next()
        if str(function.getName()) == "entry":
            entry = function
        if biggest is None or function.getBody().getNumAddresses() > biggest.getBody().getNumAddresses():
            biggest = function
    return entry, biggest


# ---- scenarios ----------------------------------------------------------------


async def main_scenario(driver: Driver, started: float) -> None:
    # G05: initialize and tools/list answer before the GUI is ready; an early call waits, then LOCK_TIMEOUT.
    tools = {tool.name for tool in (await driver.client.list_tools()).tools}
    early, error = await driver.call("get_program_info")
    record(
        "G05",
        early is None
        and error is not None
        and error.get("code") == "LOCK_TIMEOUT"
        and (error.get("details") or {}).get("lock") == "startup"
        and "stage" in (error.get("details") or {}),
        initialize_seconds=round(started, 3),
        tools=len(tools),
        early_error=error,
    )
    # G03: the U rows of spec §7.2, written out: four tools and three whole categories (11, 10, 3 tools).
    from ghidra_mcp.contracts.tool_spec import ToolCategoryTag, get_all_tool_specs

    specs = get_all_tool_specs()
    u_sizes = {ToolCategoryTag.BSIM: 11, ToolCategoryTag.SHARED_SYNC: 10, ToolCategoryTag.SCRIPTS: 3}
    by_category = {tag: {name for name, spec in specs.items() if spec.category_tag is tag} for tag in u_sizes}
    unsupported = {"import_program", "analyze_program", "create_project", "close_session_and_remove_program"}
    unsupported = unsupported.union(*by_category.values())
    record(
        "G03",
        {"get_gui_context", "show_in_gui", "rename_variable"} <= tools
        and not tools & unsupported
        and {tag: len(names) for tag, names in by_category.items()} == u_sizes,
        tools=sorted(tools),
        unsupported_exposed=sorted(tools & unsupported),
    )
    await driver.until_ready()

    from ghidra.app.services import GoToService, ProgramManager
    from ghidra.program.model.listing import CommentType
    from ghidra.program.model.symbol import SourceType
    from java.lang import Thread

    from ghidra_headless.handlers import core_runtime

    program = driver.gui_program("/WinHelloCPP.exe")
    context = core_runtime._CONTEXTS.get("default")
    record(
        "G09",
        context is not None and program is not None and context.program == program,
        edt_class_loader=str(driver.on_edt(lambda: Thread.currentThread().getContextClassLoader())),
    )
    entry, biggest = entry_and_biggest(program)
    entry_address = str(entry.getEntryPoint())
    function_address = str(biggest.getEntryPoint())

    # G10: an MCP rename and comment show on the GUI's object, unsaved.
    result, error = await driver.call(
        "apply_edits",
        {
            "edits": [
                {"kind": "rename_function", "address": entry_address, "new_name": "ai_entry"},
                {"kind": "set_comment", "address": entry_address, "comment": "ai plate", "comment_type": "plate"},
            ]
        },
    )
    record(
        "G10",
        error is None
        and result.get("status") == "applied"
        and str(entry.getName()) == "ai_entry"
        and driver.comment(program, entry.getEntryPoint(), "PLATE") == "ai plate"
        and bool(program.isChanged()),
        error=error,
    )
    # G38: the batch was one Mecha transaction; batches with decompiling kinds are refused before starting,
    # and the standalone tool makes the refused rename as a Mecha transaction of its own.
    undo_names = [str(name) for name in program.getAllUndoNames()]
    modification = int(program.getModificationNumber())
    owner = function_with_parameters(program, prefer=biggest)
    old_variable = str(owner.getParameter(0).getName())
    rename = {"function_address": str(owner.getEntryPoint()), "old_name": old_variable, "new_name": "ai_variable"}
    _refused, refusal = await driver.call("apply_edits", {"edits": [{"kind": "rename_variable", **rename}]})
    refusal_changed_nothing = int(program.getModificationNumber()) == modification
    renamed, rename_error = await driver.call("rename_variable", rename)
    parameters_in_gui = [str(parameter.getName()) for parameter in owner.getParameters()]
    record(
        "G38",
        undo_names == ["Mecha: Apply annotation edits"]
        and refusal is not None
        and refusal.get("code") == "GUI_UNSUPPORTED"
        and (refusal.get("details") or {}).get("reason") == "edit_kind_decompiles"
        and refusal_changed_nothing
        and rename_error is None
        and (renamed or {}).get("name") == "ai_variable"
        and "ai_variable" in parameters_in_gui
        and old_variable not in parameters_in_gui
        and str(program.getUndoName()) == "Mecha: Rename variable",
        undo_names=undo_names[:3],
        refusal=refusal,
        renamed=f"{owner.getName()}:{old_variable}",
        parameters_in_gui=parameters_in_gui,
        rename_error=rename_error,
    )

    # G11: a human edit on the EDT is in the next read, and the revision moves.
    before = await driver.revision()
    human_ok = driver.human_comment(program, entry.getEntryPoint(), "human G11")
    comments, comments_error = await driver.call("get_comments", {"address": entry_address})
    after = await driver.revision()
    record(
        "G11",
        human_ok
        and comments_error is None
        and "human G11" in json.dumps(comments)
        and None not in (before, after)
        and before != after,
        before=before,
        after=after,
    )

    # G13: the human's undo and redo are in the next read.
    driver.on_edt(program.undo)
    driver.settle(program)
    undone, undone_error = await driver.call("get_comments", {"address": entry_address})
    driver.on_edt(program.redo)
    driver.settle(program)
    redone, redone_error = await driver.call("get_comments", {"address": entry_address})
    record(
        "G13",
        undone_error is None
        and redone_error is None
        and "human G11" not in json.dumps(undone)
        and "human G11" in json.dumps(redone),
    )

    # G26: AI undo refuses the human's step and leaves it; AI undo takes back its own step.
    _undo, foreign = await driver.call("undo_program_change", {"target": "default", "count": 1})
    driver.settle(program)
    human_step_kept = (
        str(program.getUndoName()) == "Set Comment" and driver.comment(program, entry.getEntryPoint()) == "human G11"
    )
    _eol, eol_error = await driver.call(
        "apply_edits",
        {"edits": [{"kind": "set_comment", "address": entry_address, "comment": "ai eol", "comment_type": "eol"}]},
    )
    own, own_error = await driver.call("undo_program_change", {"target": "default", "count": 1})
    driver.settle(program)
    record(
        "G26",
        foreign is not None
        and (foreign.get("details") or {}).get("reason") == "foreign_undo"
        and human_step_kept
        and eol_error is None
        and own_error is None
        and own.get("undone") == ["Mecha: Apply annotation edits"]
        and driver.comment(program, entry.getEntryPoint()) == "human G11",
        foreign=foreign,
        own=own,
    )

    # G12: types in both directions, for a prototype and for data.
    _proto, proto_error = await driver.call(
        "set_function_prototype", {"function_address": function_address, "prototype": "int ai_proto(int a, int b)"}
    )
    # ApplyFunctionSignatureCmd renames only a default-named function, so check the parameters.
    ai_prototype_in_gui = [str(parameter.getName()) for parameter in biggest.getParameters()] == ["a", "b"]
    from ghidra.app.cmd.data import CreateDataCmd
    from ghidra.app.cmd.function import SetReturnDataTypeCmd
    from ghidra.app.cmd.label import AddLabelCmd
    from ghidra.program.model.data import DWordDataType, UnsignedIntegerDataType

    human_prototype = driver.human(
        SetReturnDataTypeCmd(biggest.getEntryPoint(), UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED),
        program,
    )
    described, described_error = await driver.call("get_function", {"address": function_address})
    signature = str((described or {}).get("signature", ""))
    human_prototype_seen = described_error is None and signature.split("(")[0].split()[0] == "uint"
    block = program.getMemory().getBlock(".data")
    listing = program.getListing()
    free = []
    address = block.getStart()
    while len(free) < 2 and block.contains(address.add(4)):
        if listing.getUndefinedDataAt(address) is not None:
            free.append(address)
        address = address.add(8)
    human_address, ai_address = free
    human_type = driver.human(CreateDataCmd(human_address, DWordDataType.dataType), program)
    driver.human(AddLabelCmd(human_address, "human_dword", SourceType.USER_DEFINED), program)
    human_type_seen = await _data_type_at(driver, str(human_address)) == "dword"
    _set, set_error = await driver.call("set_global_data_type", {"address": str(ai_address), "data_type": "/dword"})
    ai_data = listing.getDataAt(ai_address)
    ai_type_in_gui = ai_data is not None and str(ai_data.getDataType().getName()) == "dword"
    record(
        "G12",
        proto_error is None
        and ai_prototype_in_gui
        and human_prototype
        and human_prototype_seen
        and human_type
        and human_type_seen
        and set_error is None
        and ai_type_in_gui,
        prototype=str(biggest.getSignature().getPrototypeString()),
        ai_signature=signature,
        human_address=str(human_address),
        ai_address=str(ai_address),
        errors=[proto_error, described_error, set_error],
    )

    # G14: an AI load opens a visible tab without changing the human's current program.
    project_location = driver.project_location()
    before_current = driver.current_path()
    before_tabs = len(driver.open_programs())
    _opened, open_error = await driver.call(
        "open_program",
        {"target": "second", "project_location": project_location, "project_name": "GUI", "domain_path": "/Second.exe"},
    )
    second = driver.gui_program("/Second.exe")
    manager = driver.manager()
    record(
        "G14",
        open_error is None
        and second is not None
        and bool(driver.on_edt(lambda: manager.isVisible(second)))
        and driver.current_path() == before_current
        and len(driver.open_programs()) == before_tabs + 1,
        error=open_error,
        current=driver.current_path(),
    )

    # G15: a program a GUI tool already has open is bound, not opened again.
    third_file = driver.project().getProjectData().getFile("/Third.exe")
    from ghidra.framework.model import DomainFile

    driver.post(lambda: manager.openProgram(third_file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE))
    for _ in range(int(100 * TIME_SCALE)):
        if driver.gui_program("/Third.exe") is not None:
            break
        time.sleep(0.05)
    third = driver.gui_program("/Third.exe")
    tabs = len(driver.open_programs())
    _bound, bound_error = await driver.call(
        "open_program",
        {"target": "third", "project_location": project_location, "project_name": "GUI", "domain_path": "/Third.exe"},
    )
    third_context = core_runtime._CONTEXTS.get("third")
    record(
        "G15",
        bound_error is None
        and third_context is not None
        and third_context.program == third
        and len(driver.open_programs()) == tabs,
        error=bound_error,
    )

    # The human's cursor in WinHelloCPP sits on the biggest function, not on its entry point (G18).
    driver.on_edt(lambda: driver.tool().getService(GoToService).goTo(biggest.getEntryPoint()))
    _until(lambda: driver.location() == function_address)

    # G16 / G17: the human switches tabs; AI work, also on the human's own program, leaves the view alone.
    driver.post(lambda: manager.setCurrentProgram(second))
    _until(lambda: driver.current_path() == "/Second.exe")
    info, info_error = await driver.call("get_program_info", {"target": "default"})
    record(
        "G16",
        info_error is None and driver.current_path() == "/Second.exe" and info.get("domain_path") == "/WinHelloCPP.exe",
    )
    view_before = (driver.current_path(), driver.location())
    second_entry = str(entry_and_biggest(second)[0].getEntryPoint())
    work = [
        ("decompile_function", {"target": "default", "address": entry_address}),
        (
            "apply_edits",
            {
                "target": "default",
                "edits": [{"kind": "rename_function", "address": entry_address, "new_name": "ai_entry2"}],
            },
        ),
        ("list_functions", {"target": "third", "limit": 5}),
        ("decompile_function", {"target": "second", "address": second_entry}),
        (
            "apply_edits",
            {
                "target": "second",
                "edits": [{"kind": "rename_function", "address": second_entry, "new_name": "ai_second"}],
            },
        ),
    ]
    work_errors = [(await driver.call(name, arguments))[1] for name, arguments in work]
    record(
        "G17",
        all(error is None for error in work_errors) and (driver.current_path(), driver.location()) == view_before,
        before=view_before,
        errors=work_errors,
    )

    # G18: show_in_gui(target) shows the program and keeps the human's position in it.
    tools_before = len(driver.tools())
    shown, show_error = await driver.call("show_in_gui", {"target": "default"})
    record(
        "G18",
        show_error is None
        and shown.get("shown")
        and driver.current_path() == "/WinHelloCPP.exe"
        and driver.location() == function_address,
        result=shown,
        location=driver.location(),
    )
    # G19: moves by name and by address, checked in the view itself.
    by_name, name_error = await driver.call("show_in_gui", {"target": "default", "name": "ai_entry2"})
    at_name = driver.location()
    by_address, address_error = await driver.call("show_in_gui", {"target": "default", "address": function_address})
    at_address = driver.location()
    record(
        "G19",
        name_error is None and address_error is None
        and by_name.get("navigated") and at_name == entry_address
        and by_address.get("navigated") and at_address == function_address,
        by_name=by_name,
        by_address=by_address,
    )  # fmt: skip
    # G20: showing again adds no tool, tab or window.
    windows_before = _visible_windows()
    tabs_before = len(driver.open_programs())
    again, again_error = await driver.call("show_in_gui", {"target": "default", "name": "ai_entry2"})
    record(
        "G20",
        again_error is None
        and not again.get("created_tab")
        and len(driver.tools()) == tools_before
        and len(driver.open_programs()) == tabs_before
        and _visible_windows() == windows_before
        and driver.location() == entry_address,
        tools=len(driver.tools()),
        windows=(windows_before, _visible_windows()),
    )
    # G21: the human is on another program; an invalid address fails before anything changes.
    driver.post(lambda: manager.setCurrentProgram(second))
    _until(lambda: driver.current_path() == "/Second.exe")
    view = (driver.current_path(), driver.location())
    _bad, bad_error = await driver.call("show_in_gui", {"target": "default", "address": "0xZZZZ"})
    record(
        "G21",
        bad_error is not None
        and bad_error.get("code") in ("VALIDATION_ERROR", "NOT_FOUND")
        and (driver.current_path(), driver.location()) == view,
        error=bad_error,
    )
    await driver.call("show_in_gui", {"target": "default", "name": "ai_entry2"})

    # G22: get_gui_context reads the view and changes no target.
    targets_before, before_error = await driver.call("list_targets")
    context_result, context_error = await driver.call("get_gui_context")
    targets_after, after_error = await driver.call("list_targets")
    location = (context_result or {}).get("location") or {}
    record(
        "G22",
        context_error is None
        and before_error is None
        and after_error is None
        and (context_result.get("program") or {}).get("domain_path") == "/WinHelloCPP.exe"
        and location.get("address") == entry_address
        and (location.get("function") or {}).get("name") == "ai_entry2"
        and "default" in context_result.get("targets", [])
        and targets_before == targets_after,
        result=context_result,
    )

    # G23 / G36: a write while another transaction stays open waits, then LOCK_TIMEOUT with nothing changed.
    held, release = threading.Event(), threading.Event()

    def holder():
        transaction = program.startTransaction("Holder (test)")
        held.set()
        release.wait(10 * TIME_SCALE)
        program.endTransaction(transaction, True)

    threading.Thread(target=holder, daemon=True).start()
    held.wait(5 * TIME_SCALE)
    waited_from = time.monotonic()
    _blocked, blocked = await driver.call(
        "apply_edits",
        {"edits": [{"kind": "set_comment", "address": entry_address, "comment": "blocked", "comment_type": "pre"}]},
    )
    waited = time.monotonic() - waited_from
    release.set()
    driver.settle(program)
    details = (blocked or {}).get("details") or {}
    record(
        "G23",
        blocked is not None
        and blocked.get("code") == "LOCK_TIMEOUT"
        and details.get("lock") == "program_transaction"
        and details.get("transaction") == "Holder (test)"
        and waited >= 0.9  # --lock-timeout-seconds 1
        and driver.comment(program, entry.getEntryPoint(), "PRE") is None,
        error=blocked,
        waited=round(waited, 2),
    )

    # G24: the human edits while Mecha's transaction is open, and the AI's batch then fails: the human's
    # edit stays.  Without rule 3 it would join Mecha's transaction and roll back with it.
    addresses = [str(function.getEntryPoint()) for function in program.getFunctionManager().getFunctions(True)]
    batch = [
        {"kind": "set_comment", "address": address, "comment": f"ai G24 {index}", "comment_type": "pre"}
        for index, address in enumerate(addresses[1:100])
    ]
    batch.append({"kind": "rename_function", "address": "0xZZZZ", "new_name": "never"})
    during: dict[str, object] = {}

    def human_during_mecha() -> None:
        deadline = time.monotonic() + 30 * TIME_SCALE
        while time.monotonic() < deadline:
            info = program.getCurrentTransactionInfo()
            if info is not None and str(info.getDescription()).startswith("Mecha: "):
                during["seen"] = str(info.getDescription())
                driver.post(lambda: driver.tool().execute(_eol_command(entry.getEntryPoint(), "human G24"), program))
                return
            time.sleep(0.0005)

    watcher = threading.Thread(target=human_during_mecha, daemon=True)
    watcher.start()
    failed, failed_error = await driver.call("apply_edits", {"edits": batch})
    failed = await driver.full(failed)
    watcher.join(35 * TIME_SCALE)
    driver.settle(program)
    _until(lambda: driver.comment(program, entry.getEntryPoint(), "EOL") == "human G24")
    record(
        "G24",
        failed_error is None
        and (failed or {}).get("status") == "rolled_back"
        and "seen" in during
        and driver.comment(program, entry.getEntryPoint(), "EOL") == "human G24"
        and all(driver.comment(program, _address(program, address), "PRE") is None for address in addresses[1:6]),
        during=during,
        status=(failed or {}).get("status"),
        error=failed_error,
    )
    # G36: output_state as headless: absent for a timeout and for a rollback, and rule 6 records a commit.
    _label, label_error = await driver.call("create_label", {"address": entry_address, "name": "bad label name"})
    from ghidra_headless.session.transactions import TransactionRecord, use_record
    from ghidra_headless.session.write_boundary import write_boundary

    probe_record = TransactionRecord()
    driver.settle(program, timeout=60)  # the edits above may have started auto-analysis
    with use_record(probe_record):
        write_boundary().write(
            program,
            "G36 probe",
            lambda: program.getListing().setComment(entry.getEntryPoint(), CommentType.POST, "G36 committed"),
        )
    record(
        "G36",
        (details.get("output_state") == "absent")
        and label_error is not None
        and (label_error.get("details") or {}).get("output_state") == "absent"
        and probe_record.outcome() == "committed",
        lock_timeout=details,
        rolled_back=label_error,
        committed=probe_record.outcome(),
    )

    # G25: dry_run is refused and changes nothing.
    modification = int(program.getModificationNumber())
    undo_top = str(program.getUndoName())
    _dry, dry = await driver.call(
        "apply_edits",
        {"dry_run": True, "edits": [{"kind": "rename_function", "address": entry_address, "new_name": "dry"}]},
    )
    record(
        "G25",
        dry is not None
        and dry.get("code") == "GUI_UNSUPPORTED"
        and int(program.getModificationNumber()) == modification
        and str(program.getUndoName()) == undo_top,
        error=dry,
    )

    # G33: the EDT answers during a long decompile.  Two Java timers stamp System.nanoTime every
    # _STAMP_PERIOD_MS, one on the EDT and one on a thread of its own.  No Python runs in them, so Python's
    # GIL does not delay them.  The EDT's wait is its longest gap between stamps beyond the period, less
    # what the control thread waited at the same time: a pause of the whole JVM or machine (a
    # collection, a safepoint, a busy runner) stops both, and is not the EDT's.  The GUI's answer to the
    # edits above runs on the EDT too, so it ends first.
    from java.lang.management import ManagementFactory
    from java.util.concurrent import ConcurrentLinkedQueue, Executors, TimeUnit
    from javax.swing import Timer as SwingTimer

    def collector_ms() -> int:
        return sum(max(0, int(bean.getCollectionTime())) for bean in ManagementFactory.getGarbageCollectorMXBeans())

    edt_quiet = driver.quiet_edt(program)
    edt_queue, control_queue = ConcurrentLinkedQueue(), ConcurrentLinkedQueue()
    edt_timer = SwingTimer(_STAMP_PERIOD_MS, _nano_stamper(edt_queue).listener)
    control = Executors.newSingleThreadScheduledExecutor()
    collected_before = collector_ms()
    decompile_ms, decompile_error = 0.0, None
    try:
        edt_timer.start()
        control.scheduleWithFixedDelay(
            _nano_stamper(control_queue).runnable, 0, _STAMP_PERIOD_MS, TimeUnit.MILLISECONDS
        )
        _until(lambda: edt_queue.size() > 0 and control_queue.size() > 0)
        decompile_began = time.perf_counter()
        _code, decompile_error = await driver.call("decompile_function", {"address": function_address})
        decompile_ms = (time.perf_counter() - decompile_began) * 1000
        await asyncio.sleep(3 * _STAMP_PERIOD_MS / 1000)  # a stamp after the decompile closes the last gap
    finally:
        edt_timer.stop()
        control.shutdownNow()
    collected_ms = collector_ms() - collected_before
    edt_stamps, control_stamps = _millis(edt_queue), _millis(control_queue)
    edt_wait = _own_wait(edt_stamps, control_stamps)
    record(
        "G33",
        decompile_error is None
        and len(edt_stamps) >= 3
        and len(control_stamps) >= 3
        and edt_wait < 100
        and decompile_ms >= 2 * edt_wait,
        edt_wait_ms=round(edt_wait, 2),
        edt_max_gap_ms=round(_max_gap(edt_stamps), 2),
        control_max_gap_ms=round(_max_gap(control_stamps), 2),
        decompile_ms=round(decompile_ms, 1),
        stamps=[len(edt_stamps), len(control_stamps)],
        gc_ms=collected_ms,
        edt_quiet_before=edt_quiet,
        error=decompile_error,
    )

    # G27: every step the AI left in the undo list is named "Mecha: "; the rest are the human's commands.
    names = [str(name) for name in program.getAllUndoNames()]
    ghidra_own = {"Auto Analysis"}  # background analysis the edits started
    record(
        "G27",
        all(name.startswith("Mecha: ") or name in driver.human_names | ghidra_own for name in names)
        and any(name.startswith("Mecha: ") for name in names),
        undo_names=names[:12],
        human=sorted(driver.human_names),
    )

    # G28: a save includes the human's changes and leaves nothing unsaved.
    human_saved = driver.human_comment(program, entry.getEntryPoint(), "human G28", "POST")
    modified = int(program.getDomainFile().getLastModifiedTime())
    undo_before_save = len(list(program.getAllUndoNames()))
    saved, save_error = await driver.call("save_project_program", {"target": "default"})
    record(
        "G28",
        human_saved
        and save_error is None
        and saved.get("saved")
        and not bool(program.isChanged())
        and int(program.getDomainFile().getLastModifiedTime()) > modified,
        result=saved,
        error=save_error,
        undo_steps=(undo_before_save, len(list(program.getAllUndoNames()))),  # Ghidra clears them on save
    )

    # G29: export works on the open program.
    exports = Path(os.environ["GUI_TEST_EXPORTS"])
    output = exports / "WinHelloCPP.gzf"
    undo_before_export = len(list(program.getAllUndoNames()))
    _exported, export_error = await driver.call(
        "export_program", {"target": "default", "output_path": str(output), "format": "gzf"}
    )
    record(
        "G29",
        export_error is None and output.is_file(),
        error=export_error,
        undo_steps=(undo_before_export, len(list(program.getAllUndoNames()))),  # Ghidra may clear them
    )

    # G30: close_session only unbinds: the program stays open, changed and unsaved; discarding is refused.
    second_file = second.getDomainFile()
    second_modified = int(second_file.getLastModifiedTime())
    second_changed = bool(second.isChanged())  # the AI renamed its entry through target "second" (G17)
    _discard, discard = await driver.call("close_session", {"target": "second", "discard_changes": True})
    _closed, close_error = await driver.call("close_session", {"target": "second"})
    _gone_second, gone_second = await driver.call("get_program_info", {"target": "second"})
    record(
        "G30",
        discard is not None
        and discard.get("code") == "GUI_UNSUPPORTED"
        and close_error is None
        and gone_second is not None
        and second_changed
        and bool(second.isChanged())
        and int(second_file.getLastModifiedTime()) == second_modified
        and driver.gui_program("/Second.exe") == second,
        discard=discard,
        error=close_error,
        after=gone_second,
    )

    # G31: the human closes a tab; the target expires; a new load works.
    driver.on_edt(lambda: manager.closeProgram(third, True))
    _gone, gone = await driver.call("get_program_info", {"target": "third"})
    reloaded, reload_error = await driver.call("load_project_program", {"target": "third", "domain_path": "/Third.exe"})
    # A tab closed while an operation holds the program: the operation's own consumer keeps the program
    # open until the operation ends (spec §5.2), then the program closes.
    third_again = driver.gui_program("/Third.exe")
    _, third_biggest = entry_and_biggest(third_again)
    tools_consumers = len(list(third_again.getConsumerList()))
    hold: dict[str, object] = {}

    def close_while_held() -> None:
        deadline = time.monotonic() + 30 * TIME_SCALE
        while time.monotonic() < deadline:
            consumers = list(third_again.getConsumerList())
            if len(consumers) > tools_consumers:
                driver.on_edt(lambda: manager.closeProgram(third_again, True))
                hold["closed_while_held"] = True
                hold["open_after_close"] = not bool(third_again.isClosed())
                return
            time.sleep(0.0005)

    closer = threading.Thread(target=close_while_held, daemon=True)
    closer.start()
    _code, during_error = await driver.call(
        "decompile_function", {"target": "third", "address": str(third_biggest.getEntryPoint())}
    )
    closer.join(35 * TIME_SCALE)
    record(
        "G31",
        gone is not None
        and gone.get("code") == "PROGRAM_NOT_OPEN"
        and (gone.get("details") or {}).get("reason") == "closed_in_gui"
        and reload_error is None
        and hold.get("closed_while_held")
        and hold.get("open_after_close")
        and during_error is None
        and bool(third_again.isClosed()),
        gone=gone,
        reload_error=reload_error,
        reloaded=reloaded,
        hold=hold,
        during_error=during_error,
    )


async def _data_type_at(driver: Driver, address: str) -> str | None:
    """The data type the AI reads at ``address`` (list_data_items, paged small enough to stay inline)."""
    offset = 0
    while True:
        items, error = await driver.call("list_data_items", {"offset": offset, "limit": 50})
        items = await driver.full(items)
        page = items if isinstance(items, list) else (items or {}).get("items", [])
        if error is not None or not page:
            return None
        for item in page:
            if item.get("address") == address:
                return item.get("dataType")
        offset += len(page)


def _address(program, text: str):
    return program.getAddressFactory().getAddress(text)


_STAMP_PERIOD_MS = 10


class _Stamper(NamedTuple):
    runnable: object
    listener: object


def _nano_stamper(queue) -> _Stamper:
    """A Java Runnable and ActionListener that add System.nanoTime() to ``queue``, with no Python in them."""
    from java.awt.event import ActionEvent, ActionListener
    from java.lang import Boolean, Long, Object, Runnable, System
    from java.lang.invoke import MethodHandleProxies, MethodHandles, MethodType

    lookup = MethodHandles.publicLookup()
    now = lookup.findStatic(System.class_, "nanoTime", MethodType.methodType(Long.TYPE))
    box = lookup.findStatic(Long.class_, "valueOf", MethodType.methodType(Long.class_, Long.TYPE))
    add = lookup.findVirtual(queue.getClass(), "add", MethodType.methodType(Boolean.TYPE, Object.class_))
    stamp = MethodHandles.dropReturn(
        MethodHandles.collectArguments(
            add.bindTo(queue), 0, MethodHandles.filterReturnValue(now, box).asType(MethodType.methodType(Object.class_))
        )
    )
    return _Stamper(
        MethodHandleProxies.asInterfaceInstance(Runnable.class_, stamp),
        MethodHandleProxies.asInterfaceInstance(
            ActionListener.class_, MethodHandles.dropArguments(stamp, 0, ActionEvent.class_)
        ),
    )


def _millis(queue) -> list[float]:
    return [int(value) / 1e6 for value in queue.toArray()]


def _max_gap(stamps: list[float]) -> float:
    return max((later - earlier for earlier, later in zip(stamps, stamps[1:])), default=0.0)


def _own_wait(stamps: list[float], control: list[float]) -> float:
    """The longest wait beyond the period in ``stamps`` that ``control`` did not share, in ms."""
    control_gaps = list(zip(control, control[1:]))
    worst = 0.0
    for start, end in zip(stamps, stamps[1:]):
        shared = max(
            (
                min(end, c_end) - max(start, c_start)
                for c_start, c_end in control_gaps
                if c_start < end and c_end > start
            ),
            default=0.0,
        )
        worst = max(worst, (end - start) - _STAMP_PERIOD_MS - max(0.0, shared - _STAMP_PERIOD_MS))
    return worst


def _until(condition, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout * TIME_SCALE
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return bool(condition())


def _visible_windows() -> int:
    from java.awt import Window

    return int(Driver.on_edt(lambda: sum(1 for window in Window.getWindows() if window.isVisible())))


def _eol_command(address, text):
    from ghidra.app.cmd.comments import SetCommentCmd
    from ghidra.program.model.listing import CommentType

    return SetCommentCmd(address, CommentType.EOL, text)


async def prompt_scenario(driver: Driver, _started: float) -> None:
    """G37: the first program of an empty CodeBrowser is current, and Ghidra asks to analyze it."""
    await driver.until_ready()
    project_location = driver.project_location()
    began = time.perf_counter()
    loaded, error = await driver.call(
        "open_program",
        {
            "target": "default",
            "project_location": project_location,
            "project_name": "GUI",
            "domain_path": "/Unanalyzed.exe",
        },
    )
    seconds = time.perf_counter() - began
    deadline = time.monotonic() + 10 * TIME_SCALE
    from ghidra_headless.gui.edt import modal_dialog_titles

    while "Analyze?" not in modal_dialog_titles() and time.monotonic() < deadline:
        time.sleep(0.1)
    dialogs = modal_dialog_titles()
    info, info_error = await driver.call("get_program_info")
    context, _ = await driver.call("get_gui_context")
    # The prompt waits until this scenario answers it below, so any bound tells a load that waits for it
    # from one that does not: scaled for a slow machine.
    record(
        "G37",
        error is None and seconds < 15 * TIME_SCALE and "Analyze?" in dialogs and info_error is None
        and (loaded or {}).get("modal_dialog") == "Analyze?"
        and (context or {}).get("modal_dialog") == "Analyze?",
        load_seconds=round(seconds, 2),
        dialogs=dialogs,
        loaded=loaded,
    )  # fmt: skip
    _click("No")


def _click(label: str) -> str | None:
    from java.awt import Dialog, Window
    from javax.swing import AbstractButton

    def find(component):
        if isinstance(component, AbstractButton) and component.isShowing() and str(component.getText()) == label:
            return component
        for child in getattr(component, "getComponents", list)():
            hit = find(child)
            if hit is not None:
                return hit
        return None

    def press():
        for window in Window.getWindows():
            if isinstance(window, Dialog) and window.isVisible() and window.isModal():
                button = find(window)
                if button is not None:
                    button.doClick()
                    return str(window.getTitle())
        return None

    return Driver.on_edt(press)


def _save_dialog_texts() -> list[str]:
    """Every text the visible save dialog shows: buttons and check boxes, labels, list and table rows."""
    from java.awt import Dialog, Window
    from javax.swing import AbstractButton, JLabel, JList, JTable

    def texts(component, found):
        if isinstance(component, (AbstractButton, JLabel)) and component.getText():
            found.append(str(component.getText()))
        elif isinstance(component, JList):
            model = component.getModel()
            found.extend(str(model.getElementAt(i)) for i in range(model.getSize()))
        elif isinstance(component, JTable):
            model = component.getModel()
            for row in range(model.getRowCount()):
                found.extend(str(model.getValueAt(row, column)) for column in range(model.getColumnCount()))
        for child in getattr(component, "getComponents", list)():
            texts(child, found)
        return found

    def scan():
        for window in Window.getWindows():
            if (
                isinstance(window, Dialog)
                and window.isVisible()
                and window.isModal()
                and "Save" in str(window.getTitle())
            ):
                return texts(window, [])
        return []

    return list(Driver.on_edt(scan))


def _wait_dialog(title_part: str, timeout: float = 10.0) -> list[str]:
    from ghidra_headless.gui.edt import modal_dialog_titles

    deadline = time.monotonic() + timeout * TIME_SCALE
    while time.monotonic() < deadline:
        titles = modal_dialog_titles()
        if any(title_part in title for title in titles):
            return titles
        time.sleep(0.1)
    return modal_dialog_titles()


def _interrupt() -> None:
    """SIGINT; on Windows Ctrl+C, a console event (the scenario has a console of its own)."""
    if os.name == "nt":
        import ctypes

        ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT, every process of this console
    else:
        os.kill(os.getpid(), signal.SIGINT)


def _terminate() -> None:
    """SIGTERM; on Windows, which sends no SIGTERM, Ctrl+Break."""
    if os.name == "nt":
        import ctypes

        ctypes.windll.kernel32.GenerateConsoleCtrlEvent(1, 0)  # CTRL_BREAK_EVENT
    else:
        os.kill(os.getpid(), signal.SIGTERM)


async def exit_scenario(driver: Driver, _started: float) -> None:
    """G32 and G34: Ghidra's own exit, with its save prompt, on SIGINT and SIGTERM (on Windows, Ctrl+C and
    Ctrl+Break); SIGHUP, which Windows does not have, leaves it running."""
    await driver.until_ready()
    entry, _ = entry_and_biggest(driver.gui_program("/WinHelloCPP.exe"))
    _edit, edit_error = await driver.call(
        "apply_edits",
        {
            "edits": [
                {
                    "kind": "set_comment",
                    "address": str(entry.getEntryPoint()),
                    "comment": "unsaved",
                    "comment_type": "plate",
                }
            ]
        },
    )
    from ghidra_headless.gui.edt import modal_dialog_titles

    def saving(titles) -> bool:
        return any("Save" in title for title in titles)

    _interrupt()
    sigint_titles = _wait_dialog("Save")
    time.sleep(0.5 * TIME_SCALE)
    shown = _save_dialog_texts()
    sigint_cancel = _click("Cancel")
    time.sleep(1.0 * TIME_SCALE)
    after_sigint = modal_dialog_titles()
    _up, up_error = await driver.call("get_program_info")
    record(
        "G32",
        edit_error is None and any("WinHelloCPP" in text for text in shown),
        dialogs=sigint_titles,
        texts=shown[:20],
    )
    after_sighup: list[str] = []
    hup_error = None
    if hasattr(signal, "SIGHUP"):
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(2.0 * TIME_SCALE)
        after_sighup = modal_dialog_titles()
        _hup, hup_error = await driver.call("get_program_info")
    _terminate()
    sigterm_titles = _wait_dialog("Save")
    sigterm_cancel = _click("Cancel")
    time.sleep(1.0 * TIME_SCALE)
    after_sigterm = modal_dialog_titles()
    _term, term_error = await driver.call("get_program_info")
    record(
        "G34",
        saving(sigint_titles) and sigint_cancel is not None and not saving(after_sigint) and up_error is None
        and not saving(after_sighup) and hup_error is None
        and saving(sigterm_titles) and sigterm_cancel is not None and not saving(after_sigterm) and term_error is None,
        sigint=sigint_titles,
        after_sighup=after_sighup if hasattr(signal, "SIGHUP") else "no SIGHUP on this OS",
        sigterm=sigterm_titles,
        cancelled=[sigint_cancel, sigterm_cancel],
    )  # fmt: skip
    record("exiting", True)
    _terminate()
    if not saving(_wait_dialog("Save")):
        # The exit did not ask: end now instead of waiting for the test's timeout.
        record("exit_prompt_missing", False)
        import jpype

        jpype.java.lang.System.exit(3)
    _click("Don't Save")


async def restore_scenario(driver: Driver, _started: float) -> None:
    """G08: another project in the settings' LastOpenedProject; the requested one opens."""
    await driver.until_ready()
    name = str(driver.project().getProjectLocator().getName())
    record("G08", name == os.environ["GUI_TEST_EXPECT_PROJECT"], project=name)

    # G28, second half: a program with nowhere to save to fails without a Save As dialog.
    from ghidra_headless.gui.edt import modal_dialog_titles

    read_only = driver.project().getProjectData().getFile("/Second.exe")
    driver.on_edt(lambda: read_only.setReadOnly(True))
    project_location = driver.project_location()
    _opened, open_error = await driver.call(
        "open_program",
        {"target": "ro", "project_location": project_location, "project_name": "GUI", "domain_path": "/Second.exe"},
    )
    program = driver.gui_program("/Second.exe")
    entry, _ = entry_and_biggest(program)
    human_ok = driver.human_comment(program, entry.getEntryPoint(), "human, read-only file")
    _saved, save_error = await driver.call("save_project_program", {"target": "ro"})
    time.sleep(1.0)
    dialogs = modal_dialog_titles()
    record(
        "G28",
        open_error is None
        and human_ok
        and save_error is not None
        and save_error.get("code") == "SAVE_FAILED"
        and not dialogs
        and bool(program.isChanged())
        and not bool(program.canSave()),
        open_error=open_error,
        save_error=save_error,
        dialogs=dialogs,
    )


async def failed_start_scenario(driver: Driver, _started: float) -> None:
    """G06 and G07: the startup fails before GhidraRun, and every call says why."""
    deadline = time.monotonic() + 60
    while True:
        _result, error = await driver.call("list_targets")
        if error is not None and error.get("code") != "LOCK_TIMEOUT":
            break
        if time.monotonic() > deadline:
            break
        await asyncio.sleep(0.3)
    failed = error is not None and error.get("code") == "STARTUP_FAILED"
    if failed:
        _startup_failed.set()
    record("failed_start", failed, error=error)


SCENARIOS = {
    "main": main_scenario,
    "prompt": prompt_scenario,
    "exit": exit_scenario,
    "restore": restore_scenario,
    "failed_start": failed_start_scenario,
}


def _wait_for_port(timeout: float = 120.0) -> None:
    """Wait until the server accepts connections: the MCP client does not retry a refused one."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def drive() -> None:
    async def run() -> None:
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client

        _wait_for_port()
        began = time.perf_counter()
        # One connection per request, as the relays do: on a slow machine calls come seconds apart, and a
        # kept-alive connection that uvicorn closes after 5 s idle can break the next call halfway.
        http = httpx2.AsyncClient(
            timeout=httpx2.Timeout(150.0, connect=10.0),
            limits=httpx2.Limits(max_keepalive_connections=0),
            trust_env=False,
        )
        async with http, Client(streamable_http_client(URL, http_client=http), read_timeout_seconds=120) as client:
            initialized = time.perf_counter() - began
            driver = Driver(client)
            try:
                await SCENARIOS[SCENARIO](driver, initialized)
            finally:
                if driver.deferred:
                    record("deferred_calls", True, calls=driver.deferred)

    try:
        asyncio.run(run())
        record("done", True)
    except BaseException as exc:
        record("driver_error", False, error=repr(exc), traceback=traceback.format_exc())
    finally:
        # A failed start ends the server by itself; one that started anyway must not wait for the timeout.
        if SCENARIO != "exit" and (SCENARIO != "failed_start" or not _startup_failed.is_set()):
            import jpype

            if jpype.isJVMStarted():
                jpype.java.lang.System.exit(0)
            os._exit(0)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    threading.Thread(target=drive, name="gui-test-driver", daemon=True).start()
    from ghidra_mcp.presentation import cli

    sys.exit(cli.main(SERVER_ARGS))
