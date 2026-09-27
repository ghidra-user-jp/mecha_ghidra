"""GUI backend units that need no JVM: the startup gate's stage details, the GUI project handle's ownership,
and a transaction record fed by the write boundary (spec §4.4, §5.3, §6.2 rule 6)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.gui import project_handle as gui_handle_module
from ghidra_headless.gui.project_handle import GuiProjectHandle
from ghidra_headless.session.transactions import TransactionRecord
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.startup import BackgroundStartup, StartupGate, StartupStep


class TestStartupGate:
    def test_the_gui_gate_says_the_stage_and_the_dialog_that_waits(self):
        gate = StartupGate(report_stage=True, details_provider=lambda: {"modal_dialogs": ["Ghidra User Agreement"]})
        gate.set_stage("front_end")
        with pytest.raises(DomainError) as raised:
            asyncio.run(gate.wait(0.01))
        error = raised.value
        assert error.code is ErrorCode.LOCK_TIMEOUT and error.retryable
        assert error.details == {
            "lock": "startup",
            "timeout": 0.01,
            "stage": "front_end",
            "modal_dialogs": ["Ghidra User Agreement"],
        }
        assert "Ghidra User Agreement" in error.hint

    def test_the_headless_gate_keeps_its_details(self):
        gate = StartupGate()
        gate.set_stage("jvm")
        with pytest.raises(DomainError) as raised:
            asyncio.run(gate.wait(0.01))
        assert raised.value.details == {"lock": "startup", "timeout": 0.01}

    def test_the_startup_records_each_step_as_the_stage(self):
        gate = StartupGate(report_stage=True)
        seen = []
        startup = BackgroundStartup(
            [StartupStep(name, lambda name=name: seen.append(gate.stage), f"{name} failed") for name in ("a", "b")],
            gate,
        )
        startup.start()
        assert startup.join(5)
        assert seen == ["a", "b"] and gate.state == "ready"

    @pytest.mark.parametrize("ghidra_running", [False, True])
    def test_a_failure_after_ghidrarun_started_keeps_serving_the_error(self, ghidra_running):
        """Before GhidraRun the server ends; after it the GUI stays up and every call hears why (spec §12)."""

        def fail():
            raise RuntimeError("STARTUP_FAILED: the program is gone")

        gate = StartupGate(report_stage=True)
        stopped = []
        startup = BackgroundStartup(
            [StartupStep("default_session", fail, "Failed to initialize default session")],
            gate,
            keep_serving_on_failure=lambda: ghidra_running,
        )
        startup.start(stop_serving=lambda: stopped.append(True))
        assert startup.join(5)
        assert gate.state == "failed"
        assert stopped == ([] if ghidra_running else [True])


class TestTransactionRecord:
    @staticmethod
    def info(status: str, wrote: bool):
        return SimpleNamespace(getStatus=lambda: status, hasCommittedDBTransaction=lambda: wrote)

    def test_noted_transactions_decide_the_outcome_without_a_listener(self):
        committed = TransactionRecord()
        committed.note_transaction(self.info("COMMITTED", True))
        rolled_back = TransactionRecord()
        rolled_back.note_transaction(self.info("ABORTED", False))
        still_open = TransactionRecord()
        still_open.note_transaction(self.info("NOT_DONE", False))
        history = TransactionRecord()
        history.note_history_change()
        assert [r.outcome() for r in (committed, rolled_back, still_open, history)] == [
            "committed",
            "rolled_back",
            "unknown",
            "committed",
        ]

    def test_without_a_listener_or_notes_the_outcome_stays_unknown(self):
        assert TransactionRecord().outcome() == "unknown"


class FakeLocator:
    def __init__(self, location: Path, name: str) -> None:
        self._location = location
        self._name = name

    def getLocation(self):
        return str(self._location)

    def getName(self):
        return self._name


class FakeProject:
    def __init__(self, location: Path, name: str) -> None:
        self.locator = FakeLocator(location, name)
        self.closed = False

    def getProjectLocator(self):
        return self.locator

    def equals(self, other):
        return other is self

    def close(self):
        self.closed = True


class TestGuiProjectHandle:
    @pytest.fixture
    def gui_project(self, tmp_path, monkeypatch):
        (tmp_path / "sample.gpr").write_text("")
        project = FakeProject(tmp_path, "sample")
        monkeypatch.setattr(gui_handle_module, "active_gui_project", lambda: project)
        monkeypatch.setattr(gui_handle_module._RuntimeProject, "java_project", project)
        saves = []
        monkeypatch.setattr(gui_handle_module, "save_in_gui", lambda _project, program: saves.append(program))
        project.saves = saves
        return project

    def test_it_borrows_only_the_runtime_project(self, gui_project, tmp_path_factory):
        other = tmp_path_factory.mktemp("other")
        (other / "other.gpr").write_text("")
        with pytest.raises(HeadlessError) as raised:
            GuiProjectHandle(str(other / "other.gpr"), None)
        assert raised.value.code == "GUI_UNSUPPORTED" and raised.value.details == {"reason": "other_project"}

    @pytest.mark.parametrize("reopened", [False, True])
    def test_the_runtime_stays_closed_once_the_human_closed_its_project(
        self, gui_project, monkeypatch, tmp_path, reopened
    ):
        """Opening the same project again is a new project object: nothing binds to it (spec §5.1)."""
        from ghidra_mcp.infrastructure.ghidra_adapter.runtime.gui_operations import RuntimeGuiOperations

        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        now_open = FakeProject(tmp_path, "sample" if reopened else "other")
        monkeypatch.setattr(gui_handle_module, "active_gui_project", lambda: now_open)
        calls = [
            lambda: GuiProjectHandle(gui_project.locator.getLocation(), "sample"),
            handle.get_java_project,
            RuntimeGuiOperations(store=SimpleNamespace()).get_gui_context,
        ]
        for call in calls:
            with pytest.raises(HeadlessError) as raised:
                call()
            assert raised.value.code == "SESSION_NOT_FOUND"
            assert raised.value.details == {"reason": "gui_project_closed"}
        assert handle.is_closed()

    def test_an_operation_after_the_human_switched_projects_hears_so(self, gui_project, monkeypatch, tmp_path):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        monkeypatch.setattr(gui_handle_module, "active_gui_project", lambda: FakeProject(tmp_path, "other"))
        with pytest.raises(HeadlessError) as raised, handle.hold_program(FakeProgram()):
            pass
        assert raised.value.code == "SESSION_NOT_FOUND"
        assert raised.value.details == {"reason": "gui_project_closed"}

    def test_releasing_a_program_only_unbinds_it(self, gui_project):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        program = object()
        handle._program_keys.append((program, ("/", "a.exe")))
        handle._open_programs.add(("/", "a.exe"))
        handle._refcount = 1
        handle.release_program(program, save=True)
        assert gui_project.saves == [] and not gui_project.closed
        assert handle._open_programs == set() and not handle.is_closed()
        with pytest.raises(HeadlessError) as raised:
            handle.release_program(program)
        assert raised.value.code == "PROGRAM_NOT_OPEN"

    def test_closing_the_handle_leaves_the_gui_project_open(self, gui_project):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        handle.close(force=True)
        handle._close_project_locked()
        assert handle.is_closed() and not gui_project.closed

    def test_it_expires_when_the_human_switches_projects(self, gui_project, monkeypatch, tmp_path):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        monkeypatch.setattr(gui_handle_module, "active_gui_project", lambda: FakeProject(tmp_path, "sample"))
        assert handle.is_closed()

    @pytest.mark.parametrize(
        ("call", "reason"),
        [
            (lambda handle: handle.open_program("/a.exe", version=2), "version"),
            (lambda handle: handle.release_program(object(), remove_program=True), "remove_program"),
            (lambda handle: handle.import_program("/tmp/x"), "import"),
            (lambda handle: handle.checkout_program("/a.exe"), "version_control"),
            (lambda handle: handle.delete_domain_file("/a.exe"), "delete_file"),
        ],
    )
    def test_what_the_human_does_in_the_gui_is_refused(self, gui_project, call, reason):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        with pytest.raises(HeadlessError) as raised:
            call(handle)
        assert raised.value.code == "GUI_UNSUPPORTED" and raised.value.details == {"reason": reason}

    def test_a_save_goes_through_the_gui(self, gui_project):
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        program = SimpleNamespace(isChanged=lambda: True)
        assert handle.save_program(program) is True
        assert gui_project.saves == [program]
        unchanged = SimpleNamespace(isChanged=lambda: False)
        assert handle.save_program(unchanged) is False

    def test_an_operation_keeps_the_program_open_until_it_ends(self, gui_project, monkeypatch):
        monkeypatch.setattr(gui_handle_module, "_new_consumer", object)
        monkeypatch.setattr(gui_handle_module, "is_open_in_gui", lambda _project, program: program.in_tab)
        program = FakeProgram()
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        with handle.hold_program(program) as still_open:
            assert still_open and len(program.consumers) == 2
            program.close_tab()
            assert not program.closed
        assert program.closed and program.consumers == []

    def test_a_program_the_human_closed_is_not_held(self, gui_project, monkeypatch):
        monkeypatch.setattr(gui_handle_module, "_new_consumer", object)
        monkeypatch.setattr(gui_handle_module, "is_open_in_gui", lambda _project, program: program.in_tab)
        closed = FakeProgram()
        closed.close_tab()
        other_consumer = FakeProgram()
        other_consumer.in_tab = False
        handle = GuiProjectHandle(gui_project.locator.getLocation(), "sample")
        for program in (closed, other_consumer, None):
            with handle.hold_program(program) as still_open:
                assert not still_open
        assert closed.consumers == [] and len(other_consumer.consumers) == 1


class FakeProgram:
    """A DomainObject's consumers: addConsumer fails once closed; the last release closes it."""

    def __init__(self) -> None:
        self.tool = object()
        self.consumers = [self.tool]
        self.closed = False
        self.in_tab = True

    def addConsumer(self, consumer):
        if self.closed:
            return False
        self.consumers.append(consumer)
        return True

    def release(self, consumer):
        self.consumers.remove(consumer)
        if not self.consumers:
            self.closed = True

    def close_tab(self):
        self.in_tab = False
        self.release(self.tool)


class TestOperationHold:
    """Every operation on a GUI program runs inside the handle's hold (spec §5.2)."""

    @staticmethod
    def session(handle, program=None):
        return SimpleNamespace(get_project_handle=lambda: handle, get_program=lambda: program)

    def test_a_headless_session_runs_without_a_hold(self):
        from ghidra_mcp.infrastructure.ghidra_adapter.runtime.core_execution import RuntimeCoreExecution

        ran = []
        with RuntimeCoreExecution._program_held_locked(self.session(SimpleNamespace()), "default"):
            ran.append(True)
        assert ran == [True]

    @pytest.mark.parametrize("still_open", [True, False])
    def test_the_operation_runs_inside_the_hold_or_the_target_has_expired(self, still_open):
        from contextlib import contextmanager

        from ghidra_mcp.infrastructure.ghidra_adapter.runtime.core_execution import RuntimeCoreExecution

        events = []

        @contextmanager
        def hold_program(program):
            events.append(("hold", program))
            yield still_open
            events.append("release")

        session = self.session(SimpleNamespace(hold_program=hold_program), program="program")
        if still_open:
            with RuntimeCoreExecution._program_held_locked(session, "default"):
                events.append("operation")
            assert events == [("hold", "program"), "operation", "release"]
            return
        with pytest.raises(HeadlessError) as raised:
            with RuntimeCoreExecution._program_held_locked(session, "default"):
                events.append("operation")
        assert raised.value.code == "PROGRAM_NOT_OPEN" and raised.value.details == {"reason": "closed_in_gui"}
        assert "operation" not in events
