"""What running the GUI backend on Windows needs, without a JVM (spec §4.5, §10.1, §10.6; G50).

The helpers that take ``windows=`` run everywhere with the Windows branch chosen; the tests that
need Windows itself (job objects, sharing violations, the console's signals) skip elsewhere.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidra_headless.gui import project_handle as gui_handle_module
from ghidra_mcp.presentation import gui_registry, gui_relay
from ghidra_mcp.presentation import gui_runtime as runtime_module
from ghidra_mcp.presentation.gui_registry import FileLock, ProjectRegistry, RuntimeRecord

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows only")
SRC = str(Path(gui_registry.__file__).parents[2])


def record() -> RuntimeRecord:
    return RuntimeRecord(
        runtime_id="r1",
        pid=123,
        endpoint="http://127.0.0.1:1234/mcp",
        token="secret",
        public=False,
        project_file="C:/p/GUI.gpr",
        ghidra_install_dir="C:/g",
        mecha_version="1.1.0",
        fingerprint={"tools": ["a"]},
    )


class TestProjectLocation:
    @pytest.mark.parametrize(
        ("location", "windows", "expected"),
        [
            ("/C:/a/b", True, "C:/a/b"),  # ProjectLocator.getLocation() on Windows
            ("//server/share/a", True, "//server/share/a"),  # a UNC path stays one
            ("/home/me/a", True, "/home/me/a"),
            ("/C:/a/b", False, "/C:/a/b"),  # elsewhere nothing changes
        ],
    )
    def test_ghidras_location_reads_as_a_path_of_this_os(self, location, windows, expected):
        assert gui_handle_module.native_project_location(location, windows=windows) == expected

    @WINDOWS_ONLY
    def test_the_project_ghidra_opened_is_the_requested_one(self, tmp_path):
        locator = SimpleNamespace(getLocation=lambda: "/" + tmp_path.as_posix(), getName=lambda: "GUI")
        project = SimpleNamespace(getProjectLocator=lambda: locator)
        assert gui_handle_module.is_same_project(project, str(tmp_path), "GUI")
        assert not gui_handle_module.is_same_project(project, str(tmp_path / "other"), "GUI")


class TestRegistryRetries:
    def test_windows_tries_again_while_another_handle_refuses_it(self, monkeypatch):
        monkeypatch.setattr(gui_registry, "_SHARING_RETRY_INTERVAL", 0)
        attempts = []

        def refused_twice():
            attempts.append(1)
            if len(attempts) < 3:
                raise PermissionError(13, "The process cannot access the file")
            return "done"

        assert gui_registry._retry_sharing(refused_twice, windows=True) == "done"
        assert len(attempts) == 3

    def test_elsewhere_a_permission_error_is_final(self):
        attempts = []

        def refused():
            attempts.append(1)
            raise PermissionError(13, "denied")

        with pytest.raises(PermissionError):
            gui_registry._retry_sharing(refused, windows=False)
        assert len(attempts) == 1

    def test_the_retries_end(self, monkeypatch):
        monkeypatch.setattr(gui_registry, "_SHARING_RETRY_SECONDS", 0.05)

        def refused():
            raise PermissionError(13, "denied")

        started = time.monotonic()
        with pytest.raises(PermissionError):
            gui_registry._retry_sharing(refused, windows=True)
        assert time.monotonic() - started < 2

    @WINDOWS_ONLY
    def test_the_registry_is_under_local_app_data(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert gui_registry.registry_dir() == tmp_path / "mecha_ghidra" / "gui-runtimes"

    @WINDOWS_ONLY
    def test_a_record_another_process_holds_open_is_replaced_read_and_removed(self, tmp_path):
        """A relay reading the record keeps Windows from replacing or deleting it (WinError 5 and 32)."""
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        registry.write(record())
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys, time\nhandle = open(sys.argv[1])\nprint('open', flush=True)\ntime.sleep(0.5)\n",
                str(registry.record_path),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout.readline().strip() == "open"
            registry.write(record())  # waits for the holder to let go
            assert registry.read() is not None
        finally:
            holder.wait(10)
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys, time\nhandle = open(sys.argv[1])\nprint('open', flush=True)\ntime.sleep(0.5)\n",
                str(registry.record_path),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout.readline().strip() == "open"
            registry.remove()
            assert not registry.record_path.exists()
        finally:
            holder.wait(10)

    @WINDOWS_ONLY
    def test_the_lock_ends_with_its_process_and_no_child_keeps_it(self, tmp_path):
        """A holder ended with TerminateProcess frees its msvcrt lock, although a child it started still runs."""
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import subprocess, sys, time
                    sys.path.insert(0, {SRC!r})
                    from ghidra_mcp.presentation.gui_registry import FileLock
                    assert FileLock(__import__("pathlib").Path({str(tmp_path / "k.lock")!r})).try_acquire()
                    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
                    print(child.pid, flush=True)
                    time.sleep(60)
                    """
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        child_pid = int(holder.stdout.readline())
        try:
            registry_lock = FileLock(tmp_path / "k.lock")
            assert not registry_lock.try_acquire()
            holder.kill()
            holder.wait(10)
            assert registry_lock.acquire(2)
            registry_lock.release()
        finally:
            subprocess.run(["taskkill", "/PID", str(child_pid), "/F"], capture_output=True, check=False)


class EndedProcess:
    """A launched runtime that has ended with ``returncode``."""

    def __init__(self, returncode: int, pid: int = 4242) -> None:
        self.pid = pid
        self.returncode = returncode

    def poll(self) -> int:
        return self.returncode


BASE_PYTHON = getattr(sys, "_base_executable", None) or sys.executable


def watch(pid: int):
    """The process ``pid``, watched as a relay watches the runtime it started; None when it is gone."""
    handle = gui_relay._handle_to_watch(pid)
    return None if handle is None else gui_relay._DetachedRuntime(pid, handle)


def ended(process, seconds: float = 30.0):
    """``process.poll()`` once the process ended, or None if it still runs after ``seconds``."""
    deadline = time.monotonic() + seconds
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    return process.poll()


class TestRuntimeLaunch:
    def test_a_venv_runtime_starts_on_the_base_interpreter_on_windows(self, monkeypatch):
        """A venv's python.exe is a redirector: its child would be the runtime, with a console of its own."""
        monkeypatch.setattr(sys, "executable", r"C:\work\.venv\Scripts\python.exe")
        monkeypatch.setattr(sys, "_base_executable", r"C:\Python313\python.exe", raising=False)
        python, env = gui_relay._runtime_python(windows=True)
        assert python == r"C:\Python313\python.exe"
        assert env is not None and env["__PYVENV_LAUNCHER__"] == r"C:\work\.venv\Scripts\python.exe"

    @pytest.mark.parametrize(
        ("windows", "base"),
        [(False, "/usr/bin/python3"), (True, r"C:\work\.venv\Scripts\python.exe")],
        ids=["posix-venv", "windows-no-venv"],
    )
    def test_otherwise_the_runtime_starts_on_this_python(self, monkeypatch, windows, base):
        monkeypatch.setattr(sys, "executable", r"C:\work\.venv\Scripts\python.exe")
        monkeypatch.setattr(sys, "_base_executable", base, raising=False)
        assert gui_relay._runtime_python(windows=windows) == (r"C:\work\.venv\Scripts\python.exe", None)

    @pytest.mark.parametrize(
        ("in_a_job", "flags", "kept"),
        [
            (False, 0, False),  # outside every job
            (True, 0x0, False),  # a job that only groups processes (the Claude desktop app runs its children in one)
            (True, 0x3000, True),  # KILL_ON_JOB_CLOSE, as the MCP Python SDK's job: the GUI would end with the client
            (True, 0x2800, True),
        ],
    )
    def test_only_a_job_that_ends_its_processes_on_close_keeps_the_runtime(self, in_a_job, flags, kept):
        assert gui_relay.kept_by_a_client_job(in_a_job=lambda _pid: in_a_job, job_limit_flags=lambda: flags) is kept

    @WINDOWS_ONLY
    def test_the_relay_says_what_to_do_when_the_runtime_ended_for_a_job(self, tmp_path):
        """The runtime that a job would end with the client exits at once; the relay gives the guidance."""
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        error = gui_relay._wait_for_registration(registry, EndedProcess(gui_relay.EXIT_KEPT_BY_CLIENT_JOB))
        assert error.code.value == "RUNTIME_UNAVAILABLE"
        assert "start it first in a terminal with --backend gui --transport http" in error.message
        assert "would end the Ghidra GUI runtime" in error.details["cause_message"]

    def test_another_early_exit_is_still_a_failed_start(self, tmp_path):
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        error = gui_relay._wait_for_registration(registry, EndedProcess(1))
        assert error.code.value == "STARTUP_FAILED" and error.details["stage"] == "launch"

    @WINDOWS_ONLY
    def test_the_runtime_outlives_a_client_that_ends_the_relays_process_tree(self, tmp_path):
        """Claude Code ends a stdio server's process tree by parent pid when the server still runs a few seconds
        after its stdin closed, as ``taskkill /T /F`` does.  The runtime starts through a starter that ends at
        once, so its parent is gone; a child the relay starts itself dies with the tree (spec §10.6)."""
        log = tmp_path / "runtime.log"
        relay_script = textwrap.dedent(
            f"""
            import subprocess, sys, time
            sys.path.insert(0, {SRC!r})
            from ghidra_mcp.presentation import gui_relay
            sleep = [{BASE_PYTHON!r}, "-c", "import time; time.sleep(60)"]
            with open({str(log)!r}, "wb") as log:
                runtime = gui_relay._start_detached(sleep, None, {str(log)!r}, log)
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            child = subprocess.Popen(sleep, creationflags=flags | subprocess.CREATE_BREAKAWAY_FROM_JOB)
            print(runtime.pid, child.pid, flush=True)
            time.sleep(60)
            """
        )
        relay = subprocess.Popen([sys.executable, "-c", relay_script], stdout=subprocess.PIPE, text=True)
        runtime_pid, child_pid = (int(pid) for pid in relay.stdout.readline().split())
        try:
            runtime, child = watch(runtime_pid), watch(child_pid)
            assert runtime is not None and child is not None
            # Not checked: a process of the tree may end before taskkill reaches it (the venv redirector's job
            # ends the relay with it), and taskkill then exits with 255.
            killed = subprocess.run(["taskkill", "/PID", str(relay.pid), "/T", "/F"], capture_output=True, text=True)
            relay.wait(10)
            assert ended(child) == 1, killed  # taskkill /F ends each process of the tree with exit code 1
            assert runtime.poll() is None
        finally:
            for pid in (runtime_pid, child_pid):
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, check=False)

    @WINDOWS_ONLY
    def test_a_job_around_the_starter_that_forbids_leaving_keeps_the_runtime_which_says_so(self, tmp_path):
        """Nested jobs: the relay's own job lets the starter leave, one around it that ends its processes on close
        does not.  The starter then starts the runtime in that job, and the runtime finds the job and ends with
        EXIT_KEPT_BY_CLIENT_JOB, as it does without a starter (spec §10.6)."""
        log = tmp_path / "runtime.log"
        check = (
            f"import sys; sys.path.insert(0, {SRC!r}); from ghidra_mcp.presentation import gui_relay; "
            "sys.exit(gui_relay.EXIT_KEPT_BY_CLIENT_JOB if gui_relay.kept_by_a_client_job() else 0)"
        )
        relay_script = textwrap.dedent(
            f"""
            import ctypes, sys, time
            from ctypes import wintypes
            sys.path.insert(0, {SRC!r})
            from ghidra_mcp.presentation import gui_relay
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            # Outer: KILL_ON_JOB_CLOSE, no leaving; inner (the relay's own): the same, but BREAKAWAY_OK.
            for limits in (0x2000, 0x2000 | 0x800):
                job = kernel32.CreateJobObjectW(None, None)
                info = (ctypes.c_ubyte * 144)()
                ctypes.c_uint32.from_buffer(info, 16).value = limits
                assert kernel32.SetInformationJobObject(job, 9, info, 144), ctypes.get_last_error()
                assert kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()), ctypes.get_last_error()
            python, env = gui_relay._runtime_python()
            with open({str(log)!r}, "wb") as out:
                runtime = gui_relay._start_detached([python, "-c", {check!r}], env, {str(log)!r}, out)
            deadline = time.monotonic() + 60
            while runtime.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            print(runtime.returncode, flush=True)
            """
        )
        extra = {"__PYVENV_LAUNCHER__": sys.executable} if BASE_PYTHON != sys.executable else {}
        relay = subprocess.run(
            [BASE_PYTHON, "-c", relay_script], env={**os.environ, **extra}, capture_output=True, text=True, timeout=120
        )
        assert relay.stdout.strip() == str(gui_relay.EXIT_KEPT_BY_CLIENT_JOB), (
            relay.stdout,
            relay.stderr,
            log.read_text(),
        )

    @WINDOWS_ONLY
    def test_the_relay_reads_the_runtimes_exit_code_through_the_starter(self, tmp_path):
        """The starter holds the runtime until the relay does: an exit at once still reaches the relay."""
        log_path = tmp_path / "runtime.log"
        with open(log_path, "wb") as log:
            runtime = gui_relay._start_detached([BASE_PYTHON, "-c", "raise SystemExit(3)"], None, log_path, log)
        assert runtime.pid != os.getpid()
        assert ended(runtime) == gui_relay.EXIT_KEPT_BY_CLIENT_JOB

    @WINDOWS_ONLY
    def test_the_starter_hands_the_venv_on_to_the_runtime(self, tmp_path):
        """The base interpreter drops __PYVENV_LAUNCHER__ once read (bpo-35873): the runtime still runs for the venv."""
        python, env = gui_relay._runtime_python()
        if env is None:
            pytest.skip("the tests do not run in a venv")
        log_path = tmp_path / "runtime.log"
        with open(log_path, "wb") as log:
            runtime = gui_relay._start_detached(
                [python, "-c", "import sys; print(sys.prefix != sys.base_prefix)"], env, log_path, log
            )
        assert ended(runtime) == 0
        assert log_path.read_text().strip() == "True"

    @WINDOWS_ONLY
    def test_a_runtime_its_starter_could_not_start_is_a_failed_start(self, tmp_path):
        (tmp_path / "GUI.gpr").write_text("")
        registry = ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")
        with open(registry.log_path, "wb") as log:
            # A log the starter cannot open: it ends with its traceback and starts nothing.
            runtime = gui_relay._start_detached([BASE_PYTHON, "-c", "pass"], None, tmp_path, log)
        assert runtime.returncode == 1
        error = gui_relay._wait_for_registration(registry, runtime)
        assert error.code.value == "STARTUP_FAILED" and error.details["stage"] == "launch"
        assert "PermissionError" in error.details["cause_message"]

    @WINDOWS_ONLY
    def test_the_job_of_a_process_can_be_read(self):
        assert isinstance(gui_relay._in_a_job(os.getpid()), bool)
        with pytest.raises(OSError):
            gui_relay._in_a_job(0x7FFFFFFC)  # no such process
        if gui_relay._in_a_job(os.getpid()):
            assert isinstance(gui_relay._own_job_limit_flags(), int)
        assert isinstance(gui_relay.kept_by_a_client_job(), bool)


class TestRuntimeSignals:
    @pytest.fixture
    def runtime(self, monkeypatch):
        asked: list[bool] = []
        monkeypatch.setattr(runtime_module, "request_gui_exit", lambda: asked.append(True) or True)
        gui = runtime_module.GuiRuntime(ghidra_path=None, project_location="C:/p", project_name="GUI")
        gui.launch.ghidra_run_started.set()
        return gui, asked

    @pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGBREAK"])
    def test_the_exit_signals_ask_ghidra_to_exit(self, runtime, name):
        """Ctrl+C, SIGTERM and, on Windows, Ctrl+Break start Ghidra's own exit with its save prompt."""
        if not hasattr(signal, name):
            pytest.skip(f"no {name} on this OS")
        gui, asked = runtime
        gui._on_signal(getattr(signal, name))
        assert asked == [True]

    @pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX: Windows has no SIGHUP")
    def test_sighup_only_leaves_the_terminal(self, runtime, monkeypatch):
        gui, asked = runtime
        left = []
        monkeypatch.setattr(runtime_module, "_detach_from_terminal", lambda: left.append(True))
        gui._on_signal(signal.SIGHUP)
        assert left == [True] and asked == []

    def test_a_signal_reaches_the_watcher_through_the_wakeup_channel(self):
        previous = signal.signal(signal.SIGINT, runtime_module._ignore_signal)
        try:
            receive, ends = runtime_module._wakeup_channel()
            try:
                signal.raise_signal(signal.SIGINT)
                if os.name == "nt":
                    ends[0].settimeout(5)
                else:
                    assert select.select([ends[0]], [], [], 5)[0]
                assert receive() == bytes([signal.SIGINT])
            finally:
                signal.set_wakeup_fd(-1)
                for end in ends:
                    if isinstance(end, int):
                        os.close(end)
                    else:
                        end.close()
        finally:
            signal.signal(signal.SIGINT, previous)
