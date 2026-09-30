"""GUI backend acceptance tests (spec §14.3, G03 to G38 of Phase 1) against a real Ghidra GUI.

Run only with GHIDRA_GUI_VALIDATION=1, a display (macOS, Windows, or Linux with
Xvfb) and GHIDRA_INSTALL_DIR; they open Ghidra windows.  Run them in their own
pytest invocation: each scenario starts ``tests/gui_driver.py`` in a subprocess,
where the real CLI runs the GUI on the main thread and a driver thread checks it
from inside (see that module).  Every run uses a copy of one prepared project and
a throwaway Ghidra settings directory, so the user's projects and settings are
never touched.  On Windows each scenario gets a hidden console of its own, so
the Ctrl+C and Ctrl+Break it sends itself reach nothing else.
GHIDRA_GUI_TEST_TIME_SCALE stretches the harness's waits on a slow machine.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_GUI_VALIDATION") != "1" or not os.environ.get("GHIDRA_INSTALL_DIR"),
    reason="Run only when GHIDRA_GUI_VALIDATION=1 and GHIDRA_INSTALL_DIR are set (opens Ghidra GUI windows)",
)

TIME_SCALE = float(os.environ.get("GHIDRA_GUI_TEST_TIME_SCALE") or "1")
SCENARIO_TIMEOUT_SECONDS = 420 * TIME_SCALE


def _free_port() -> int:
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        return reserved.getsockname()[1]


class Run:
    def __init__(self, workdir: Path, returncode: int, results: list[dict], log: str) -> None:
        self.workdir = workdir
        self.returncode = returncode
        self.results = results
        self.log = log

    def check(self, check: str) -> dict:
        matches = [line for line in self.results if line["check"] == check]
        assert matches, f"{check} was not reported; driver lines: {self.results}\n{self.log[-6000:]}"
        return matches[-1]

    def assert_ok(self, *checks: str) -> None:
        errors = [line for line in self.results if line["check"] == "driver_error"]
        assert not errors, errors
        failed = [self.check(check) for check in checks if not self.check(check)["ok"]]
        assert not failed, json.dumps(failed, indent=1, default=str)


def run_scenario(
    scenario: str,
    tmp_path: Path,
    prepared,
    *server_args: str,
    env: dict[str, str | None] | None = None,
    before=None,
) -> Run:
    project_source, settings_source = prepared
    workdir = tmp_path / scenario
    project = workdir / "project"
    settings = workdir / "settings"
    exports = workdir / "exports"
    shutil.copytree(project_source, project)
    shutil.copytree(settings_source, settings)
    exports.mkdir(parents=True)
    if before is not None:
        before(workdir)
    port = _free_port()
    results = workdir / "results.jsonl"
    command = [
        sys.executable,
        str(TESTS / "gui_driver.py"),
        scenario,
        str(results),
        str(port),
        "--",
        "--backend",
        "gui",
        "--transport",
        "http",
        "--mcp-port",
        str(port),
        "--project-location",
        str(project),
        "--project-name",
        "GUI",
        "--allowed-project-root",
        str(workdir),
        "--allowed-export-root",
        str(exports),
        *server_args,
    ]
    registry_home = workdir / "home"
    registry_home.mkdir(exist_ok=True)
    process_env = {
        **os.environ,
        # Ghidra's settings, cache and temporary files are this run's, apart from the user's Ghidra.
        "JAVA_TOOL_OPTIONS": (
            f"-Dapplication.settingsdir={settings} -Dapplication.cachedir={workdir / 'ghidra-cache'}"
            f" -Dapplication.tempdir={workdir / 'ghidra-temp'}"
        ),
        "GUI_TEST_EXPORTS": str(exports),
        "PYTHONPATH": os.pathsep.join([str(TESTS), str(ROOT / "src")]),
        # The runtime registers for relays (spec §10.1): in this run's directory, not the user's.
        "HOME": str(registry_home),
        "XDG_STATE_HOME": str(registry_home / "state"),
        "LOCALAPPDATA": str(registry_home / "localappdata"),
    }
    if os.name == "nt":  # Ghidra's temporary files too, apart from the user's Ghidra
        (workdir / "temp").mkdir(exist_ok=True)
        process_env.update(TEMP=str(workdir / "temp"), TMP=str(workdir / "temp"))
    for key, value in (env or {}).items():  # None removes the variable
        if value is None:
            process_env.pop(key, None)
        else:
            process_env[key] = value
    with (workdir / "server.log").open("w") as log, _sigint_not_ignored():
        process = subprocess.Popen(
            command, cwd=ROOT, env=process_env, stdout=log, stderr=subprocess.STDOUT, **_own_console()
        )
        try:
            returncode = process.wait(SCENARIO_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            _dump_threads(process.pid, workdir / "jstack.log")
            process.kill()
            returncode = process.wait(30)
    lines = []
    if results.exists():
        lines = [json.loads(line) for line in results.read_text().splitlines() if line.strip()]
    return Run(workdir, returncode, lines, (workdir / "server.log").read_text(errors="replace"))


def _dump_threads(pid: int, path: Path) -> None:
    """Where a scenario that ran out of time waits: the JVM's threads, from the JDK's jstack, if there is one."""
    java_home = os.environ.get("JAVA_HOME")
    jstack = shutil.which("jstack") or (java_home and shutil.which("jstack", path=str(Path(java_home) / "bin")))
    if not jstack:
        return
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        dumped = subprocess.run([jstack, str(pid)], capture_output=True, text=True, timeout=60)
        path.write_text(dumped.stdout + dumped.stderr)


def _own_console() -> dict:
    """On Windows, a hidden console of the scenario's own: the console events it sends reach it alone."""
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0  # SW_HIDE
    return {"creationflags": subprocess.CREATE_NEW_CONSOLE, "startupinfo": startup}


@contextlib.contextmanager
def _sigint_not_ignored():
    """Start the scenario with SIGINT at its default, which G34 needs.

    A job that a non-interactive shell starts with ``&`` ignores SIGINT, and
    the server keeps an ignored signal ignored (like ``nohup``).  Only an
    ignored signal survives ``exec``, so a handler here gives the child the default.
    Windows has the like: a process started in a new process group (a CI
    runner starts its steps so) has Ctrl+C disabled, and its children inherit
    that.  It is enabled here for the scenario to inherit, as in a terminal;
    Windows cannot read the old setting back, so it stays enabled.
    """
    if os.name == "nt":
        import ctypes

        ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False)
        yield
        return
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def test_live_sharing_in_one_gui_session(tmp_path, prepared):
    """G03, G05, G09 to G31 (G28's first half), G33, G36, G38: one GUI session, the human simulated on the EDT."""
    # A short lock timeout for G23; a slow machine's background transactions (a GUI command's trailing
    # task, auto-analysis) need longer to end before the AI's next write.
    lock_timeout = f"{1 * TIME_SCALE:g}"
    run = run_scenario(
        "main", tmp_path, prepared, "--domain-path", "/WinHelloCPP.exe", "--lock-timeout-seconds", lock_timeout
    )
    run.assert_ok(
        "G03", "G05", "G09", "G10", "G11", "G12", "G13", "G14", "G15", "G16", "G17", "G18", "G19", "G20",
        "G21", "G22", "G23", "G24", "G25", "G26", "G27", "G28", "G29", "G30", "G31", "G33", "G36", "G38",
        "done",
    )  # fmt: skip


def test_a_load_that_shows_the_analysis_prompt_does_not_block(tmp_path, prepared):
    """G37: the first program of an empty CodeBrowser becomes current, and Ghidra asks to analyze it."""
    run = run_scenario("prompt", tmp_path, prepared)
    run.assert_ok("G37", "done")


def test_signals_use_ghidras_own_exit(tmp_path, prepared):
    """G32 and G34: SIGINT and SIGTERM ask about unsaved changes; Cancel keeps running; SIGHUP changes nothing."""
    run = run_scenario("exit", tmp_path, prepared, "--domain-path", "/WinHelloCPP.exe")
    run.assert_ok("G32", "G34", "exiting")
    assert run.returncode == 0, run.log[-4000:]


def test_the_requested_project_opens_not_the_last_one(tmp_path, prepared):
    """G08: the settings' last project is another one; GhidraRun opens the requested project.

    G28, second half: saving a read-only file's program fails without a dialog.
    """

    def point_last_project_elsewhere(workdir: Path) -> None:
        other = workdir / "other"
        shutil.copytree(workdir / "project", other)
        (other / "GUI.gpr").rename(other / "Other.gpr")
        (other / "GUI.rep").rename(other / "Other.rep")
        for preferences in (workdir / "settings").rglob("preferences"):
            text = "\n".join(
                line for line in preferences.read_text().splitlines() if not line.startswith("LastOpenedProject=")
            )
            preferences.write_text(text + f"\nLastOpenedProject={other / 'Other'}\n")

    run = run_scenario(
        "restore", tmp_path, prepared, before=point_last_project_elsewhere, env={"GUI_TEST_EXPECT_PROJECT": "GUI"}
    )
    run.assert_ok("G08", "G28", "done")


def test_a_project_another_process_holds_is_not_opened(tmp_path, prepared):
    """G07: the lock is checked before the GUI starts; the call says PROJECT_LOCKED; the lock stays."""
    holder = {}

    def hold_the_project(workdir: Path) -> None:
        # The holder's Ghidra settings, cache and temporary files go to its own directory in the run's.
        script = (
            "import os, sys\n"
            "from ghidra_headless.launcher import prepare_headless_launcher, start_headless_jvm\n"
            "launcher = prepare_headless_launcher(os.environ['GHIDRA_INSTALL_DIR'])\n"
            "launcher.add_vmargs(*('-Dapplication.' + name + '=' + os.path.join(sys.argv[2], name)\n"
            "                      for name in ('settingsdir', 'cachedir', 'tempdir')))\n"
            "start_headless_jvm(os.environ['GHIDRA_INSTALL_DIR'], launcher=launcher)\n"
            "from ghidra.base.project import GhidraProject\n"
            "project = GhidraProject.openProject(sys.argv[1], 'GUI', False)\n"
            "print('holding', flush=True)\n"
            "sys.stdin.read()\n"
            "project.close()\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(workdir / "project"), str(workdir / "holder")],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert process.stdout.readline().strip() == "holding"
        holder["process"] = process

    try:
        run = run_scenario("failed_start", tmp_path, prepared, before=hold_the_project)
        line = run.check("failed_start")
        details = (line.get("error") or {}).get("details") or {}
        assert line["ok"] and details.get("stage") == "project_lock", line
        assert details.get("cause_type") == "PROJECT_LOCKED", line
        assert run.returncode == 1
        assert (run.workdir / "project" / "GUI.lock").exists()
        assert holder["process"].poll() is None
    finally:
        process = holder.get("process")
        if process is not None:
            process.stdin.close()
            process.wait(60)


@pytest.mark.skipif(sys.platform in ("darwin", "win32"), reason="Linux: DISPLAY decides whether there is a display")
@pytest.mark.parametrize("display", [None, ":987"])
def test_no_usable_display_fails_before_ghidrarun(tmp_path, prepared, display):
    """G06: no DISPLAY, or one no X server answers: STARTUP_FAILED(display), and no stuck GhidraRun."""
    started = time.monotonic()
    run = run_scenario("failed_start", tmp_path, prepared, env={"DISPLAY": display})
    line = run.check("failed_start")
    assert line["ok"] and ((line.get("error") or {}).get("details") or {}).get("stage") == "display", line
    assert run.returncode == 1 and time.monotonic() - started < 120
