"""Build the Ghidra project the GUI integration tests share, headlessly (tests/test_gui_integration.py).

Usage: python tests/gui_project_setup.py <project_dir> <settings_dir>

The project ``GUI`` holds Ghidra's exercise PE four times: /WinHelloCPP.exe,
/Second.exe and /Third.exe analyzed, /Unanalyzed.exe as imported (Ghidra asks
to analyze it when it becomes a tool's current program).  The settings
directory is a throwaway one; the test run seeds the user agreement there
only, as the spec allows for tests (§4.6).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from binary_fixtures import GHIDRA_EXERCISE_PE

project_dir, settings_dir = Path(sys.argv[1]), Path(sys.argv[2])
project_dir.mkdir(parents=True, exist_ok=True)
settings_dir.mkdir(parents=True, exist_ok=True)

from ghidra_headless.launcher import prepare_headless_launcher, start_headless_jvm  # noqa: E402

launcher = prepare_headless_launcher(os.environ["GHIDRA_INSTALL_DIR"])
launcher.add_vmargs(f"-Dapplication.settingsdir={settings_dir}")
start_headless_jvm(os.environ["GHIDRA_INSTALL_DIR"], launcher=launcher)

from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.framework import Application  # noqa: E402
from ghidra.program.flatapi import FlatProgramAPI  # noqa: E402
from ghidra.program.util import GhidraProgramUtilities  # noqa: E402
from java.io import File  # noqa: E402

project = GhidraProject.createProject(str(project_dir), "GUI", False)
try:
    for name, analyze in (
        ("WinHelloCPP.exe", True),
        ("Second.exe", True),
        ("Third.exe", True),
        ("Unanalyzed.exe", False),
    ):
        program = project.importProgram(File(str(GHIDRA_EXERCISE_PE)))
        if analyze:
            FlatProgramAPI(program).analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
        project.saveAs(program, "/", name, True)
        project.close(program)
finally:
    project.close()

preferences = Path(str(Application.getUserSettingsDirectory())) / "preferences"
with preferences.open("a", encoding="utf-8") as handle:
    handle.write("GhidraShowWhatsNew=false\nSHOW_TIPS=false\nUSER_AGREEMENT=ACCEPT\n")
print(f"PROJECT={project_dir / 'GUI.gpr'}")
