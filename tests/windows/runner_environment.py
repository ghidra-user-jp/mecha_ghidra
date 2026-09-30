"""Print what a Windows CI runner gives its steps, for the GUI acceptance job (spec §10.6, G50).

Not a check.  A detached runtime outlives its client only where the job
object around the relay lets it leave (or does not end its processes when it
closes), and the GUI needs an interactive window station; the tests' Ctrl+C
reaches a scenario only where Ctrl+C is not disabled for it.  This records
them before the tests run, so a failure there reads at once.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
from ctypes import wintypes

from ghidra_mcp.presentation.gui_relay import _in_a_job, _own_job_limit_flags

_BREAKAWAY_OK = 0x0800
_SILENT_BREAKAWAY_OK = 0x1000
_KILL_ON_JOB_CLOSE = 0x2000
_UOI_FLAGS = 1
_WSF_VISIBLE = 0x0001


class _UserObjectFlags(ctypes.Structure):
    _fields_ = [("fInherit", wintypes.BOOL), ("fReserved", wintypes.BOOL), ("dwFlags", wintypes.DWORD)]


def _job() -> str:
    try:
        if not _in_a_job(os.getpid()):
            return "none"
        flags = _own_job_limit_flags()
    except OSError as exc:
        return f"unreadable ({exc})"
    return (
        f"limit flags {flags:#x}: breakaway {bool(flags & _BREAKAWAY_OK)}, "
        f"silent breakaway {bool(flags & _SILENT_BREAKAWAY_OK)}, kill on close {bool(flags & _KILL_ON_JOB_CLOSE)}"
    )


def _window_station() -> str:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetProcessWindowStation.restype = wintypes.HANDLE
    user32.GetUserObjectInformationW.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]  # fmt: skip
    flags = _UserObjectFlags()
    needed = wintypes.DWORD()
    if not user32.GetUserObjectInformationW(
        user32.GetProcessWindowStation(), _UOI_FLAGS, ctypes.byref(flags), ctypes.sizeof(flags), ctypes.byref(needed)
    ):
        return f"unreadable ({ctypes.WinError(ctypes.get_last_error())})"
    screen = f"{user32.GetSystemMetrics(0)}x{user32.GetSystemMetrics(1)}"
    return f"interactive {bool(flags.dwFlags & _WSF_VISIBLE)}, screen {screen}"


# A child with a console of its own sends itself Ctrl+C, as the tests' scenarios do.
_CTRL_C_PROBE = """
import ctypes, signal, time
got = []
signal.signal(signal.SIGINT, lambda *_: got.append(1))
ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, 0)
deadline = time.monotonic() + 3
while not got and time.monotonic() < deadline:
    time.sleep(0.05)
print("yes" if got else "no")
"""


def _ctrl_c_reaches_a_child() -> str:
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0  # SW_HIDE
    completed = subprocess.run(
        [sys.executable, "-c", _CTRL_C_PROBE],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        startupinfo=startup,
    )
    return completed.stdout.strip() or f"no answer (exit {completed.returncode})"


def main() -> int:
    print(f"Windows {platform.version()} ({platform.machine()}), Python {sys.version.split()[0]}")
    print(f"Job object of this step: {_job()}")
    print(f"Window station: {_window_station()}")
    print(f"Ctrl+C reaches a child as the step starts it: {_ctrl_c_reaches_a_child()}")
    ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False)  # what the GUI tests do before their scenarios
    print(f"Ctrl+C reaches a child once enabled here: {_ctrl_c_reaches_a_child()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
