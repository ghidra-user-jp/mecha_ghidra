"""Print what a Windows CI runner gives its steps, for the GUI acceptance job (spec §10.6, G50).

Not a check.  A detached runtime outlives its client only where the job
object around the relay lets it leave (or does not end its processes when it
closes), and the GUI needs an interactive window station; this records both
before the tests run, so a failure there reads at once.
"""

from __future__ import annotations

import ctypes
import os
import platform
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


def main() -> int:
    print(f"Windows {platform.version()} ({platform.machine()}), Python {sys.version.split()[0]}")
    print(f"Job object of this step: {_job()}")
    print(f"Window station: {_window_station()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
