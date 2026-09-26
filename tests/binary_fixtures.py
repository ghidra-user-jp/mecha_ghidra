"""Ghidra's benign exercise binary, bundled so runtime tests work in fresh checkouts."""

from pathlib import Path

GHIDRA_EXERCISE_PE = Path(__file__).resolve().parent / "fixtures" / "ghidra" / "WinHelloCPP.exe"
