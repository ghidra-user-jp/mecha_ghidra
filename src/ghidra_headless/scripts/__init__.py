"""Ghidra script execution inside the headless JVM.

Modules here are JVM-bound (they import Ghidra classes through PyGhidra) and
are only imported after the JVM has started.  The pure-Python catalog lives
in the application layer (``ghidra_mcp.application.services.script_catalog``).
"""
