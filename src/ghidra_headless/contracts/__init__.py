"""JVM-free contracts shared with the MCP schema layer.

Modules here describe *what* the headless core accepts (allowlists, request
shapes, budgets) without touching Ghidra: nothing under this package may import
``jpype``, ``pyghidra`` or ``ghidra.*``, at module level or lazily.  That is the
property that lets ``ghidra_mcp.contracts`` import them (the one exception to
"contracts import nothing from other layers" in ``tests/test_layering.py``),
so the rules a client sees in the tool schema and the rules the core enforces
are the same code.  ``tests/test_layering.py`` verifies the JVM-free property
by importing the package in a fresh interpreter.
"""
