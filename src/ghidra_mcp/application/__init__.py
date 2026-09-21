"""Application layer exports (resolved lazily; see ``ghidra_mcp._lazy``)."""

from ghidra_mcp._lazy import lazy_exports

__all__ = [
    "BSIM_COMMANDS",
    "CORE_COMMANDS",
    "DATATYPE_COMMANDS",
    "FUNCTION_COMMANDS",
    "MEMORY_COMMANDS",
    "SYMBOL_COMMANDS",
]

__getattr__, __dir__ = lazy_exports(__name__, dict.fromkeys(__all__, ".commands"))
