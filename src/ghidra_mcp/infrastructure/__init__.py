"""Infrastructure layer exports (resolved lazily; see ``ghidra_mcp._lazy``)."""

from ghidra_mcp._lazy import lazy_exports

__all__ = ["CoreGateway", "LockManager", "ProgramLease", "RuntimeBackend"]

__getattr__, __dir__ = lazy_exports(
    __name__,
    {
        # Compatibility re-export: LockManager moved to the application layer.
        "LockManager": "ghidra_mcp.application.locks",
        "CoreGateway": ".ghidra_adapter",
        "ProgramLease": ".ghidra_adapter",
        "RuntimeBackend": ".ghidra_adapter",
    },
)
