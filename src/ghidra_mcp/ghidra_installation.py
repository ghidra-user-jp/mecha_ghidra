"""Compatibility re-export; the implementation lives in ``ghidra_headless.installation``.

The headless (in-JVM) layer must not depend on ``ghidra_mcp``, so the platform
check moved down a layer.  Import from ``ghidra_headless.installation`` directly
in new code.
"""

from ghidra_headless.installation import (
    decompiler_binary_path,
    resolve_decompiler_platform_dir,
    validate_linux_arm64_decompiler_install,
)

__all__ = [
    "decompiler_binary_path",
    "resolve_decompiler_platform_dir",
    "validate_linux_arm64_decompiler_install",
]
