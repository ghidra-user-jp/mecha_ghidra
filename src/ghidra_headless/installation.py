"""Helpers for platform-specific Ghidra native binary resolution."""

from __future__ import annotations

import platform
from pathlib import Path

_MACHINE_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "arm64": "arm64",
    "aarch64": "arm64",
}

_DECOMPILER_PLATFORM_DIRS = {
    ("linux", "x86_64"): "linux_x86_64",
    ("linux", "arm64"): "linux_arm_64",
    ("darwin", "x86_64"): "mac_x86_64",
    ("darwin", "arm64"): "mac_arm_64",
    ("windows", "x86_64"): "win_x86_64",
}


def _normalize_system(system_name: str | None = None) -> str:
    value = system_name or platform.system()
    return value.strip().lower()


def _normalize_machine(machine_name: str | None = None) -> str:
    value = machine_name or platform.machine()
    return _MACHINE_ALIASES.get(value.strip().lower(), value.strip().lower())


def resolve_decompiler_platform_dir(system_name: str | None = None, machine_name: str | None = None) -> str | None:
    key = (_normalize_system(system_name), _normalize_machine(machine_name))
    return _DECOMPILER_PLATFORM_DIRS.get(key)


def decompiler_binary_path(
    install_dir: str | Path,
    *,
    binary_name: str = "decompile",
    system_name: str | None = None,
    machine_name: str | None = None,
) -> Path | None:
    platform_dir = resolve_decompiler_platform_dir(system_name=system_name, machine_name=machine_name)
    if platform_dir is None:
        return None
    return Path(install_dir) / "Ghidra" / "Features" / "Decompiler" / "os" / platform_dir / binary_name


def _is_executable_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if platform.system().lower() == "windows":
        return True
    return (path.stat().st_mode & 0o111) != 0


def validate_linux_arm64_decompiler_install(
    install_dir: str | Path | None,
    *,
    system_name: str | None = None,
    machine_name: str | None = None,
) -> None:
    if resolve_decompiler_platform_dir(system_name=system_name, machine_name=machine_name) != "linux_arm_64":
        return
    if install_dir is None:
        raise RuntimeError(
            "Linux ARM64 requires Ghidra native decompiler binaries under "
            "Ghidra/Features/Decompiler/os/linux_arm_64, but GHIDRA_INSTALL_DIR is not set."
        )

    install_path = Path(install_dir)
    missing: list[Path] = []
    for binary_name in ("decompile", "sleigh"):
        binary_path = decompiler_binary_path(
            install_path,
            binary_name=binary_name,
            system_name=system_name,
            machine_name=machine_name,
        )
        if binary_path is None or not _is_executable_file(binary_path):
            if binary_path is not None:
                missing.append(binary_path)

    if not missing:
        return

    missing_text = ", ".join(str(path) for path in missing)
    raise RuntimeError(
        "Linux ARM64 requires Ghidra native decompiler binaries in "
        "Ghidra/Features/Decompiler/os/linux_arm_64, but they were not found or were not executable "
        f"under '{install_path}'. Missing: {missing_text}. Install the mecha_ghidra linux_arm_64 "
        "decompiler overlay or use the patched linux_arm_64 Ghidra distribution release artifact."
    )


__all__ = [
    "decompiler_binary_path",
    "resolve_decompiler_platform_dir",
    "validate_linux_arm64_decompiler_install",
]
