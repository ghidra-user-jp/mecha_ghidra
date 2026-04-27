from __future__ import annotations

import pytest

from ghidra_mcp.ghidra_installation import (
    decompiler_binary_path,
    resolve_decompiler_platform_dir,
    validate_linux_arm64_decompiler_install,
)


def test_resolve_decompiler_platform_dir_for_linux_arm64():
    assert resolve_decompiler_platform_dir(system_name="Linux", machine_name="aarch64") == "linux_arm_64"
    assert resolve_decompiler_platform_dir(system_name="Linux", machine_name="arm64") == "linux_arm_64"


def test_resolve_decompiler_platform_dir_for_linux_x86_64():
    assert resolve_decompiler_platform_dir(system_name="Linux", machine_name="x86_64") == "linux_x86_64"
    assert resolve_decompiler_platform_dir(system_name="Linux", machine_name="amd64") == "linux_x86_64"


def test_decompiler_binary_path_uses_expected_subdirectory(tmp_path):
    path = decompiler_binary_path(tmp_path, system_name="Linux", machine_name="aarch64")
    assert path == tmp_path / "Ghidra" / "Features" / "Decompiler" / "os" / "linux_arm_64" / "decompile"


def test_validate_linux_arm64_decompiler_install_accepts_complete_install(tmp_path):
    install_dir = tmp_path / "ghidra"
    decompiler_dir = install_dir / "Ghidra" / "Features" / "Decompiler" / "os" / "linux_arm_64"
    decompiler_dir.mkdir(parents=True)
    for binary_name in ("decompile", "sleigh"):
        binary = decompiler_dir / binary_name
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)

    validate_linux_arm64_decompiler_install(
        install_dir,
        system_name="Linux",
        machine_name="aarch64",
    )


def test_validate_linux_arm64_decompiler_install_raises_for_missing_files(tmp_path):
    install_dir = tmp_path / "ghidra"
    with pytest.raises(RuntimeError, match="linux_arm_64"):
        validate_linux_arm64_decompiler_install(
            install_dir,
            system_name="Linux",
            machine_name="aarch64",
        )


def test_validate_linux_arm64_decompiler_install_ignores_other_platforms(tmp_path):
    validate_linux_arm64_decompiler_install(
        tmp_path / "ghidra",
        system_name="Darwin",
        machine_name="arm64",
    )
