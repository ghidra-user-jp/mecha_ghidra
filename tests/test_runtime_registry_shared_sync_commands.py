from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pyghidra
import pytest
from mcp.types import CallToolResult

from ghidra_mcp import cli


RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


def _require_env(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        pytest.fail(f"{name} is not set (required for runtime registry/shared-sync validation)")
    return value


def _require_existing_path(value: str, env_name: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists():
        pytest.fail(f"{env_name} does not exist: {path}")
    return path


def _start_pyghidra() -> None:
    if pyghidra.started():
        return
    if shutil.which("java") is None:
        pytest.fail("java command not found (required for runtime registry/shared-sync validation)")
    install_dir = _require_existing_path(_require_env("GHIDRA_INSTALL_DIR"), "GHIDRA_INSTALL_DIR")
    pyghidra.start(install_dir=str(install_dir))


def _unwrap_runtime_result(result):
    if isinstance(result, CallToolResult):
        assert len(result.content) == 1
        assert result.content[0].text == "[]"
        return []
    return result


def _sample_of(value):
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return value.splitlines()[0] if value else ""
    return value


def _count_of(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, str):
        return len(value.splitlines())
    return None


def _log_runtime_result(name: str, value) -> None:
    print(
        f"[runtime] {name}: type={type(value).__name__} "
        f"count={_count_of(value)} sample={_sample_of(value)!r}"
    )


def _copy_runtime_binary(tmp_path: Path, source_binary: Path) -> Path:
    suffix = source_binary.suffix or ".bin"
    copied = tmp_path / f"{source_binary.stem}_{uuid.uuid4().hex[:8]}{suffix}"
    shutil.copy2(source_binary, copied)
    return copied


def test_runtime_registry_and_shared_sync_commands_all_success(tmp_path):
    _start_pyghidra()

    project_location = _require_env("GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION")
    project_name = _require_env("GHIDRA_RUNTIME_SHARED_PROJECT_NAME")
    shared_domain_path = _require_env("GHIDRA_RUNTIME_SHARED_DOMAIN_PATH")
    binary_path = _require_existing_path(_require_env("GHIDRA_RUNTIME_BINARY_PATH"), "GHIDRA_RUNTIME_BINARY_PATH")

    target = f"runtime_regsync_{uuid.uuid4().hex[:8]}"
    create_target = f"{target}_create"
    remove_target = f"{target}_remove"
    stale_target = f"{target}_stale"

    copied_binary = _copy_runtime_binary(tmp_path, binary_path)

    runtime_results = {}
    cleanup_targets: list[str] = []
    try:
        runtime_results["register_target"] = _unwrap_runtime_result(
            cli.register_target(
                target=target,
                project_location=project_location,
                project_name=project_name,
            )
        )
        cleanup_targets.append(target)

        runtime_results["list_targets"] = _unwrap_runtime_result(cli.list_targets())
        runtime_results["list_project_programs"] = _unwrap_runtime_result(cli.list_project_programs(target))

        runtime_results["import_program"] = _unwrap_runtime_result(
            cli.import_program(target=target, binary_path=str(copied_binary))
        )
        imported_domain_path = runtime_results["import_program"]["program"]
        copied_binary_for_terminate = _copy_runtime_binary(tmp_path, binary_path)
        runtime_results["import_program_for_terminate"] = _unwrap_runtime_result(
            cli.import_program(target=target, binary_path=str(copied_binary_for_terminate))
        )
        terminate_domain_path = runtime_results["import_program_for_terminate"]["program"]

        runtime_results["create_session"] = _unwrap_runtime_result(
            cli.create_session(
                target=create_target,
                project_location=project_location,
                project_name=project_name,
                domain_path=imported_domain_path,
            )
        )
        cleanup_targets.append(create_target)
        runtime_results["close_session"] = _unwrap_runtime_result(cli.close_session(create_target))

        runtime_results["create_session_for_remove"] = _unwrap_runtime_result(
            cli.create_session(
                target=remove_target,
                project_location=project_location,
                project_name=project_name,
                domain_path=imported_domain_path,
            )
        )
        cleanup_targets.append(remove_target)
        runtime_results["close_session_and_remove_program"] = _unwrap_runtime_result(
            cli.close_session_and_remove_program(remove_target)
        )

        _unwrap_runtime_result(
            cli.register_target(
                target=stale_target,
                project_location=project_location,
                project_name=project_name,
            )
        )
        cleanup_targets.append(stale_target)
        _unwrap_runtime_result(
            cli.load_project_program(target=stale_target, domain_path=terminate_domain_path)
        )
        stale_status_before_checkout = _unwrap_runtime_result(
            cli.get_project_sync_status(target=stale_target, domain_path=terminate_domain_path)
        )
        if not bool(stale_status_before_checkout.get("is_versioned")):
            _unwrap_runtime_result(
                cli.add_project_program_to_version_control(
                    target=stale_target,
                    comment="runtime stale checkout preparation",
                    keep_checked_out=False,
                    domain_path=terminate_domain_path,
                )
            )
        _unwrap_runtime_result(
            cli.checkout_project_program(
                target=stale_target,
                exclusive=False,
                domain_path=terminate_domain_path,
            )
        )
        stale_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=stale_target, domain_path=terminate_domain_path)
        )
        stale_checkout_id = None
        for item in stale_status.get("checkouts", []):
            maybe_id = item.get("checkout_id")
            if maybe_id is not None:
                stale_checkout_id = int(maybe_id)
                break
        if stale_checkout_id is None:
            maybe_checkout_status = stale_status.get("checkout_status") or {}
            maybe_id = maybe_checkout_status.get("checkout_id")
            if maybe_id is not None:
                stale_checkout_id = int(maybe_id)
        if stale_checkout_id is None:
            pytest.fail("Failed to obtain stale checkout_id for terminate_project_program_checkout")
        _unwrap_runtime_result(cli.close_session(stale_target))

        runtime_results["load_project_program"] = _unwrap_runtime_result(
            cli.load_project_program(target=target, domain_path=shared_domain_path)
        )

        runtime_results["get_project_sync_status"] = _unwrap_runtime_result(
            cli.get_project_sync_status(target=target, domain_path=shared_domain_path)
        )
        runtime_results["add_project_program_to_version_control"] = _unwrap_runtime_result(
            cli.add_project_program_to_version_control(
                target=target,
                comment="runtime shared sync validation",
                keep_checked_out=False,
                domain_path=shared_domain_path,
            )
        )
        runtime_results["checkout_project_program"] = _unwrap_runtime_result(
            cli.checkout_project_program(
                target=target,
                exclusive=False,
                domain_path=shared_domain_path,
            )
        )
        runtime_results["commit_project_program"] = _unwrap_runtime_result(
            cli.commit_project_program(
                target=target,
                message="runtime shared sync check-in",
                keep_checked_out=True,
                auto_checkout=True,
                domain_path=shared_domain_path,
            )
        )
        runtime_results["get_version_history"] = _unwrap_runtime_result(
            cli.get_version_history(target=target, limit=20, domain_path=shared_domain_path)
        )
        versions = runtime_results["get_version_history"].get("versions", [])
        if versions:
            from_version = int(versions[-1]["version"])
            to_version = int(versions[0]["version"])
        else:
            current = int(runtime_results["get_version_history"]["current_version"])
            from_version = current
            to_version = current
        runtime_results["get_version_diff"] = _unwrap_runtime_result(
            cli.get_version_diff(
                target=target,
                from_version=from_version,
                to_version=to_version,
                range_limit=50,
                domain_path=shared_domain_path,
            )
        )
        runtime_results["pull_project_program"] = _unwrap_runtime_result(
            cli.pull_project_program(
                target=target,
                on_local_changes="discard",
                domain_path=shared_domain_path,
            )
        )
        runtime_results["reload_project_program"] = _unwrap_runtime_result(
            cli.reload_project_program(target=target, domain_path=shared_domain_path)
        )
        runtime_results["undo_checkout_project_program"] = _unwrap_runtime_result(
            cli.undo_checkout_project_program(
                target=target,
                discard_local_changes=True,
                domain_path=shared_domain_path,
            )
        )
        runtime_results["terminate_project_program_checkout"] = _unwrap_runtime_result(
            cli.terminate_project_program_checkout(
                target=target,
                checkout_id=stale_checkout_id,
                domain_path=terminate_domain_path,
            )
        )

        for command_name, value in runtime_results.items():
            _log_runtime_result(command_name, value)

        assert isinstance(runtime_results["list_targets"], list)
        assert isinstance(runtime_results["list_project_programs"], list)
        for command_name in [
            "register_target",
            "load_project_program",
            "import_program",
            "create_session",
            "close_session",
            "create_session_for_remove",
            "close_session_and_remove_program",
            "get_project_sync_status",
            "add_project_program_to_version_control",
            "checkout_project_program",
            "commit_project_program",
            "get_version_history",
            "get_version_diff",
            "pull_project_program",
            "undo_checkout_project_program",
            "terminate_project_program_checkout",
            "reload_project_program",
        ]:
            assert isinstance(runtime_results[command_name], dict), (
                f"{command_name} returned non-dict value: {type(runtime_results[command_name])}"
            )
    finally:
        for cleanup_target in [stale_target, remove_target, create_target, target]:
            try:
                cli.close_session(cleanup_target)
            except Exception:
                pass
