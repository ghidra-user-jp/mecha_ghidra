from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pyghidra
import pyghidra.core as pycore
import pytest
from mcp.types import CallToolResult

from ghidra_headless.launcher import start_headless_jvm
from ghidra_mcp import cli

RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)

_GHIDRA_SERVER_AUTH_CONFIGURED = False


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
    if not pyghidra.started():
        if shutil.which("java") is None:
            pytest.fail("java command not found (required for runtime registry/shared-sync validation)")
        install_dir = _require_existing_path(_require_env("GHIDRA_INSTALL_DIR"), "GHIDRA_INSTALL_DIR")
        start_headless_jvm(str(install_dir))
    _configure_ghidra_server_auth_from_env()


def _configure_ghidra_server_auth_from_env() -> None:
    global _GHIDRA_SERVER_AUTH_CONFIGURED
    if _GHIDRA_SERVER_AUTH_CONFIGURED:
        return

    username = (
        os.environ.get("GHIDRA_RUNTIME_SHARED_SERVER_USER") or os.environ.get("GHIDRA_SERVER_USER") or ""
    ).strip()
    password = os.environ.get("GHIDRA_SERVER_PASSWORD")
    if not username and password is None:
        return
    if not username or password is None or password == "":
        pytest.fail(
            "GHIDRA_RUNTIME_SHARED_SERVER_USER/GHIDRA_SERVER_USER and "
            "GHIDRA_SERVER_PASSWORD must be set together for authenticated shared-project tests"
        )

    try:
        authenticator = pycore.JClass("ghidra.framework.client.PasswordClientAuthenticator")(
            username,
            password,
        )
        pycore.JClass("ghidra.framework.client.ClientUtil").setClientAuthenticator(authenticator)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"Failed to configure Ghidra server authentication: {exc}")
    _GHIDRA_SERVER_AUTH_CONFIGURED = True


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
    print(f"[runtime] {name}: type={type(value).__name__} count={_count_of(value)} sample={_sample_of(value)!r}")


def _copy_runtime_binary(tmp_path: Path, source_binary: Path) -> Path:
    suffix = source_binary.suffix or ".bin"
    copied = tmp_path / f"{source_binary.stem}_{uuid.uuid4().hex[:8]}{suffix}"
    # Only the bytes matter to Ghidra.  copy2() also propagates macOS file
    # flags; system binaries such as /bin/ls carry flags that an unprivileged
    # process cannot apply to a pytest temp file, causing chflags(2) to fail
    # before the shared-sync validation even starts.
    shutil.copyfile(source_binary, copied)
    return copied


def _copy_shared_project_cache(tmp_path: Path, project_location: str, project_name: str) -> str:
    source_path = Path(project_location).expanduser().resolve()
    source_dir = source_path.parent if source_path.suffix.lower() == ".gpr" else source_path
    source_name = source_path.stem if source_path.suffix.lower() == ".gpr" else project_name
    dest_dir = tmp_path / f"shared_project_{uuid.uuid4().hex[:8]}"
    dest_dir.mkdir()
    shutil.copy2(source_dir / f"{source_name}.gpr", dest_dir / f"{project_name}.gpr")
    shutil.copytree(
        source_dir / f"{source_name}.rep",
        dest_dir / f"{project_name}.rep",
        ignore=shutil.ignore_patterns("*.lock", "*.lock~"),
    )
    return str(dest_dir / f"{project_name}.gpr")


def _local_checkout_id(status: dict) -> int:
    checkout_status = status.get("checkout_status") or {}
    checkout_id = checkout_status.get("checkout_id")
    if checkout_id is None:
        pytest.fail("The test client checkout has no checkout_id")
    assert checkout_status.get("project_name")
    assert checkout_status.get("project_location")
    assert checkout_status.get("user_host_name")
    assert checkout_status.get("checkout_time_iso")
    checkout_id = int(checkout_id)
    listed_ids = {
        int(item["checkout_id"]) for item in status.get("checkouts", []) if item.get("checkout_id") is not None
    }
    if checkout_id not in listed_ids:
        pytest.fail(f"The local checkout_id {checkout_id} is absent from remote checkouts {listed_ids}")
    return checkout_id


def _close_runtime_target(target: str) -> None:
    try:
        cli.close_session(target)
    except Exception:
        pass


def _cleanup_runtime_domain_path(
    *,
    project_location: str,
    project_name: str,
    domain_path: str,
) -> None:
    """Remove only the UUID-scoped artifact created by this runtime test."""
    cleanup_target = f"runtime_cleanup_{uuid.uuid4().hex[:8]}"
    cli.register_target(
        target=cleanup_target,
        project_location=project_location,
        project_name=project_name,
    )
    try:
        try:
            status = _unwrap_runtime_result(
                cli.get_project_sync_status(
                    target=cleanup_target,
                    domain_path=domain_path,
                )
            )
        except Exception as exc:
            if "Domain file not found" in str(exc) or "PROGRAM_NOT_FOUND" in str(exc):
                return
            raise

        if status.get("is_checked_out"):
            _unwrap_runtime_result(
                cli.undo_checkout_project_program(
                    target=cleanup_target,
                    discard_local_changes=True,
                    domain_path=domain_path,
                )
            )
            status = _unwrap_runtime_result(
                cli.get_project_sync_status(
                    target=cleanup_target,
                    domain_path=domain_path,
                )
            )

        # The artifact name is unique to this test. Any remaining checkout can
        # only have been created by its secondary client, so terminate those
        # exact IDs before deletion rather than touching unrelated repository files.
        for item in list(status.get("checkouts") or []):
            checkout_id = item.get("checkout_id")
            if checkout_id is None:
                continue
            _unwrap_runtime_result(
                cli.terminate_project_program_checkout(
                    target=cleanup_target,
                    checkout_id=int(checkout_id),
                    domain_path=domain_path,
                )
            )

        status = _unwrap_runtime_result(
            cli.get_project_sync_status(
                target=cleanup_target,
                domain_path=domain_path,
            )
        )
        latest_version = status.get("latest_version")
        deleted = _unwrap_runtime_result(
            cli.delete_shared_project_file(
                target=cleanup_target,
                domain_path=domain_path,
                confirm=domain_path,
                expected_latest_version=(
                    int(latest_version) if status.get("is_versioned") and latest_version is not None else None
                ),
                allow_private=not bool(status.get("is_versioned")),
                allow_non_atomic_versioned_delete=bool(status.get("is_versioned")),
            )
        )
        assert deleted["deleted"] is True
        remaining = _unwrap_runtime_result(cli.list_project_programs(cleanup_target))
        assert domain_path not in {item.get("domain_path") for item in remaining}
    finally:
        _close_runtime_target(cleanup_target)


def test_runtime_create_project_success(tmp_path):
    _start_pyghidra()

    project_file = tmp_path / "created_by_tool.gpr"
    result = _unwrap_runtime_result(cli.create_project(project_location=str(project_file), project_name=None))

    _log_runtime_result("create_project", result)
    assert result["status"] == "ok"
    assert result["project_name"] == "created_by_tool"
    assert Path(result["project_file"]).is_file()
    assert (tmp_path / "created_by_tool.rep").is_dir()


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
    guard_target = f"{target}_guard"
    delete_target = f"{target}_delete"

    # Create the second client cache before either cache is opened. It still
    # points to the same test repository (needed for checkout interaction), but
    # is a consistent closed snapshot rather than a copy of live cache files.
    stale_project_location = _copy_shared_project_cache(
        tmp_path,
        project_location,
        project_name,
    )
    lifecycle_binary = _copy_runtime_binary(tmp_path, binary_path)
    work_binary = _copy_runtime_binary(tmp_path, binary_path)

    runtime_results = {}
    lifecycle_domain_path: str | None = None
    generated_domain_path: str | None = None
    kept_domain_path: str | None = None
    try:
        runtime_results["register_target"] = _unwrap_runtime_result(
            cli.register_target(
                target=target,
                project_location=project_location,
                project_name=project_name,
            )
        )

        runtime_results["list_targets"] = _unwrap_runtime_result(cli.list_targets())
        runtime_results["list_project_programs"] = _unwrap_runtime_result(cli.list_project_programs(target))

        # The caller-provided file is read-only test input. Never checkout,
        # commit, discard, undo, or delete it.
        runtime_results["get_project_sync_status"] = _unwrap_runtime_result(
            cli.get_project_sync_status(target=target, domain_path=shared_domain_path)
        )
        assert runtime_results["get_project_sync_status"]["is_versioned"] is True
        runtime_results["get_version_history_seed"] = _unwrap_runtime_result(
            cli.get_version_history(target=target, limit=20, domain_path=shared_domain_path)
        )
        seed_version = int(runtime_results["get_version_history_seed"]["current_version"])
        runtime_results["get_version_diff_seed"] = _unwrap_runtime_result(
            cli.get_version_diff(
                target=target,
                from_version=seed_version,
                to_version=seed_version,
                range_limit=0,
                domain_path=shared_domain_path,
            )
        )

        runtime_results["import_program"] = _unwrap_runtime_result(
            cli.import_program(target=target, binary_path=str(lifecycle_binary))
        )
        lifecycle_domain_path = runtime_results["import_program"]["program"]
        runtime_results["import_program_for_sync"] = _unwrap_runtime_result(
            cli.import_program(target=target, binary_path=str(work_binary))
        )
        generated_domain_path = runtime_results["import_program_for_sync"]["program"]

        runtime_results["create_session"] = _unwrap_runtime_result(
            cli.create_session(
                target=create_target,
                project_location=project_location,
                project_name=project_name,
                domain_path=lifecycle_domain_path,
            )
        )
        runtime_results["close_session"] = _unwrap_runtime_result(cli.close_session(create_target))

        runtime_results["create_session_for_remove"] = _unwrap_runtime_result(
            cli.create_session(
                target=remove_target,
                project_location=project_location,
                project_name=project_name,
                domain_path=lifecycle_domain_path,
            )
        )
        runtime_results["close_session_and_remove_program"] = _unwrap_runtime_result(
            cli.close_session_and_remove_program(remove_target)
        )

        runtime_results["add_project_program_to_version_control"] = _unwrap_runtime_result(
            cli.add_project_program_to_version_control(
                target=target,
                comment="runtime shared sync validation",
                keep_checked_out=False,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["add_project_program_to_version_control"]["status"] == "ok"
        initial_version = int(runtime_results["add_project_program_to_version_control"]["version"])

        runtime_results["checkout_project_program"] = _unwrap_runtime_result(
            cli.checkout_project_program(
                target=target,
                exclusive=False,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["checkout_project_program"]["checked_out"] is True
        runtime_results["load_project_program"] = _unwrap_runtime_result(
            cli.load_project_program(target=target, domain_path=generated_domain_path)
        )
        functions = _unwrap_runtime_result(cli.list_functions(offset=0, limit=1, target=target))
        assert functions, "Imported runtime binary has no function to modify"
        function_address = functions[0]["entry"]
        first_comment = f"runtime sync commit {uuid.uuid4().hex}"
        runtime_results["set_disassembly_comment_for_commit"] = _unwrap_runtime_result(
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=first_comment,
                target=target,
            )
        )
        dirty_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=target, domain_path=generated_domain_path)
        )
        assert dirty_status["modified_since_checkout"] is True

        commit_message = f"runtime shared sync check-in {uuid.uuid4().hex}"
        runtime_results["commit_project_program"] = _unwrap_runtime_result(
            cli.commit_project_program(
                target=target,
                message=commit_message,
                keep_checked_out=False,
                auto_checkout=True,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["commit_project_program"]["status"] == "ok"
        committed_version = int(runtime_results["commit_project_program"]["new_version"])
        assert committed_version > initial_version
        assert runtime_results["commit_project_program"]["checked_out"] is False

        runtime_results["get_version_history"] = _unwrap_runtime_result(
            cli.get_version_history(target=target, limit=20, domain_path=generated_domain_path)
        )
        versions = runtime_results["get_version_history"]["versions"]
        assert int(versions[0]["version"]) == committed_version
        assert versions[0]["comment"] == commit_message
        runtime_results["get_version_diff"] = _unwrap_runtime_result(
            cli.get_version_diff(
                target=target,
                from_version=initial_version,
                to_version=committed_version,
                range_limit=50,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["get_version_diff"]["total_diff_addresses"] > 0

        _unwrap_runtime_result(
            cli.checkout_project_program(
                target=target,
                exclusive=False,
                domain_path=generated_domain_path,
            )
        )
        second_comment = f"runtime sync pull discard {uuid.uuid4().hex}"
        _unwrap_runtime_result(
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=second_comment,
                target=target,
            )
        )
        with pytest.raises(RuntimeError, match="LOCAL_CHANGES_EXIST"):
            cli.pull_project_program(
                target=target,
                on_local_changes="abort",
                domain_path=generated_domain_path,
            )
        runtime_results["pull_project_program"] = _unwrap_runtime_result(
            cli.pull_project_program(
                target=target,
                on_local_changes="discard",
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["pull_project_program"]["discarded_local_changes"] is True
        assert runtime_results["pull_project_program"]["updated"] is True

        _unwrap_runtime_result(
            cli.checkout_project_program(
                target=target,
                exclusive=False,
                domain_path=generated_domain_path,
            )
        )
        _unwrap_runtime_result(
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=f"runtime sync undo {uuid.uuid4().hex}",
                target=target,
            )
        )
        runtime_results["undo_checkout_project_program"] = _unwrap_runtime_result(
            cli.undo_checkout_project_program(
                target=target,
                discard_local_changes=True,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["undo_checkout_project_program"]["checked_out"] is False

        runtime_results["reload_project_program"] = _unwrap_runtime_result(
            cli.load_project_program(target=target, domain_path=generated_domain_path)
        )
        assert runtime_results["reload_project_program"]["reloaded"] is True

        runtime_results["commit_project_program_clean"] = _unwrap_runtime_result(
            cli.commit_project_program(
                target=target,
                message=f"runtime clean no-op {uuid.uuid4().hex}",
                keep_checked_out=False,
                auto_checkout=True,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["commit_project_program_clean"]["status"] == "noop"
        assert runtime_results["commit_project_program_clean"]["reason"] == "not_modified"
        assert runtime_results["commit_project_program_clean"]["checked_out"] is False
        clean_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=target, domain_path=generated_domain_path)
        )
        assert clean_status["is_checked_out"] is False

        runtime_results["checkout_project_program_exclusive"] = _unwrap_runtime_result(
            cli.checkout_project_program(
                target=target,
                exclusive=True,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["checkout_project_program_exclusive"]["checked_out"] is True
        assert runtime_results["checkout_project_program_exclusive"]["exclusive"] is True
        exclusive_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=target, domain_path=generated_domain_path)
        )
        assert exclusive_status["is_checked_out_exclusive"] is True

        kept_comment = f"runtime sync undo keep {uuid.uuid4().hex}"
        _unwrap_runtime_result(
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=kept_comment,
                target=target,
            )
        )
        runtime_results["undo_checkout_project_program_keep"] = _unwrap_runtime_result(
            cli.undo_checkout_project_program(
                target=target,
                discard_local_changes=False,
                domain_path=generated_domain_path,
            )
        )
        kept_domain_path = runtime_results["undo_checkout_project_program_keep"].get("kept_program")
        assert kept_domain_path
        assert kept_domain_path != generated_domain_path
        kept_disassembly = _unwrap_runtime_result(cli.disassemble_function(address=function_address, target=target))
        kept_instruction = next(item for item in kept_disassembly if item["address"] == function_address)
        assert kept_instruction["comment"] == kept_comment

        _unwrap_runtime_result(cli.close_session(target))
        _cleanup_runtime_domain_path(
            project_location=project_location,
            project_name=project_name,
            domain_path=kept_domain_path,
        )
        kept_domain_path = None
        _unwrap_runtime_result(
            cli.register_target(
                target=target,
                project_location=project_location,
                project_name=project_name,
            )
        )
        _unwrap_runtime_result(cli.load_project_program(target=target, domain_path=generated_domain_path))
        original_disassembly = _unwrap_runtime_result(cli.disassemble_function(address=function_address, target=target))
        original_instruction = next(item for item in original_disassembly if item["address"] == function_address)
        assert original_instruction["comment"] != kept_comment

        _unwrap_runtime_result(
            cli.register_target(
                target=stale_target,
                project_location=stale_project_location,
                project_name=project_name,
            )
        )
        _unwrap_runtime_result(cli.load_project_program(target=stale_target, domain_path=generated_domain_path))
        _unwrap_runtime_result(
            cli.checkout_project_program(
                target=stale_target,
                exclusive=False,
                domain_path=generated_domain_path,
            )
        )
        remote_comment = f"runtime remote advance {uuid.uuid4().hex}"
        _unwrap_runtime_result(
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=remote_comment,
                target=stale_target,
            )
        )
        remote_commit = _unwrap_runtime_result(
            cli.commit_project_program(
                target=stale_target,
                message=f"runtime remote advance commit {uuid.uuid4().hex}",
                keep_checked_out=False,
                auto_checkout=False,
                domain_path=generated_domain_path,
            )
        )
        remote_version = int(remote_commit["new_version"])
        assert remote_version > committed_version

        runtime_results["pull_project_program_remote_advance"] = _unwrap_runtime_result(
            cli.pull_project_program(
                target=target,
                on_local_changes="abort",
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["pull_project_program_remote_advance"]["updated"] is True
        assert runtime_results["pull_project_program_remote_advance"]["followed_latest"] is True
        assert runtime_results["pull_project_program_remote_advance"]["reloaded"] is True
        assert int(runtime_results["pull_project_program_remote_advance"]["version"]) == remote_version
        primary_disassembly = _unwrap_runtime_result(cli.disassemble_function(address=function_address, target=target))
        primary_instruction = next(item for item in primary_disassembly if item["address"] == function_address)
        assert primary_instruction["comment"] == remote_comment

        _unwrap_runtime_result(cli.close_session(target))
        _unwrap_runtime_result(
            cli.register_target(
                target=guard_target,
                project_location=project_location,
                project_name=project_name,
            )
        )
        with pytest.raises(RuntimeError, match="TARGET_ALREADY_LOADED"):
            cli.delete_shared_project_file(
                target=guard_target,
                domain_path=generated_domain_path,
                confirm=generated_domain_path,
            )

        _unwrap_runtime_result(
            cli.checkout_project_program(
                target=stale_target,
                exclusive=False,
                domain_path=generated_domain_path,
            )
        )
        stale_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=stale_target, domain_path=generated_domain_path)
        )
        stale_checkout_id = _local_checkout_id(stale_status)
        with pytest.raises(RuntimeError, match="UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
            cli.terminate_project_program_checkout(
                target=guard_target,
                checkout_id=stale_checkout_id,
                domain_path=generated_domain_path,
            )
        _unwrap_runtime_result(cli.close_session(stale_target))

        runtime_results["terminate_project_program_checkout"] = _unwrap_runtime_result(
            cli.terminate_project_program_checkout(
                target=guard_target,
                checkout_id=stale_checkout_id,
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["terminate_project_program_checkout"]["checkout_id"] == stale_checkout_id
        assert runtime_results["terminate_project_program_checkout"]["active_checkouts"] == []

        _unwrap_runtime_result(
            cli.register_target(
                target=stale_target,
                project_location=stale_project_location,
                project_name=project_name,
            )
        )
        hijacked_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=stale_target, domain_path=generated_domain_path)
        )
        assert hijacked_status["is_versioned"] is False
        assert hijacked_status["is_hijacked"] is True
        _unwrap_runtime_result(cli.load_project_program(target=stale_target, domain_path=generated_domain_path))
        with pytest.raises(RuntimeError, match="HIJACKED_PROGRAM"):
            cli.set_comment(
                kind="eol",
                address=function_address,
                comment=f"must be rejected {uuid.uuid4().hex}",
                target=stale_target,
            )
        runtime_results["pull_project_program_hijack_recovery"] = _unwrap_runtime_result(
            cli.pull_project_program(
                target=stale_target,
                on_local_changes="discard",
                domain_path=generated_domain_path,
            )
        )
        assert runtime_results["pull_project_program_hijack_recovery"]["discarded_hijacked_file"] is True
        recovered_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=stale_target, domain_path=generated_domain_path)
        )
        assert recovered_status["is_hijacked"] is False
        assert recovered_status["is_versioned"] is True
        assert int(recovered_status["version"]) == remote_version
        recovered_disassembly = _unwrap_runtime_result(
            cli.disassemble_function(address=function_address, target=stale_target)
        )
        recovered_instruction = next(item for item in recovered_disassembly if item["address"] == function_address)
        assert recovered_instruction["comment"] == remote_comment
        _unwrap_runtime_result(cli.close_session(stale_target))

        _unwrap_runtime_result(
            cli.register_target(
                target=delete_target,
                project_location=project_location,
                project_name=project_name,
            )
        )
        delete_status = _unwrap_runtime_result(
            cli.get_project_sync_status(target=delete_target, domain_path=generated_domain_path)
        )
        runtime_results["delete_shared_project_file"] = _unwrap_runtime_result(
            cli.delete_shared_project_file(
                target=delete_target,
                domain_path=generated_domain_path,
                confirm=generated_domain_path,
                expected_latest_version=int(delete_status["latest_version"]),
                allow_non_atomic_versioned_delete=True,
            )
        )
        assert runtime_results["delete_shared_project_file"]["deleted"] is True
        generated_domain_path = None

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
            "delete_shared_project_file",
            "reload_project_program",
        ]:
            assert isinstance(runtime_results[command_name], dict), (
                f"{command_name} returned non-dict value: {type(runtime_results[command_name])}"
            )
    finally:
        for cleanup_target in [
            stale_target,
            guard_target,
            remove_target,
            create_target,
            delete_target,
            target,
        ]:
            _close_runtime_target(cleanup_target)
        for cleanup_domain_path in [
            kept_domain_path,
            lifecycle_domain_path,
            generated_domain_path,
        ]:
            if cleanup_domain_path is None:
                continue
            _cleanup_runtime_domain_path(
                project_location=project_location,
                project_name=project_name,
                domain_path=cleanup_domain_path,
            )
