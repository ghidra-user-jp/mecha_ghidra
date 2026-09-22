from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from cli_support import ToolHarness
from ghidra_headless.launcher import start_headless_jvm
from ghidra_mcp.application.services.bsim_service import BsimConfig
from ghidra_mcp.contracts.tool_spec import get_all_tool_specs

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()

RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_BSIM_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_BSIM_RUNTIME_VALIDATION=1",
)


def _resolve_ghidra_install_dir() -> Path:
    explicit = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [
        explicit,
        str(Path.home() / "ghidra" / "ghidra_12.1.4_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1.4_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.1.3_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1.3_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.1.2_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1.2_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.0.4_PUBLIC"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    pytest.fail("Cannot continue BSim runtime tests because GHIDRA_INSTALL_DIR was not found")


def _configure_runtime() -> None:

    install_dir = _resolve_ghidra_install_dir()
    os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
    start_headless_jvm(str(install_dir))
    username = os.environ.get("GHIDRA_SERVER_USER")
    password = os.environ.get("GHIDRA_SERVER_PASSWORD")
    if username or password:
        if not username or not password:
            pytest.fail("GHIDRA_SERVER_USER and GHIDRA_SERVER_PASSWORD must be set together")
        from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator

        ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(username, password))
    bsim_url = os.environ.get("GHIDRA_BSIM_URL")
    if not bsim_url:
        pytest.fail("GHIDRA_BSIM_URL is required for BSim runtime tests")
    cli_tools.configure(
        selected_specs=get_all_tool_specs(),
        bsim_config=BsimConfig(
            bsim_url=bsim_url,
            bsim_password=os.environ.get("GHIDRA_BSIM_PASSWORD"),
            bsim_password_env=os.environ.get("GHIDRA_BSIM_PASSWORD_ENV"),
            remote_cache_dir=os.environ.get("GHIDRA_BSIM_REMOTE_CACHE_DIR"),
        ),
    )


def test_runtime_bsim_database_status():
    _configure_runtime()

    result = cli_tools.get_bsim_database_status()

    assert result["status"] == "ok"
    assert isinstance(result["executable_count"], int)
    # postgresql://, elastic://, https:// or a file: H2 database
    assert result["bsim_url"].startswith(("postgresql://", "elastic://", "https://", "file:"))
    assert result["ghidra_install_dir"] == os.environ["GHIDRA_INSTALL_DIR"]
    assert result["ghidra_version"]
    if result.get("database_type") == "postgres":
        assert result["postgresql_version"]


def test_runtime_bsim_readonly_java_bridge():
    _configure_runtime()

    status = cli_tools.get_bsim_database_status()
    executables = cli_tools.list_bsim_executables(limit=1)

    assert isinstance(status["categories"], list)
    assert isinstance(status["function_tags"], list)
    assert executables["count"] == len(executables["items"])
    assert 0 <= executables["count"] <= 1
    assert isinstance(executables["truncated"], bool)
    for item in executables["items"]:
        assert isinstance(item["md5"], str)
        assert isinstance(item["name"], str)
        assert isinstance(item["categories"], dict)


def test_runtime_bsim_category_mutation_java_bridge():
    if os.environ.get("GHIDRA_BSIM_MUTATION_VALIDATION") != "1":
        pytest.skip("Set GHIDRA_BSIM_MUTATION_VALIDATION=1 for isolated mutation validation")
    _configure_runtime()
    category = f"CODEX_RUNTIME_{uuid.uuid4().hex[:12].upper()}"

    created = cli_tools.bsim_add_executable_category(category=category)
    repeated = cli_tools.bsim_add_executable_category(category=category)
    status = cli_tools.get_bsim_database_status()

    assert created["status"] == "created"
    assert created["category"] == category
    assert category in created["items"]
    assert repeated["status"] == "already_exists"
    assert category in status["categories"]


def test_runtime_bsim_metadata_mutation_java_bridge():
    if os.environ.get("GHIDRA_BSIM_MUTATION_VALIDATION") != "1":
        pytest.skip("Set GHIDRA_BSIM_MUTATION_VALIDATION=1 for isolated mutation validation")
    _configure_runtime()
    executables = cli_tools.list_bsim_executables(limit=1)
    if not executables["items"]:
        pytest.skip("BSim metadata mutation validation requires one executable record")

    executable = executables["items"][0]
    category = f"CODEX_RUNTIME_{uuid.uuid4().hex[:12].upper()}"
    cli_tools.bsim_add_executable_category(category=category)

    updated = cli_tools.bsim_update_executable_metadata(
        md5=executable["md5"],
        categories={category: "temporary"},
    )
    fetched = cli_tools.get_bsim_executable(md5=executable["md5"])

    assert updated["status"] == "updated"
    assert updated["updated_executables"] == 1
    assert updated["updated_functions"] == 0
    assert updated["categories"][category] == ["temporary"]
    assert fetched["categories"][category] == ["temporary"]

    cleared = cli_tools.bsim_update_executable_metadata(
        md5=executable["md5"],
        categories={category: None},
    )
    fetched_after_clear = cli_tools.get_bsim_executable(md5=executable["md5"])

    assert cleared["status"] == "updated"
    assert cleared["updated_executables"] == 1
    assert cleared["updated_functions"] == 0
    assert category not in cleared["categories"]
    assert category not in fetched_after_clear["categories"]


def test_runtime_bsim_query_function_and_decompile_match():
    required = {
        "GHIDRA_BSIM_PROJECT_LOCATION": os.environ.get("GHIDRA_BSIM_PROJECT_LOCATION"),
        "GHIDRA_BSIM_PROJECT_NAME": os.environ.get("GHIDRA_BSIM_PROJECT_NAME"),
        "GHIDRA_BSIM_QUERY_DOMAIN_PATH": os.environ.get("GHIDRA_BSIM_QUERY_DOMAIN_PATH"),
        "GHIDRA_BSIM_QUERY_FUNCTION": os.environ.get("GHIDRA_BSIM_QUERY_FUNCTION"),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        pytest.skip(f"Set {', '.join(missing)} to run BSim query/decompile runtime validation")

    _configure_runtime()
    target = f"bsim_runtime_{uuid.uuid4().hex[:8]}"
    match_target = f"{target}_match"
    opened_targets = []
    try:
        cli_tools.register_target(
            target=target,
            project_location=required["GHIDRA_BSIM_PROJECT_LOCATION"],
            project_name=required["GHIDRA_BSIM_PROJECT_NAME"],
        )
        opened_targets.append(target)
        cli_tools.load_project_program(target=target, domain_path=required["GHIDRA_BSIM_QUERY_DOMAIN_PATH"])

        result = cli_tools.bsim_query(
            target=target,
            similarity_threshold=float(os.environ.get("GHIDRA_BSIM_SIMILARITY_THRESHOLD", "0.5")),
            significance_threshold=float(os.environ.get("GHIDRA_BSIM_SIGNIFICANCE_THRESHOLD", "0.0")),
            matches_per_function=10,
            max_results=10,
            scope="functions",
            function_names=[required["GHIDRA_BSIM_QUERY_FUNCTION"]],
        )

        assert result["count"] > 0
        best = result["matches"][0]
        assert best["similarity"] >= float(os.environ.get("GHIDRA_BSIM_SIMILARITY_THRESHOLD", "0.5"))

        loaded = cli_tools.bsim_load_matched_executable(matched_ref=best["matched_ref"], target=match_target)
        opened_targets.append(loaded["target"])
        query_decompile = cli_tools.decompile_function(name=required["GHIDRA_BSIM_QUERY_FUNCTION"], target=target)
        match_decompile = cli_tools.decompile_function(name=best["matched_ref"]["name"], target=loaded["target"])

        assert required["GHIDRA_BSIM_QUERY_FUNCTION"] in str(query_decompile)
        assert best["matched_ref"]["name"] in str(match_decompile)
    finally:
        for opened_target in reversed(opened_targets):
            cli_tools.close_session(opened_target)
