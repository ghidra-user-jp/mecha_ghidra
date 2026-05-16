from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from ghidra_mcp import cli
from ghidra_mcp.application.services.bsim_service import BsimConfig
from ghidra_mcp.contracts.tool_spec import get_all_tool_specs


RUNTIME_VALIDATION_ENABLED = os.environ.get("GHIDRA_BSIM_RUNTIME_VALIDATION") == "1"

pytestmark = pytest.mark.skipif(
    not RUNTIME_VALIDATION_ENABLED,
    reason="Run only when GHIDRA_BSIM_RUNTIME_VALIDATION=1",
)


def _resolve_ghidra_install_dir() -> Path:
    explicit = os.environ.get("GHIDRA_INSTALL_DIR")
    candidates = [
        explicit,
        str(Path.home() / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "Library" / "ghidra" / "ghidra_12.1_PUBLIC"),
        str(Path.home() / "ghidra" / "ghidra_12.0.4_PUBLIC"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    pytest.fail("Cannot continue BSim runtime tests because GHIDRA_INSTALL_DIR was not found")


def _configure_runtime() -> None:
    import pyghidra

    install_dir = _resolve_ghidra_install_dir()
    os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
    pyghidra.start(install_dir=str(install_dir))
    bsim_url = os.environ.get("GHIDRA_BSIM_URL")
    if not bsim_url:
        pytest.fail("GHIDRA_BSIM_URL is required for BSim runtime tests")
    cli._get_registry(
        selected_specs=get_all_tool_specs(),
        bsim_config=BsimConfig(
            bsim_url=bsim_url,
            bsim_password=os.environ.get("GHIDRA_BSIM_PASSWORD"),
            bsim_password_env=os.environ.get("GHIDRA_BSIM_PASSWORD_ENV"),
        ),
    )


def test_runtime_bsim_database_status():
    _configure_runtime()

    result = cli.get_bsim_database_status()

    assert result["status"] == "ok"
    assert isinstance(result["executable_count"], int)
    assert "://" in result["bsim_url"]


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
    cli.register_target(
        target=target,
        project_location=required["GHIDRA_BSIM_PROJECT_LOCATION"],
        project_name=required["GHIDRA_BSIM_PROJECT_NAME"],
    )
    cli.load_project_program(target=target, domain_path=required["GHIDRA_BSIM_QUERY_DOMAIN_PATH"])

    result = cli.bsim_query_function(
        target=target,
        function_name=required["GHIDRA_BSIM_QUERY_FUNCTION"],
        similarity_threshold=float(os.environ.get("GHIDRA_BSIM_SIMILARITY_THRESHOLD", "0.5")),
        significance_threshold=float(os.environ.get("GHIDRA_BSIM_SIGNIFICANCE_THRESHOLD", "0.0")),
        matches_per_function=10,
        max_results=10,
    )

    assert result["count"] > 0
    best = result["matches"][0]
    assert best["similarity"] >= float(os.environ.get("GHIDRA_BSIM_SIMILARITY_THRESHOLD", "0.5"))

    loaded = cli.bsim_load_matched_executable(matched_ref=best["matched_ref"], target=match_target)
    query_decompile = cli.decompile_function(name=required["GHIDRA_BSIM_QUERY_FUNCTION"], target=target)
    match_decompile = cli.decompile_function(name=best["matched_ref"]["name"], target=loaded["target"])

    assert required["GHIDRA_BSIM_QUERY_FUNCTION"] in str(query_decompile)
    assert best["matched_ref"]["name"] in str(match_decompile)
