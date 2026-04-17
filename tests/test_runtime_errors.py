from __future__ import annotations

from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.errors import to_domain_error


def test_to_domain_error_maps_target_already_loaded_prefix():
    err = to_domain_error(
        RuntimeError("TARGET_ALREADY_LOADED: program already loaded: /main"),
        operation="load_program",
        target="fw-shadow",
        domain_path="/main",
    )

    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "load_program",
        "target": "fw-shadow",
        "domain_path": "/main",
    }


def test_to_domain_error_maps_program_already_imported_prefix():
    err = to_domain_error(
        RuntimeError("PROGRAM_ALREADY_IMPORTED: program already exists: /sample.exe"),
        operation="import_program",
        target="fw",
    )

    assert err.code == ErrorCode.PROGRAM_ALREADY_IMPORTED
    assert err.details == {
        "operation": "import_program",
        "target": "fw",
    }
