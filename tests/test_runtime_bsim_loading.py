"""Real-Ghidra regressions for BSim reference validation during session creation."""

from __future__ import annotations

import os

import pytest

from test_runtime_import_lifecycle import bundle as _bundle

bundle = _bundle

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)


@pytest.fixture
def project(bundle, tmp_path):
    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="sample")
    api["register_target"](target="source", project_location=str(tmp_path), project_name="sample")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    imported = api["import_program"](
        target="source",
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        base_address="0x1000",
        entry_address="0x1000",
        analyze_imported=True,
    )
    api["load_project_program"](target="source", domain_path=imported["program"])
    info = api["get_program_info"](target="source")
    ref = dict(
        matched_ref_version=1,
        executable_md5=info["executable_md5"],
        executable_name="tiny.bin",
        project_location=str(tmp_path),
        project_name="sample",
        domain_path=imported["program"],
        address="0x1000",
        name="entry",
    )
    return bundle, ref


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("invalid", ["md5", "address", None])
def test_bsim_new_session_validation_restores_binding_and_allows_retry(project, tmp_path, registered, invalid):
    from ghidra_headless.handlers.core_runtime import _CONTEXTS

    bundle, ref = project
    api = bundle.runtime.tools
    api["close_session"](target="source")
    if registered:
        api["create_project"](project_location=str(tmp_path), project_name="original")
        api["register_target"](target="candidate", project_location=str(tmp_path), project_name="original")
    before = api["list_targets"]()
    stale = dict(ref)
    if invalid == "md5":
        stale["executable_md5"] = "0" * 32
    elif invalid == "address":
        stale["address"] = "0x1001"
    if invalid is not None:
        with pytest.raises(Exception, match="BSIM_MATCH_STALE"):
            api["bsim_load_matched_executable"](target="candidate", matched_ref=stale)
        assert api["list_targets"]() == before
        assert "candidate" not in _CONTEXTS
        assert "candidate" not in bundle.runtime_backend._store.sessions
        assert not bundle.runtime_backend._store.project_handles
        assert not bundle.bsim_service._loaded_match_index
    loaded = api["bsim_load_matched_executable"](target="candidate", matched_ref=ref)
    assert loaded["status"] == "loaded"
    assert loaded["target"] == "candidate"
    assert "0x2a" in api["decompile_function"](target="candidate", address="0x1000")


@pytest.mark.parametrize("invalid", ["md5", "address"])
def test_bsim_validation_failure_keeps_existing_loaded_program_and_edits(project, invalid):
    bundle, ref = project
    api = bundle.runtime.tools
    api["apply_edits"](
        target="source",
        edits=[{"kind": "set_comment", "address": "0x1000", "comment_type": "plate", "comment": "keep unsaved"}],
    )
    before = api["list_targets"]()
    revision = api["get_program_info"](target="source")["revision"]
    stale = {**ref, "executable_md5": "0" * 32} if invalid == "md5" else {**ref, "address": "0x1001"}
    with pytest.raises(Exception, match="BSIM_MATCH_STALE"):
        api["bsim_load_matched_executable"](target="source", matched_ref=stale)
    assert api["list_targets"]() == before
    assert api["get_program_info"](target="source")["revision"] == revision
    assert api["get_comments"](target="source", address="0x1000")["plate"] == "keep unsaved"
    assert "0x2a" in api["decompile_function"](target="source", address="0x1000")


def test_bsim_validation_rollback_keeps_other_program_in_same_project(project, tmp_path):
    bundle, ref = project
    api = bundle.runtime.tools
    api["close_session"](target="source")
    peer_binary = tmp_path / "peer.bin"
    peer_binary.write_bytes(bytes.fromhex("b8 07 00 00 00 c3"))
    peer = api["import_program"](
        target="source",
        binary_path=str(peer_binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        base_address="0x1000",
        entry_address="0x1000",
        analyze_imported=True,
    )
    api["load_project_program"](target="source", domain_path=peer["program"])
    before = api["list_targets"]()
    with pytest.raises(Exception, match="BSIM_MATCH_STALE"):
        api["bsim_load_matched_executable"](target="candidate", matched_ref={**ref, "executable_md5": "0" * 32})
    assert api["list_targets"]() == before
    assert api["get_function"](target="source", address="0x1000")["entry"] == "00001000"
    assert "candidate" not in bundle.runtime_backend._store.sessions
    loaded = api["bsim_load_matched_executable"](target="candidate", matched_ref=ref)
    assert loaded["status"] == "loaded"
    assert "0x2a" in api["decompile_function"](target="candidate", address="0x1000")
