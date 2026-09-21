"""Real-Ghidra checks that edit outcomes agree with saving and sync status."""

import os

import pytest

from test_runtime_import_lifecycle import bundle as _bundle

bundle = _bundle
TARGET = "dirty_state"
DOMAIN = "/tiny.bin"
pytestmark = pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra")


@pytest.fixture
def loaded(bundle, tmp_path):
    api = bundle.runtime.tools
    api["create_project"](project_location=str(tmp_path), project_name="state")
    api["register_target"](target=TARGET, project_location=str(tmp_path), project_name="state")
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))
    api["import_program"](
        target=TARGET,
        binary_path=str(binary),
        import_mode="raw_binary",
        language_id="x86:LE:64:default",
        base_address="0x1000",
        entry_address="0x1000",
        analyze_imported=True,
    )
    api["load_project_program"](target=TARGET, domain_path=DOMAIN)
    api["save_project_program"](target=TARGET)
    try:
        yield bundle
    finally:
        bundle.script_service.shutdown()


def _comment_edit(text="temporary"):
    return {"kind": "set_comment", "address": "0x1000", "comment_type": "pre", "comment": text}


def _invalid_edit():
    return {"kind": "rename_function", "address": "0x9999", "new_name": "missing"}


def _add_prior_edit(api):
    api["apply_edits"](
        target=TARGET,
        edits=[{"kind": "set_comment", "address": "0x1000", "comment_type": "eol", "comment": "unsaved"}],
    )


def _prepare_scripts(bundle):
    from ghidra_mcp.presentation.cli import _prepare_script_runtime

    bundle.script_service.initialize()
    _prepare_script_runtime(bundle.script_service)


def _assert_dirty(bundle, expected, monkeypatch):
    api = bundle.runtime.tools
    store = bundle.runtime_backend._store
    session = store.sessions[TARGET]
    assert bool(session.get_program().isChanged()) is expected
    assert store.is_dirty_program(TARGET, DOMAIN) is expected
    assert api["get_program_info"](target=TARGET)["has_unsaved_changes"] is expected

    # Exercise the public sync-status overlay with a real Program. Only the
    # repository metadata is stubbed; this does not connect to a shared server.
    handle = session.get_project_handle()
    status = {
        **handle.get_sync_status(DOMAIN),
        "is_versioned": True,
        "is_checked_out": True,
        "modified_since_checkout": False,
        "can_checkin": False,
        "can_merge": False,
    }
    with monkeypatch.context() as patch:
        patch.setattr(handle, "get_sync_status", lambda _path: dict(status))
        overlaid = api["get_project_sync_status"](target=TARGET)
    assert overlaid["modified_since_checkout"] is expected
    assert overlaid["can_checkin"] is expected


@pytest.mark.parametrize("prior_changes", [False, True])
@pytest.mark.parametrize("operation", ["existing_function", "analyzed", "preview", "rollback", "read_only_script"])
def test_unchanged_operation_preserves_actual_dirty_state(loaded, monkeypatch, prior_changes, operation):
    api = loaded.runtime.tools
    if prior_changes:
        _add_prior_edit(api)
    _assert_dirty(loaded, prior_changes, monkeypatch)
    if operation == "existing_function":
        assert not api["create_function"](target=TARGET, address="0x1000")["created"]
    elif operation == "analyzed":
        assert not api["analyze_program"](target=TARGET)["analyzed"]
    elif operation == "preview":
        assert api["apply_edits"](target=TARGET, edits=[_comment_edit()], dry_run=True)["status"] == "dry_run"
    elif operation == "rollback":
        result = api["apply_edits"](target=TARGET, edits=[_comment_edit(), _invalid_edit()])
        assert result["status"] == "rolled_back"
    else:
        _prepare_scripts(loaded)
        result = api["run_script"](target=TARGET, source='print("no edits")', runtime="PyGhidra")
        assert result["transaction_outcome"] == "unchanged"
    _assert_dirty(loaded, prior_changes, monkeypatch)
    comments = api["get_comments"](target=TARGET, address="0x1000")
    assert comments["pre"] is None
    assert comments["eol"] == ("unsaved" if prior_changes else None)
    assert api["save_project_program"](target=TARGET)["saved"] is prior_changes
    _assert_dirty(loaded, False, monkeypatch)


@pytest.mark.parametrize("tool", ["undo_program_change", "redo_program_change"])
def test_empty_history_does_not_force_save(loaded, monkeypatch, tool):
    api = loaded.runtime.tools
    assert api[tool](target=TARGET)["status"] == "noop"
    _assert_dirty(loaded, False, monkeypatch)
    assert not api["save_project_program"](target=TARGET)["saved"]


def test_undo_clears_dirty_and_redo_restores_saveable_changes(loaded, monkeypatch):
    api = loaded.runtime.tools
    api["apply_edits"](target=TARGET, edits=[_comment_edit("keep")])
    _assert_dirty(loaded, True, monkeypatch)
    assert api["undo_program_change"](target=TARGET)["undone_count"] == 1
    _assert_dirty(loaded, False, monkeypatch)
    assert api["get_comments"](target=TARGET, address="0x1000")["pre"] is None
    assert api["redo_program_change"](target=TARGET)["redone_count"] == 1
    _assert_dirty(loaded, True, monkeypatch)
    assert api["save_project_program"](target=TARGET)["saved"]
    api["load_project_program"](target=TARGET, domain_path=DOMAIN)
    _assert_dirty(loaded, False, monkeypatch)
    assert api["get_comments"](target=TARGET, address="0x1000")["pre"] == "keep"


def test_non_atomic_partial_edits_remain_dirty_and_saveable(loaded, monkeypatch):
    api = loaded.runtime.tools
    result = api["apply_edits"](target=TARGET, edits=[_comment_edit("keep"), _invalid_edit()], atomic=False)
    assert result["status"] == "partial" and result["applied_count"] == 1
    _assert_dirty(loaded, True, monkeypatch)
    assert api["save_project_program"](target=TARGET)["saved"]
    api["load_project_program"](target=TARGET, domain_path=DOMAIN)
    _assert_dirty(loaded, False, monkeypatch)
    assert api["get_comments"](target=TARGET, address="0x1000")["pre"] == "keep"


@pytest.mark.parametrize("prior_changes", [False, True])
def test_failed_script_retains_prior_dirty_state(loaded, monkeypatch, prior_changes):
    api = loaded.runtime.tools
    _prepare_scripts(loaded)
    if prior_changes:
        _add_prior_edit(api)
    with pytest.raises(Exception, match="SCRIPT_FAILED"):
        api["run_script"](
            target=TARGET,
            source='setPlateComment(currentProgram.getMinAddress(), "discard")\nraise RuntimeError("expected failure")',
            runtime="PyGhidra",
        )
    _assert_dirty(loaded, prior_changes, monkeypatch)
    comments = api["get_comments"](target=TARGET, address="0x1000")
    assert comments["plate"] is None
    assert comments["eol"] == ("unsaved" if prior_changes else None)
