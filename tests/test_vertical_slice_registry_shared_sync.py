from __future__ import annotations

import pytest
from mcp.types import CallToolResult

from cli_support import ToolHarness
from ghidra_mcp import cli

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()


@pytest.mark.parametrize(
    ("tool_name", "call", "expected_args", "expected_target"),
    [
        ("list_targets", lambda: cli_tools.list_targets(), {}, "default"),
        (
            "create_project",
            lambda: cli_tools.create_project(project_location="/tmp/sample.gpr", project_name=None, overwrite=False),
            {"project_location": "/tmp/sample.gpr", "overwrite": False},
            "default",
        ),
        ("list_project_programs", lambda: cli_tools.list_project_programs("fw"), {}, "fw"),
        (
            "register_target",
            lambda: cli_tools.register_target(target="fw", project_location="/tmp/sample.gpr", project_name=None),
            {"project_location": "/tmp/sample.gpr"},
            "fw",
        ),
        (
            "load_project_program",
            lambda: cli_tools.load_project_program(target="fw", domain_path="/folder/app"),
            {"domain_path": "/folder/app"},
            "fw",
        ),
        (
            "import_program",
            lambda: cli_tools.import_program(target="fw", binary_path="/tmp/app.bin"),
            {"binary_path": "/tmp/app.bin", "import_mode": "auto", "overlay": False},
            "fw",
        ),
        (
            "open_program",
            lambda: cli_tools.open_program(
                target="fw",
                project_location="/tmp/sample.gpr",
                domain_path="/folder/app",
                project_name=None,
            ),
            {
                "project_location": "/tmp/sample.gpr",
                "domain_path": "/folder/app",
            },
            "fw",
        ),
        ("close_session", lambda: cli_tools.close_session("fw"), {"discard_changes": False}, "fw"),
        ("close_session_and_remove_program", lambda: cli_tools.close_session_and_remove_program("fw"), {}, "fw"),
        (
            "get_project_sync_status",
            lambda: cli_tools.get_project_sync_status("fw", domain_path="/folder/app"),
            {"domain_path": "/folder/app"},
            "fw",
        ),
        (
            "checkout_project_program",
            lambda: cli_tools.checkout_project_program("fw", exclusive=True, domain_path="/folder/app"),
            {"exclusive": True, "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "add_project_program_to_version_control",
            lambda: cli_tools.add_project_program_to_version_control(
                "fw",
                comment="enable shared",
                keep_checked_out=False,
                domain_path="/folder/app",
            ),
            {"comment": "enable shared", "keep_checked_out": False, "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "commit_project_program",
            lambda: cli_tools.commit_project_program(
                "fw",
                "checkin",
                keep_checked_out=True,
                auto_checkout=False,
                domain_path="/folder/app",
            ),
            {
                "message": "checkin",
                "keep_checked_out": True,
                "auto_checkout": False,
                "on_conflict": "abort",
                "domain_path": "/folder/app",
            },
            "fw",
        ),
        (
            "pull_project_program",
            lambda: cli_tools.pull_project_program("fw", on_local_changes="discard", domain_path="/folder/app"),
            {"on_local_changes": "discard", "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "undo_checkout_project_program",
            lambda: cli_tools.undo_checkout_project_program(
                "fw", discard_local_changes=False, domain_path="/folder/app"
            ),
            {"discard_local_changes": False, "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "terminate_project_program_checkout",
            lambda: cli_tools.terminate_project_program_checkout("fw", checkout_id=7, domain_path="/folder/app"),
            {"checkout_id": 7, "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "delete_shared_project_file",
            lambda: cli_tools.delete_shared_project_file("fw", domain_path="/folder/app", confirm="/folder/app"),
            {
                "domain_path": "/folder/app",
                "confirm": "/folder/app",
                "allow_private": False,
                "allow_non_atomic_versioned_delete": False,
            },
            "fw",
        ),
        (
            "get_version_history",
            lambda: cli_tools.get_version_history("fw", limit=5, domain_path="/folder/app"),
            {"limit": 5, "domain_path": "/folder/app"},
            "fw",
        ),
        (
            "get_version_diff",
            lambda: cli_tools.get_version_diff(
                "fw", from_version=1, to_version=2, range_limit=50, domain_path="/folder/app"
            ),
            {
                "from_version": 1,
                "to_version": 2,
                "range_limit": 50,
                "include_details": False,
                "details_limit": 20,
                "domain_path": "/folder/app",
            },
            "fw",
        ),
    ],
)
def test_registry_shared_sync_slice_uses_dispatcher(monkeypatch, tool_name, call, expected_args, expected_target):
    called = {}

    def fake_dispatch(spec_name, raw_args, target, *, registry, core_executor=None):
        called["spec_name"] = spec_name
        called["raw_args"] = dict(raw_args)
        called["target"] = target
        called["registry"] = registry
        called["core_executor"] = core_executor
        return {"status": "ok"}

    monkeypatch.setattr(cli, "dispatch_tool", fake_dispatch)

    result = call()

    assert result == {"status": "ok"}
    assert called["spec_name"] == tool_name
    assert called["raw_args"] == expected_args
    assert called["target"] == expected_target
    assert called["registry"] is cli_tools.registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli_tools.list_targets(),
        lambda: cli_tools.list_project_programs("fw"),
    ],
)
def test_registry_shared_sync_slice_empty_result_keeps_compatibility(monkeypatch, call):
    class DummyRegistry:
        def list_targets(self):
            return []

        def list_programs(self, _target):
            return []

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    result = call()

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"


def test_registry_shared_sync_slice_create_session_error_message_is_unchanged(monkeypatch):
    class DummyRegistry:
        def create_session(self, target, **kwargs):  # noqa: ARG002
            raise RuntimeError("boom")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Failed to create session 'fw'"):
        cli_tools.open_program(
            target="fw",
            project_location="/tmp/sample.gpr",
            domain_path="/folder/app",
        )


def test_registry_shared_sync_slice_close_session_error_message_is_unchanged(monkeypatch):
    class DummyRegistry:
        def close_session(self, target, **kwargs):  # noqa: ARG002
            raise RuntimeError("boom")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Failed to close session 'fw'"):
        cli_tools.close_session("fw")


def test_registry_shared_sync_slice_close_remove_error_message_is_unchanged(monkeypatch):
    class DummyRegistry:
        def close_session(self, target, **kwargs):  # noqa: ARG002
            assert kwargs == {"remove_program": True}
            raise RuntimeError("boom")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Failed to close/remove session 'fw'"):
        cli_tools.close_session_and_remove_program("fw")
