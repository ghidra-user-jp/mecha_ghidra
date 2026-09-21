"""Exception-propagation verification must gate every script language."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.scripts import execution, providers, runtime_check
from ghidra_mcp.presentation import cli


@pytest.fixture
def native_probe(monkeypatch):
    state = {"probe_ok": None, "probe_error": "not checked", "pyghidra_version": None}
    monkeypatch.setattr(runtime_check, "_state", state)
    monkeypatch.setattr(runtime_check, "version", lambda _name: "3.2.0")
    events = []
    monkeypatch.setattr(providers, "ensure_bundle_host", lambda: events.append("bundle"))

    class Capture:
        def __init__(self, _limit):
            self.writer = SimpleNamespace(close=lambda: events.append("closed"))

    monkeypatch.setattr(runtime_check, "BoundedCapture", Capture)
    classes = {
        "generic.jar.ResourceFile": Path,
        "ghidra.app.script.GhidraState": lambda *args: object(),
        "ghidra.app.script.ScriptControls": lambda *args: object(),
        "ghidra.util.task.TaskMonitor": SimpleNamespace(DUMMY=object()),
    }
    monkeypatch.setattr(runtime_check.jpype, "JClass", classes.__getitem__)
    return events


@pytest.mark.parametrize("result", ["propagated", "swallowed", "unexpected", "load_failed"])
def test_probe_requires_actual_exception_and_cleans_resources(monkeypatch, tmp_path, native_probe, result):
    def get_instance(source, _writer):
        if result == "load_failed":
            raise RuntimeError("provider failed")

        def execute(*_args):
            native_probe.append("execute")
            if result == "propagated":
                # The generated script itself supplies the unique expected exception.
                exec(source.read_text(), {})
            elif result == "unexpected":
                raise RuntimeError("unrelated failure")

        return SimpleNamespace(execute=execute)

    def provider_for(_runtime):
        assert native_probe[0] == "bundle"
        return SimpleNamespace(getScriptInstance=get_instance)

    monkeypatch.setattr(providers, "provider_for", provider_for)
    assert runtime_check.probe_exception_propagation(tmp_path) is (result == "propagated")
    assert list(tmp_path.iterdir()) == []
    assert native_probe.count("closed") == 2
    calls = native_probe.count("execute")
    assert runtime_check.probe_exception_propagation(tmp_path) is (result == "propagated")
    assert native_probe.count("execute") == calls
    if result == "propagated":
        runtime_check.require_script_runtime_ready()
    else:
        with pytest.raises(HeadlessError, match="SCRIPT_RUNTIME_UNAVAILABLE"):
            runtime_check.require_script_runtime_ready()


def test_bundle_initialization_failure_revokes_readiness(monkeypatch, tmp_path, native_probe):
    runtime_check._state.update(probe_ok=True, probe_error=None)

    def fail():
        raise RuntimeError("bundle failed")

    monkeypatch.setattr(providers, "ensure_bundle_host", fail)
    assert runtime_check.probe_exception_propagation(tmp_path) is False
    assert runtime_check.runtime_check_state()["probe_error"] == "bundle failed"


@pytest.mark.parametrize("runtime", providers.SUPPORTED_RUNTIMES)
@pytest.mark.parametrize("checked", [None, False])
def test_unverified_runtime_rejects_every_execution_entry(monkeypatch, runtime, checked):
    monkeypatch.setattr(runtime_check, "_state", {"probe_ok": checked, "probe_error": "failed"})
    # Plain objects deliberately cannot start transactions or access a JVM.
    with pytest.raises(HeadlessError, match="SCRIPT_RUNTIME_UNAVAILABLE"):
        execution.run_script_with_transaction(
            program=object(), project=object(), description="blocked", request={"runtime": runtime}
        )
    with pytest.raises(HeadlessError, match="SCRIPT_RUNTIME_UNAVAILABLE"):
        execution.execute_script(program=object(), project=object(), script_path="unused", runtime=runtime)


def test_cli_marks_all_languages_unavailable_when_probe_fails(monkeypatch, tmp_path):
    unavailable = {}
    service = SimpleNamespace(
        initialized=True, snapshot_base=tmp_path, mark_runtime_unavailable=unavailable.__setitem__
    )
    monkeypatch.setattr(runtime_check, "probe_exception_propagation", lambda _path: False)
    monkeypatch.setattr(runtime_check, "_state", {"probe_ok": False, "probe_error": "swallowed"})
    cli._prepare_script_runtime(service)
    assert set(unavailable) == set(providers.SUPPORTED_RUNTIMES)
    assert all("swallowed" in reason for reason in unavailable.values())
