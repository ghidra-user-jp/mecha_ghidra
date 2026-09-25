from __future__ import annotations

import pytest

from ghidra_headless import launcher
from ghidra_headless.errors import HeadlessError
from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.domain.error_mapping import to_domain_error


class _FakeLauncher:
    instances: list[_FakeLauncher] = []

    def __init__(self, *, verbose=False, install_dir=None):
        self.verbose = verbose
        self.install_dir = install_dir
        self.calls: list[tuple[str, object]] = []
        _FakeLauncher.instances.append(self)

    def add_vmargs(self, *args):
        self.calls.append(("vmargs", args))

    def check_ghidra_version(self):
        self.calls.append(("version", None))

    def start(self):
        self.calls.append(("start", None))


@pytest.fixture(autouse=True)
def _fake_jvm(monkeypatch):
    _FakeLauncher.instances.clear()
    monkeypatch.setattr(launcher, "HeadlessPyGhidraLauncher", _FakeLauncher)
    state = {"started": False, "headless": True}
    monkeypatch.setattr(launcher.pyghidra, "started", lambda: state["started"])
    monkeypatch.setattr(launcher, "jvm_is_headless", lambda: state["headless"])
    return state


@pytest.mark.parametrize("install_dir", ["/tmp/ghidra", None])
def test_headless_and_signal_flags_are_added_before_start(install_dir):
    result = launcher.start_headless_jvm(install_dir)

    assert result is _FakeLauncher.instances[0]
    assert result.install_dir == install_dir
    assert result.calls == [
        ("vmargs", (launcher.HEADLESS_VM_ARG, launcher.REDUCE_SIGNAL_USAGE_VM_ARG)),
        ("version", None),
        ("start", None),
    ]


def test_prepared_launcher_is_checked_before_the_jvm_starts():
    prepared = launcher.prepare_headless_launcher("/tmp/ghidra")

    # The installation and version checks run without starting anything.
    assert prepared.calls == [
        ("vmargs", (launcher.HEADLESS_VM_ARG, launcher.REDUCE_SIGNAL_USAGE_VM_ARG)),
        ("version", None),
    ]
    assert launcher.start_headless_jvm("/tmp/ghidra", launcher=prepared) is prepared
    assert prepared.calls[-1] == ("start", None)
    assert _FakeLauncher.instances == [prepared]


def test_already_running_headless_jvm_is_reused(_fake_jvm):
    _fake_jvm["started"] = True
    assert launcher.prepare_headless_launcher("/tmp/ghidra") is None
    assert launcher.start_headless_jvm("/tmp/ghidra") is None
    assert _FakeLauncher.instances == []


def test_detach_releases_only_a_non_main_thread_that_is_attached(monkeypatch):
    import threading
    import types

    calls = []
    java_thread = types.SimpleNamespace(isAttached=lambda: True, detach=lambda: calls.append("detach"))
    monkeypatch.setattr(launcher.jpype, "isJVMStarted", lambda: True)
    monkeypatch.setattr(launcher.jpype, "java", types.SimpleNamespace(lang=types.SimpleNamespace(Thread=java_thread)))

    launcher.detach_current_thread()  # the main thread keeps its attachment
    worker = threading.Thread(target=launcher.detach_current_thread)
    worker.start()
    worker.join()
    assert calls == ["detach"]

    java_thread.isAttached = lambda: False
    worker = threading.Thread(target=launcher.detach_current_thread)
    worker.start()
    worker.join()
    assert calls == ["detach"]


def test_already_running_non_headless_jvm_is_rejected(_fake_jvm):
    _fake_jvm["started"] = True
    _fake_jvm["headless"] = False
    with pytest.raises(HeadlessError, match="JVM_NOT_HEADLESS") as exc_info:
        launcher.start_headless_jvm("/tmp/ghidra")
    assert exc_info.value.code == "JVM_NOT_HEADLESS"
    assert to_domain_error(exc_info.value, operation="startup").code is ErrorCode.JVM_NOT_HEADLESS


def test_flag_ignored_by_jvm_is_rejected(_fake_jvm):
    _fake_jvm["headless"] = False
    with pytest.raises(HeadlessError, match="ignored"):
        launcher.start_headless_jvm("/tmp/ghidra")


def test_headless_exception_from_ghidra_gets_its_own_code():
    class HeadlessException(Exception):  # mirrors java.awt.HeadlessException as seen through JPype
        pass

    mapped = to_domain_error(HeadlessException("No X11 DISPLAY variable was set"), operation="decompile_function")
    assert mapped.code is ErrorCode.HEADLESS_UNSUPPORTED
    assert mapped.retryable is False
    assert mapped.details["cause_type"].endswith("HeadlessException")
