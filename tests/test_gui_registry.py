"""The GUI runtime registry: its place, the project key, the locks and the record (spec §10.1)."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ghidra_mcp.presentation import gui_registry
from ghidra_mcp.presentation.gui_registry import FileLock, ProjectRegistry, RuntimeRecord, project_key

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX locks and permissions")


def record(**overrides) -> RuntimeRecord:
    values = {
        "runtime_id": "r1",
        "pid": 123,
        "endpoint": "http://127.0.0.1:1234/mcp",
        "token": "secret",
        "public": False,
        "project_file": "/p/GUI.gpr",
        "ghidra_install_dir": "/g",
        "mecha_version": "1.1.0",
        "fingerprint": {"tools": ["a"]},
    }
    values.update(overrides)
    return RuntimeRecord(**values)


class TestPlace:
    def test_macos_uses_application_support(self, monkeypatch, tmp_path):
        monkeypatch.setattr(gui_registry.sys, "platform", "darwin")
        monkeypatch.setenv("HOME", str(tmp_path))
        assert gui_registry.registry_dir() == tmp_path / "Library/Application Support/mecha_ghidra/gui-runtimes"

    def test_linux_follows_xdg_state_home(self, monkeypatch, tmp_path):
        monkeypatch.setattr(gui_registry.sys, "platform", "linux")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        assert gui_registry.registry_dir() == tmp_path / ".local/state/mecha_ghidra/gui-runtimes"
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
        assert gui_registry.registry_dir() == tmp_path / "state/mecha_ghidra/gui-runtimes"

    def test_the_directory_is_for_its_owner_only(self, tmp_path):
        directory = tmp_path / "reg"
        directory.mkdir(mode=0o755)
        gui_registry.ensure_registry_dir(directory)
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


class TestProjectKey:
    def test_every_name_of_the_file_is_one_project(self, tmp_path):
        project = tmp_path / "Proj"
        project.mkdir()
        gpr = project / "GUI.gpr"
        gpr.write_text("")
        (tmp_path / "link").symlink_to(project)
        os.link(gpr, project / "Hard.gpr")
        key = project_key(gpr)
        assert key == project_key(tmp_path / "link" / "GUI.gpr")
        assert key == project_key(project / "Hard.gpr")
        assert key == project_key(project / ".." / "Proj" / "GUI.gpr")

    def test_another_file_is_another_project(self, tmp_path):
        (tmp_path / "a.gpr").write_text("")
        (tmp_path / "b.gpr").write_text("")
        assert project_key(tmp_path / "a.gpr") != project_key(tmp_path / "b.gpr")


class TestLocks:
    def test_one_holder_at_a_time(self, tmp_path):
        first, second = FileLock(tmp_path / "k.lock"), FileLock(tmp_path / "k.lock")
        assert first.try_acquire()
        assert not second.try_acquire()
        first.release()
        assert second.try_acquire()
        second.release()

    def test_the_lock_ends_with_its_process_and_no_child_keeps_it(self, tmp_path):
        """A holder killed with SIGKILL frees the lock, although a child it started still runs."""
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import subprocess, sys, time
                    sys.path.insert(0, {str(Path(gui_registry.__file__).parents[2])!r})
                    from ghidra_mcp.presentation.gui_registry import FileLock
                    assert FileLock(__import__("pathlib").Path({str(tmp_path / "k.lock")!r})).try_acquire()
                    subprocess.Popen(["sleep", "30"])
                    print("held", flush=True)
                    time.sleep(60)
                    """
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            assert holder.stdout.readline().strip() == "held"
            registry_lock = FileLock(tmp_path / "k.lock")
            assert not registry_lock.try_acquire()
            os.kill(holder.pid, signal.SIGKILL)
            holder.wait(10)
            assert registry_lock.acquire(2)
            registry_lock.release()
        finally:
            os.killpg(holder.pid, signal.SIGKILL)


class TestRecord:
    @pytest.fixture
    def registry(self, tmp_path):
        (tmp_path / "GUI.gpr").write_text("")
        return ProjectRegistry(tmp_path / "GUI.gpr", directory=tmp_path / "reg")

    def test_a_written_record_reads_back_for_the_owner_only(self, registry):
        registry.write(record(state="ready"))
        assert registry.read() == record(state="ready", started_at=registry.read().started_at)
        assert stat.S_IMODE(registry.record_path.stat().st_mode) == 0o600
        assert [path.name for path in registry.directory.iterdir()] == [registry.record_path.name]

    def test_a_missing_or_foreign_record_is_none(self, registry):
        assert registry.read() is None
        registry.record_path.write_text('{"format": 99}')
        assert registry.read() is None
        registry.record_path.write_text("not json")
        assert registry.read() is None
        registry.remove()
        registry.remove()
        assert registry.read() is None

    def test_a_runtime_is_alive_while_it_holds_the_lock(self, registry):
        assert not registry.runtime_alive()
        lock = registry.runtime_lock()
        assert lock.try_acquire()
        assert registry.runtime_alive()
        lock.release()
        assert not registry.runtime_alive()
