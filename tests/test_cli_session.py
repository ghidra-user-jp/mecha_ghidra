import threading
import types
from pathlib import Path

import pytest

from ghidra_mcp import cli
from ghidra_headless import session


def dummy_core(monkeypatch):
    calls = {
        "initialize": [],
        "remove": [],
        "clear": 0,
    }

    def init(program, key="default"):
        calls["initialize"].append((program, key))

    def remove(key):
        calls["remove"].append(key)

    def clear():
        calls["clear"] += 1

    core_obj = types.SimpleNamespace(
        initialize=init,
        remove_context=remove,
        clear_contexts=clear,
    )
    monkeypatch.setattr(cli, "_core", lambda: core_obj)
    return calls


class DummySession:
    def __init__(self, *, binary_path=None, project_handle=None, domain_path=None):
        self.args = {
            "binary_path": binary_path,
        }
        self.program = object()
        self.closed = False
        self.project_handle = project_handle
        self.domain_path = domain_path or ("/" + Path(binary_path).name if binary_path else None)

    def get_program(self):
        return self.program

    def get_project_handle(self):
        return self.project_handle

    def close(self):
        self.closed = True

    def is_project_session(self):
        return self.project_handle is not None

    def to_dict(self):
        project_name = self.project_handle.get_project_name() if self.project_handle else None
        project_location = self.project_handle.get_project_location() if self.project_handle else None
        return {
            "domain_path": self.domain_path,
            "project_name": project_name,
            "project_location": project_location,
        }


class DummyHandle:
    def __init__(self, key=("/project", "Sample"), name="Sample"):
        self.key = key
        self.closed = False
        self.last_domain = None
        self.project_location = key[0]
        self.project_name = name

    def get_project_location(self):
        return self.project_location

    def get_project_name(self):
        return self.project_name

    def get_key(self):
        return self.key

    def is_closed(self):
        return self.closed

    def open_program(self, domain_path):
        self.last_domain = domain_path
        session = DummySession(binary_path=None, domain_path=domain_path)
        session.project_handle = self
        session.program = object()
        return session

    def list_programs(self):
        return ["/folder/A", "/folder/B"]

    def close(self):
        self.closed = True

    def release_program(self, program):
        pass


def test_parse_session_definition_minimal():
    cfg = cli._parse_session_definition("name=fw,binary_path=/tmp/fw.bin")
    assert cfg["name"] == "fw"
    assert cfg["binary_path"] == "/tmp/fw.bin"


@pytest.mark.parametrize(
    "text",
    ["binary_path=/tmp/fw.bin", "name=fw"],
)
def test_parse_session_definition_invalid(text):
    with pytest.raises(ValueError):
        cli._parse_session_definition(text)


def test_project_key_requires_existing_gpr(tmp_path):
    project_file = tmp_path / "sample.gpr"
    project_file.write_text("")

    assert session.ProjectHandle.make_key(str(project_file), None) == (
        str(project_file.parent),
        "sample",
    )

    with pytest.raises(ValueError):
        session.ProjectHandle.make_key(str(tmp_path / "missing.gpr"), None)


def test_project_key_requires_existing(tmp_path):
    project_file = tmp_path / "sample.gpr"
    project_file.write_text("")

    assert session.ProjectHandle.make_key(str(project_file.parent), "sample") == (
        str(project_file.parent),
        "sample",
    )

    with pytest.raises(ValueError):
        session.ProjectHandle.make_key(str(tmp_path / "missing.gpr"), None)


def test_project_key_rejects_non_gpr(tmp_path):
    non_gpr_path = tmp_path / "project_dir"
    non_gpr_path.mkdir()

    with pytest.raises(ValueError):
        session.ProjectHandle.make_key(str(non_gpr_path), None)


def test_session_registry_create_close(monkeypatch):
    calls = dummy_core(monkeypatch)
    monkeypatch.setattr(
        cli.ProgramSession,
        "from_binary",
        classmethod(lambda cls, path: DummySession(binary_path=path)),
    )

    registry = cli.SessionRegistry()
    session = registry.create_session("fw", binary_path="/tmp/fw.bin")

    assert registry.list_targets() == [
        {
            "target": "fw",
            "domain_path": "/fw.bin",
            "project_name": None,
            "project_location": None,
        }
    ]
    assert session.args["binary_path"] == "/tmp/fw.bin"
    assert calls["initialize"] == [(session.program, "fw")]

    registry.close_session("fw")
    assert registry.list_targets() == []
    assert session.closed is True
    assert calls["remove"] == ["fw"]


def test_registry_close_all(monkeypatch):
    calls = dummy_core(monkeypatch)
    monkeypatch.setattr(
        cli.ProgramSession,
        "from_binary",
        classmethod(lambda cls, path: DummySession(binary_path=path)),
    )

    registry = cli.SessionRegistry()
    registry.create_session("a", binary_path="/tmp/a.bin")
    registry.create_session("b", binary_path="/tmp/b.bin")

    registry.close_all()
    assert registry.list_targets() == []
    assert set(calls["remove"]) == {"a", "b"}
    assert calls["clear"] == 1


def test_registry_reuses_active_project_handle(monkeypatch):
    calls = dummy_core(monkeypatch)
    registry = cli.SessionRegistry()
    handle = DummyHandle()
    with registry._registry_lock:
        registry._project_handles[handle.get_key()] = handle

    session = registry.create_session("reuse", domain_path="/folder/main")

    assert session.get_project_handle() is handle
    assert handle.last_domain == "/folder/main"
    assert calls["initialize"] == [(session.program, "reuse")]


def test_program_session_to_dict_binary():
    class DummyProgram:
        def getDomainFile(self):
            class DummyDomainFile:
                def getPathname(self):
                    return "/fw.bin"
            return DummyDomainFile()

    session = cli.ProgramSession(
        flat_api=None,
        program=DummyProgram(),
        context=None,
        project_handle=None,
    )

    assert session.to_dict() == {
        "domain_path": "/fw.bin",
        "project_name": None,
        "project_location": None,
    }


def test_program_session_to_dict_project():
    class DummyProgram:
        def getDomainFile(self):
            class DummyDomainFile:
                def getPathname(self):
                    return "/main.bin"
            return DummyDomainFile()

    handle = DummyHandle(key=("/projects", "ProjectX.gpr"), name="ProjectX")
    session = cli.ProgramSession(
        flat_api=None,
        program=DummyProgram(),
        context=None,
        project_handle=handle,
    )

    assert session.to_dict() == {
        "domain_path": "/main.bin",
        "project_name": "ProjectX",
        "project_location": "/projects",
    }


def test_list_programs_without_target_returns_all_projects():
    registry = cli.SessionRegistry()
    handle_a = DummyHandle(name="A")
    handle_b = DummyHandle(key=("/project", "B"), name="B")
    session_a = DummySession(project_handle=handle_a)
    session_b = DummySession(project_handle=handle_b)
    with registry._registry_lock:
        registry._sessions["a"] = session_a
        registry._locks["a"] = threading.RLock()
        registry._sessions["b"] = session_b
        registry._locks["b"] = threading.RLock()

    result = registry.list_programs(None)

    assert result == [
        {
            "project_location": handle_a.get_project_location(),
            "project_name": handle_a.get_project_name(),
            "programs": handle_a.list_programs(),
        },
        {
            "project_location": handle_b.get_project_location(),
            "project_name": handle_b.get_project_name(),
            "programs": handle_b.list_programs(),
        },
    ]


def test_list_programs_without_target_requires_project_session():
    registry = cli.SessionRegistry()
    session = DummySession()
    with registry._registry_lock:
        registry._sessions["bin"] = session
        registry._locks["bin"] = threading.RLock()

    with pytest.raises(RuntimeError):
        registry.list_programs(None)


def test_list_programs_without_target_deduplicates_projects():
    registry = cli.SessionRegistry()
    shared_handle = DummyHandle()
    session_a = DummySession(project_handle=shared_handle)
    session_b = DummySession(project_handle=shared_handle)
    with registry._registry_lock:
        registry._sessions["a"] = session_a
        registry._locks["a"] = threading.RLock()
        registry._sessions["b"] = session_b
        registry._locks["b"] = threading.RLock()

    result = registry.list_programs(None)

    assert result == [
        {
            "project_location": shared_handle.get_project_location(),
            "project_name": shared_handle.get_project_name(),
            "programs": shared_handle.list_programs(),
        }
    ]


def test_add_bookmark_tool_invokes_core(monkeypatch):
    recorded = {}

    def fake_call(command, params, target):
        recorded["command"] = command
        recorded["params"] = params
        recorded["target"] = target
        return {"status": "ok"}

    monkeypatch.setattr(cli, "_call", fake_call)

    result = cli.add_bookmark(
        address="0x401000",
        category="Analysis",
        comment="Check this later",
        type="Info",
        target="note",
    )

    assert result == {"status": "ok"}
    assert recorded == {
        "command": "add_bookmark",
        "params": {
            "address": "0x401000",
            "category": "Analysis",
            "comment": "Check this later",
            "type": "Info",
        },
        "target": "note",
    }
