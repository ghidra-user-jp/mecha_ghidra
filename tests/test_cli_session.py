import types

import pytest

from ghidra_mcp import cli


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
    def __init__(self, *, binary_path=None):
        self.args = {
            "binary_path": binary_path,
        }
        self.program = object()
        self.closed = False
        self.project_handle = None

    def close(self):
        self.closed = True

    def is_project_session(self):
        return False


class DummyHandle:
    def __init__(self, key=("/project", "Sample")):
        self.key = key
        self.closed = False
        self.last_domain = None

    def is_closed(self):
        return self.closed

    def open_program(self, domain_path):
        self.last_domain = domain_path
        session = DummySession(binary_path=None)
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


def test_session_registry_create_close(monkeypatch):
    calls = dummy_core(monkeypatch)
    monkeypatch.setattr(
        cli.ProgramSession,
        "from_binary",
        classmethod(lambda cls, path: DummySession(binary_path=path)),
    )

    registry = cli.SessionRegistry()
    session = registry.create_session("fw", binary_path="/tmp/fw.bin")

    assert "fw" in registry.list_targets()
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
        registry._project_handles[handle.key] = handle

    session = registry.create_session("reuse", domain_path="/folder/main")

    assert session.project_handle is handle
    assert handle.last_domain == "/folder/main"
    assert calls["initialize"] == [(session.program, "reuse")]


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
