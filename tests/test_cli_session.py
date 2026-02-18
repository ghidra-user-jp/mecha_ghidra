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
    def __init__(self, *, project_handle=None, domain_path=None):
        self.program = object()
        self.closed = False
        self.project_handle = project_handle
        self.domain_path = domain_path

    def get_program(self):
        return self.program

    def get_project_handle(self):
        return self.project_handle

    def close(self, remove_program: bool = False):
        self.closed = True
        if self.project_handle is not None:
            self.project_handle.release_program(self.program, remove_program=remove_program)

    def to_dict(self):
        project_name = self.project_handle.get_project_name() if self.project_handle else None
        project_location = self.project_handle.get_project_location() if self.project_handle else None
        return {
            "domain_path": self.domain_path,
            "project_name": project_name,
            "project_location": project_location,
        }


class DummyDomainFileRef:
    def __init__(self, path):
        self._path = path

    def getPathname(self):
        return self._path


class DummyProgramRef:
    def __init__(self, path):
        self._domain_file = DummyDomainFileRef(path)

    def getDomainFile(self):
        return self._domain_file


class DummyHandle:
    def __init__(self, key=("./project", "Sample"), name="Sample"):
        key = (str(Path(key[0]).resolve()), key[1])
        self.key = key
        self.closed = False
        self.last_domain = None
        self.last_import_path = None
        self.project_location = key[0]
        self.project_name = name
        self.releases = []
        self.deleted_programs = []
        self.program_paths: dict[object, str | None] = {}
        self.sync_calls = []
        self.sync_status = {
            "is_versioned": True,
            "is_checked_out": False,
            "is_checked_out_exclusive": False,
            "is_latest_version": True,
            "modified_since_checkout": False,
            "can_add_to_repository": False,
            "can_checkout": True,
            "can_checkin": False,
            "can_merge": False,
            "is_hijacked": False,
            "version": 1,
            "latest_version": 1,
            "checkout_status": None,
            "checkouts": [],
            "shared_project_url": "ghidra://server/repo",
        }
        self.project = types.SimpleNamespace(save=lambda program: None)

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
        session = DummySession(domain_path=domain_path)
        session.project_handle = self
        session.program = DummyProgramRef(domain_path)
        self.program_paths[session.program] = session.domain_path
        return session

    def import_program(self, path):
        self.last_import_path = path

        class DummyDomainFile:
            def __init__(self, domain_path):
                self._domain_path = domain_path

            def getPathname(self):
                return self._domain_path

        return DummyDomainFile("/" + Path(path).name)

    def list_programs(self):
        return ["/folder/A", "/folder/B"]

    def close(self):
        self.closed = True

    def release_program(self, program, *, remove_program: bool = False):
        self.releases.append({"program": program, "remove_program": remove_program})
        domain_path = self.program_paths.pop(program, None)
        if remove_program and domain_path:
            self.deleted_programs.append(domain_path)

    def get_sync_status(self, domain_path):
        self.sync_calls.append(("get_sync_status", domain_path))
        return dict(self.sync_status)

    def checkout_program(self, domain_path, *, exclusive=False):
        self.sync_calls.append(("checkout_program", domain_path, exclusive))
        self.sync_status["is_checked_out"] = True
        self.sync_status["is_checked_out_exclusive"] = bool(exclusive)
        return True

    def add_program_to_version_control(self, domain_path, comment, *, keep_checked_out=False):
        self.sync_calls.append(("add_program_to_version_control", domain_path, comment, keep_checked_out))
        self.sync_status["is_versioned"] = True
        self.sync_status["can_add_to_repository"] = False
        self.sync_status["version"] = max(1, int(self.sync_status.get("version") or 0))
        self.sync_status["latest_version"] = self.sync_status["version"]
        self.sync_status["is_latest_version"] = True
        self.sync_status["is_checked_out"] = bool(keep_checked_out)

    def commit_program(self, domain_path, message, *, keep_checked_out=False, create_keep_file=False):
        self.sync_calls.append(("commit_program", domain_path, message, keep_checked_out, create_keep_file))
        self.sync_status["version"] = int(self.sync_status.get("version") or 0) + 1
        self.sync_status["latest_version"] = self.sync_status["version"]
        self.sync_status["is_latest_version"] = True
        self.sync_status["modified_since_checkout"] = False
        self.sync_status["can_checkin"] = False
        self.sync_status["is_checked_out"] = bool(keep_checked_out)

    def merge_program(self, domain_path, *, ok_to_upgrade=True):
        self.sync_calls.append(("merge_program", domain_path, ok_to_upgrade))
        self.sync_status["latest_version"] = int(self.sync_status.get("latest_version") or 0) + 1
        self.sync_status["version"] = self.sync_status["latest_version"]
        self.sync_status["is_latest_version"] = True
        self.sync_status["can_merge"] = False

    def undo_checkout_program(self, domain_path, *, keep=False):
        self.sync_calls.append(("undo_checkout_program", domain_path, keep))
        self.sync_status["is_checked_out"] = False
        self.sync_status["is_checked_out_exclusive"] = False
        if not keep:
            self.sync_status["modified_since_checkout"] = False

    def terminate_checkout_program(self, domain_path, checkout_id):
        self.sync_calls.append(("terminate_checkout_program", domain_path, int(checkout_id)))


def test_parse_session_definition_minimal():
    cfg = cli._parse_session_definition("name=fw,project_location=/tmp/sample.gpr,domain_path=/folder/fw.bin")
    assert cfg["name"] == "fw"
    assert cfg["project_location"] == "/tmp/sample.gpr"
    assert cfg["domain_path"] == "/folder/fw.bin"


@pytest.mark.parametrize(
    "text",
    ["project_location=/tmp/sample.gpr", "name=fw,domain_path=/folder/fw.bin"],
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


def test_session_registry_create_close(tmp_path, monkeypatch):
    project_file = tmp_path / "sample.gpr"
    project_file.write_text("")
    calls = dummy_core(monkeypatch)

    dummy_handle = DummyHandle(key=(str(project_file.parent), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    session = registry.create_session("fw", project_location=str(project_file), domain_path="/folder/fw.bin")

    assert registry.list_targets() == [
        {
            "target": "fw",
            "domain_path": "/folder/fw.bin",
            "project_name": "Sample",
            "project_location": str(tmp_path),
        }
    ]
    assert dummy_handle.last_domain == "/folder/fw.bin"
    assert calls["initialize"] == [(session.program, "fw")]

    registry.close_session("fw")
    assert registry.list_targets() == []
    assert session.closed is True
    assert calls["remove"] == ["fw"]
    assert dummy_handle.releases == [{"program": session.program, "remove_program": False}]


def test_session_registry_close_and_remove_program(tmp_path, monkeypatch):
    project_file = tmp_path / "sample.gpr"
    project_file.write_text("")
    calls = dummy_core(monkeypatch)

    dummy_handle = DummyHandle(key=(str(project_file.parent), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    session = registry.create_session("fw", project_location=str(project_file), domain_path="/folder/fw.bin")

    registry.close_session("fw", remove_program=True)
    assert registry.list_targets() == []
    assert session.closed is True
    assert calls["remove"] == ["fw"]
    assert dummy_handle.releases == [{"program": session.program, "remove_program": True}]
    assert dummy_handle.deleted_programs == ["/folder/fw.bin"]


def test_registry_close_all(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.create_session("a", project_location=str(tmp_path), project_name="sample", domain_path="/folder/a.bin")
    registry.create_session("b", project_location=str(tmp_path / "sample.gpr"), domain_path="/folder/b.bin")

    registry.close_all()
    assert registry.list_targets() == []
    assert set(calls["remove"]) == {"a", "b"}
    assert calls["clear"] == 1


def test_registry_reuses_active_project_handle(monkeypatch):
    calls = dummy_core(monkeypatch)
    registry = cli.SessionRegistry()
    handle = DummyHandle()
    with registry._registry_lock.write_lock():
        registry._project_handles[handle.get_key()] = handle

    session = registry.create_session("reuse", project_location=handle.get_key()[0], project_name=handle.get_key()[1], domain_path="/folder/main")

    assert session.get_project_handle() is handle
    assert handle.last_domain == "/folder/main"
    assert calls["initialize"] == [(session.program, "reuse")]


def test_registry_register_target_without_program(tmp_path):
    registry = cli.SessionRegistry()

    result = registry.register_target("fw", project_location=str(tmp_path), project_name="sample")

    assert result == {
        "target": "fw",
        "project_location": str(tmp_path.resolve()),
        "project_name": "sample",
        "domain_path": None,
    }
    assert registry.list_targets() == [result]
    assert registry.has_targets() is True
    assert registry.has_sessions() is False


def test_registry_import_program(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    imported_path = registry.import_program("fw", "/tmp/new.bin")

    assert imported_path == "/new.bin"
    assert registry.list_targets() == [
        {
            "target": "fw",
            "domain_path": "/folder/old",
            "project_name": "Sample",
            "project_location": str(tmp_path),
        }
    ]
    assert dummy_handle.last_import_path == "/tmp/new.bin"
    assert dummy_handle.releases == []
    assert len(calls["initialize"]) == 1


def test_registry_import_program_without_loaded_program(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.register_target("fw", project_location=str(tmp_path), project_name="sample")

    imported_path = registry.import_program("fw", "/tmp/new.bin")

    assert imported_path == "/new.bin"
    assert dummy_handle.last_import_path == "/tmp/new.bin"
    assert registry.list_targets() == [
        {
            "target": "fw",
            "domain_path": None,
            "project_name": "sample",
            "project_location": str(tmp_path.resolve()),
        }
    ]
    assert calls["initialize"] == []


def test_registry_load_program_requires_domain_path(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    with pytest.raises(ValueError, match="domain_path"):
        registry.load_program("fw", None)

    assert len(calls["initialize"]) == 1


def test_registry_load_program_from_registered_target(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.register_target("fw", project_location=str(tmp_path), project_name="sample")

    loaded = registry.load_program("fw", "/folder/new")

    assert loaded == "/folder/new"
    assert registry.list_targets() == [
        {
            "target": "fw",
            "domain_path": "/folder/new",
            "project_name": "Sample",
            "project_location": str(tmp_path),
        }
    ]
    assert len(calls["initialize"]) == 1


def test_program_session_to_dict_binary(tmp_path):
    class DummyProgram:
        def getDomainFile(self):
            class DummyDomainFile:
                def getPathname(self):
                    return "/fw.bin"
            return DummyDomainFile()

    session = cli.ProgramSession(
        flat_api=None,
        program=DummyProgram(),
        project_handle=DummyHandle(key=(str(tmp_path), "Sample")),
    )

    assert session.to_dict() == {
        "domain_path": "/fw.bin",
        "project_name": "Sample",
        "project_location": str(tmp_path),
    }


def test_program_session_to_dict_project():
    class DummyProgram:
        def getDomainFile(self):
            class DummyDomainFile:
                def getPathname(self):
                    return "/main.bin"
            return DummyDomainFile()

    handle = DummyHandle(key=("./projects", "ProjectX.gpr"), name="ProjectX")
    session = cli.ProgramSession(
        flat_api=None,
        program=DummyProgram(),
        project_handle=handle,
    )

    assert session.to_dict() == {
        "domain_path": "/main.bin",
        "project_name": "ProjectX",
        "project_location": str(Path("./projects").resolve()),
    }


def test_list_programs_for_target_returns_programs():
    registry = cli.SessionRegistry()
    handle_a = DummyHandle(name="A")
    handle_b = DummyHandle(key=("/project", "B"), name="B")
    session_a = DummySession(project_handle=handle_a, domain_path="/folder/A")
    session_b = DummySession(project_handle=handle_b, domain_path="/folder/B")
    with registry._registry_lock.write_lock():
        registry._sessions["a"] = session_a
        registry._sessions["b"] = session_b

    result = registry.list_programs("a")

    assert result == handle_a.list_programs()


def test_list_programs_requires_existing_target():
    registry = cli.SessionRegistry()
    with pytest.raises(RuntimeError, match="初期化されていません"):
        registry.list_programs("missing")


def test_add_bookmark_tool_invokes_core(monkeypatch):
    recorded = {}

    def fake_call(self, command, params, target):
        recorded["command"] = command
        recorded["params"] = params
        recorded["target"] = target
        return {"status": "ok"}

    monkeypatch.setattr(cli.SessionRegistry, "call", fake_call)

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


def test_close_session_and_remove_program_tool(monkeypatch):
    called = {}

    def fake_close(name, *, remove_program=False):
        called["target"] = name
        called["remove_program"] = remove_program

    monkeypatch.setattr(cli._registry, "close_session", fake_close)

    result = cli.close_session_and_remove_program("target1")

    assert result == {"status": "ok", "target": "target1"}
    assert called == {"target": "target1", "remove_program": True}


def test_create_session_tool_uses_domain_path(monkeypatch):
    called = {}

    def fake_create_session(name, project_location, *, project_name=None, domain_path=None):
        called["name"] = name
        called["project_location"] = project_location
        called["project_name"] = project_name
        called["domain_path"] = domain_path

    monkeypatch.setattr(cli._registry, "create_session", fake_create_session)

    result = cli.create_session(
        target="fw",
        project_location="/tmp/sample.gpr",
        domain_path="/folder/fw.bin",
    )

    assert result == {"status": "ok", "target": "fw"}
    assert called == {
        "name": "fw",
        "project_location": "/tmp/sample.gpr",
        "project_name": None,
        "domain_path": "/folder/fw.bin",
    }


def test_create_session_tool_rejects_binary_path():
    with pytest.raises(TypeError):
        cli.create_session(
            target="fw",
            project_location="/tmp/sample.gpr",
            binary_path="/tmp/fw.bin",
        )


def test_create_session_tool_requires_domain_path():
    with pytest.raises(TypeError):
        cli.create_session(
            target="fw",
            project_location="/tmp/sample.gpr",
        )


def test_list_project_programs_tool_requires_target():
    with pytest.raises(TypeError):
        cli.list_project_programs()


def test_list_project_programs_tool_passes_target(monkeypatch):
    called = {}

    def fake_list_programs(target):
        called["target"] = target
        return ["/folder/A", "/folder/B"]

    monkeypatch.setattr(cli._registry, "list_programs", fake_list_programs)

    result = cli.list_project_programs("fw")

    assert result == ["/folder/A", "/folder/B"]
    assert called == {"target": "fw"}


def test_import_program_tool(monkeypatch):
    called = {}

    def fake_import_program(target, binary_path):
        called["target"] = target
        called["binary_path"] = binary_path
        return "/imported/fw.bin"

    monkeypatch.setattr(cli._registry, "import_program", fake_import_program)

    result = cli.import_program(target="fw", binary_path="/tmp/fw.bin")

    assert result == {"status": "ok", "target": "fw", "program": "/imported/fw.bin"}
    assert called == {
        "target": "fw",
        "binary_path": "/tmp/fw.bin",
    }


def test_load_project_program_tool_accepts_domain_path(monkeypatch):
    called = {}

    def fake_load_program(target, domain_path):
        called["target"] = target
        called["domain_path"] = domain_path
        return domain_path

    monkeypatch.setattr(cli._registry, "load_program", fake_load_program)

    result = cli.load_project_program(target="fw", domain_path="/folder/current.bin")

    assert result == {"status": "ok", "target": "fw", "program": "/folder/current.bin"}
    assert called == {
        "target": "fw",
        "domain_path": "/folder/current.bin",
    }


def test_registry_get_project_sync_status(tmp_path, monkeypatch):
    calls = dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)

    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    status = registry.get_project_sync_status("fw")

    assert status["target"] == "fw"
    assert status["program"] == "/folder/old"
    assert status["is_versioned"] is True
    assert len(calls["initialize"]) == 1


def test_registry_checkout_project_program(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.checkout_project_program("fw", exclusive=True)

    assert result["status"] == "ok"
    assert result["checked_out"] is True
    assert result["exclusive"] is True
    assert ("checkout_program", "/folder/old", True) in dummy_handle.sync_calls


def test_registry_add_project_program_to_version_control(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    dummy_handle.sync_status["is_versioned"] = False
    dummy_handle.sync_status["can_add_to_repository"] = True
    dummy_handle.sync_status["version"] = 0
    dummy_handle.sync_status["latest_version"] = 0
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.add_project_program_to_version_control("fw", "enable shared", keep_checked_out=True)

    assert result["status"] == "ok"
    assert result["is_versioned"] is True
    assert result["effective_keep_checked_out"] is True
    assert any(call[0] == "add_program_to_version_control" for call in dummy_handle.sync_calls)
    assert len(dummy_handle.releases) == 1


def test_registry_commit_project_program(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    dummy_handle.sync_status["is_checked_out"] = True
    dummy_handle.sync_status["can_checkin"] = True
    dummy_handle.sync_status["modified_since_checkout"] = True
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.commit_project_program("fw", "sync result")

    assert result["status"] == "ok"
    assert result["new_version"] == 2
    assert result["effective_keep_checked_out"] is False
    assert any(call[0] == "commit_program" for call in dummy_handle.sync_calls)
    assert len(dummy_handle.releases) == 1


def test_registry_commit_project_program_discards_on_conflict(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    dummy_handle.sync_status["is_checked_out"] = True
    dummy_handle.sync_status["can_checkin"] = True
    dummy_handle.sync_status["modified_since_checkout"] = True
    dummy_handle.sync_status["can_merge"] = True
    dummy_handle.sync_status["version"] = 2
    dummy_handle.sync_status["latest_version"] = 3
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.commit_project_program("fw", "sync result")

    assert result["status"] == "noop"
    assert result["reason"] == "conflict_discarded"
    assert result["discarded_local_changes"] is True
    assert result["merged"] is True
    assert result["checked_out"] is False
    assert not any(call[0] == "commit_program" for call in dummy_handle.sync_calls)
    assert any(call[0] == "undo_checkout_program" for call in dummy_handle.sync_calls)
    assert any(call[0] == "merge_program" for call in dummy_handle.sync_calls)
    assert len(dummy_handle.releases) == 1


def test_registry_pull_project_program_with_discard(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    dummy_handle.sync_status["is_checked_out"] = True
    dummy_handle.sync_status["modified_since_checkout"] = True
    dummy_handle.sync_status["can_merge"] = True
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.pull_project_program("fw", on_local_changes="discard")

    assert result["status"] == "ok"
    assert result["discarded_local_changes"] is True
    assert any(call[0] == "undo_checkout_program" for call in dummy_handle.sync_calls)
    assert len(dummy_handle.releases) == 1


def test_registry_undo_checkout_project_program(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    dummy_handle.sync_status["is_checked_out"] = True
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.undo_checkout_project_program("fw", discard_local_changes=True)

    assert result["status"] == "ok"
    assert result["checked_out"] is False
    assert any(call[0] == "undo_checkout_program" for call in dummy_handle.sync_calls)
    assert len(dummy_handle.releases) == 1


def test_registry_terminate_project_program_checkout(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.terminate_project_program_checkout("fw", checkout_id=12)

    assert result["status"] == "ok"
    assert result["checkout_id"] == 12
    assert ("terminate_checkout_program", "/folder/old", 12) in dummy_handle.sync_calls


def test_registry_reload_project_program(tmp_path, monkeypatch):
    dummy_core(monkeypatch)
    dummy_handle = DummyHandle(key=(str(tmp_path), "sample"))
    monkeypatch.setattr(cli.SessionRegistry, "_get_or_create_project_handle", lambda self, *args, **kwargs: dummy_handle)
    registry = cli.SessionRegistry()
    registry.create_session("fw", project_location=str(tmp_path), project_name="sample", domain_path="/folder/old")

    result = registry.reload_project_program("fw")

    assert result == {
        "status": "ok",
        "target": "fw",
        "program": "/folder/old",
        "reloaded": True,
    }
    assert len(dummy_handle.releases) == 1


def test_shared_project_sync_tool_wrappers(monkeypatch):
    called = {}

    monkeypatch.setattr(cli._registry, "get_project_sync_status", lambda target: {"target": target})
    monkeypatch.setattr(
        cli._registry,
        "checkout_project_program",
        lambda target, exclusive=False: called.setdefault("checkout", (target, exclusive)) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "commit_project_program",
        lambda target, message, keep_checked_out=False, auto_checkout=True: called.setdefault(
            "commit", (target, message, keep_checked_out, auto_checkout)
        ) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "pull_project_program",
        lambda target, on_local_changes="abort": called.setdefault("pull", (target, on_local_changes)) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "undo_checkout_project_program",
        lambda target, discard_local_changes=True: called.setdefault(
            "undo", (target, discard_local_changes)
        ) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "terminate_project_program_checkout",
        lambda target, checkout_id: called.setdefault("terminate", (target, checkout_id)) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "add_project_program_to_version_control",
        lambda target, comment, keep_checked_out=False: called.setdefault(
            "add", (target, comment, keep_checked_out)
        ) or {},
    )
    monkeypatch.setattr(
        cli._registry,
        "reload_project_program",
        lambda target: called.setdefault("reload", (target,)) or {},
    )

    assert cli.get_project_sync_status("fw") == {"target": "fw"}
    cli.checkout_project_program("fw", exclusive=True)
    cli.add_project_program_to_version_control("fw", comment="enable shared", keep_checked_out=False)
    cli.commit_project_program("fw", "msg", keep_checked_out=True, auto_checkout=False)
    cli.pull_project_program("fw", on_local_changes="discard")
    cli.undo_checkout_project_program("fw", discard_local_changes=False)
    cli.terminate_project_program_checkout("fw", checkout_id=7)
    cli.reload_project_program("fw")

    assert called["checkout"] == ("fw", True)
    assert called["add"] == ("fw", "enable shared", False)
    assert called["commit"] == ("fw", "msg", True, False)
    assert called["pull"] == ("fw", "discard")
    assert called["undo"] == ("fw", False)
    assert called["terminate"] == ("fw", 7)
    assert called["reload"] == ("fw",)


def test_register_shared_project_sync_tools(monkeypatch):
    recorded = []

    def fake_add_tool(fn, **kwargs):
        recorded.append((fn.__name__, kwargs.get("description")))

    monkeypatch.setattr(cli, "_shared_project_sync_tools_registered", False)
    monkeypatch.setattr(cli.mcp, "add_tool", fake_add_tool)

    cli.register_shared_project_sync_tools()
    cli.register_shared_project_sync_tools()

    names = [name for name, _ in recorded]
    assert names == [
        "get_project_sync_status",
        "checkout_project_program",
        "add_project_program_to_version_control",
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "reload_project_program",
    ]


def test_parse_args_accepts_http():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--transport",
            "http",
            "--mcp-host",
            "0.0.0.0",
            "--mcp-port",
            "9090",
            "--mcp-path",
            "/mcp",
        ]
    )

    assert args.transport == "http"
    assert args.mcp_host == "0.0.0.0"
    assert args.mcp_port == 9090
    assert args.mcp_path == "/mcp"


def test_parse_args_rejects_stream_http():
    with pytest.raises(SystemExit):
        cli.parse_args(
            [
                "--project-location",
                "/tmp/sample.gpr",
                "--domain-path",
                "/main",
                "--transport",
                "stream-http",
            ]
        )


def test_parse_args_enable_shared_project_sync():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--enable-shared-project-sync",
        ]
    )
    assert args.enable_shared_project_sync is True


def test_parse_args_ghidra_server_auth_options():
    args = cli.parse_args(
        [
            "--project-location",
            "/tmp/sample.gpr",
            "--domain-path",
            "/main",
            "--ghidra-server-user",
            "alice",
            "--ghidra-server-password-env",
            "GHIDRA_SERVER_PASSWORD",
        ]
    )
    assert args.ghidra_server_user == "alice"
    assert args.ghidra_server_password_env == "GHIDRA_SERVER_PASSWORD"


def test_normalize_transport_alias():
    assert cli._normalize_transport("http") == "streamable-http"
    assert cli._normalize_transport("sse") == "sse"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mcp", "/mcp"),
        ("/mcp", "/mcp"),
        ("", "/mcp"),
    ],
)
def test_normalize_streamable_http_path(raw, expected):
    assert cli._normalize_streamable_http_path(raw) == expected


def test_configure_mcp_for_streamable_http(monkeypatch):
    fake_mcp = types.SimpleNamespace(
        settings=types.SimpleNamespace(
            log_level="INFO",
            host="127.0.0.1",
            port=8081,
            streamable_http_path="/mcp",
        )
    )
    monkeypatch.setattr(cli, "mcp", fake_mcp)

    args = types.SimpleNamespace(
        log_level="DEBUG",
        mcp_host="0.0.0.0",
        mcp_port=9090,
        mcp_path="custom",
    )
    cli.configure_mcp_for_streamable_http(args)

    assert fake_mcp.settings.log_level == "DEBUG"
    assert fake_mcp.settings.host == "0.0.0.0"
    assert fake_mcp.settings.port == 9090
    assert fake_mcp.settings.streamable_http_path == "/custom"


def test_configure_ghidra_server_auth_sets_client_authenticator(monkeypatch):
    called = {}

    class FakePasswordAuthenticator:
        def __init__(self, username, password):
            called["constructor"] = (username, password)

    class FakeClientUtil:
        @staticmethod
        def setClientAuthenticator(authenticator):
            called["authenticator"] = authenticator

    monkeypatch.setenv("GHIDRA_SERVER_PASSWORD", "secret")
    monkeypatch.setattr(cli, "_password_client_authenticator_class", lambda: FakePasswordAuthenticator)
    monkeypatch.setattr(cli, "_client_util_class", lambda: FakeClientUtil)

    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    cli.configure_ghidra_server_auth(args)

    assert called["constructor"] == ("alice", "secret")
    assert isinstance(called["authenticator"], FakePasswordAuthenticator)


@pytest.mark.parametrize(
    ("username", "password_env_name"),
    [
        ("alice", ""),
        ("", "GHIDRA_SERVER_PASSWORD"),
    ],
)
def test_configure_ghidra_server_auth_requires_user_and_env(monkeypatch, username, password_env_name):
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    args = types.SimpleNamespace(
        ghidra_server_user=username,
        ghidra_server_password_env=password_env_name,
    )
    with pytest.raises(ValueError, match="セットで指定してください"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_requires_non_empty_env_value(monkeypatch):
    monkeypatch.setenv("GHIDRA_SERVER_PASSWORD", "")
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    with pytest.raises(ValueError, match="空です"):
        cli.configure_ghidra_server_auth(args)


def test_configure_ghidra_server_auth_requires_existing_env(monkeypatch):
    monkeypatch.delenv("GHIDRA_SERVER_PASSWORD", raising=False)
    args = types.SimpleNamespace(
        ghidra_server_user="alice",
        ghidra_server_password_env="GHIDRA_SERVER_PASSWORD",
    )
    with pytest.raises(ValueError, match="未設定です"):
        cli.configure_ghidra_server_auth(args)
