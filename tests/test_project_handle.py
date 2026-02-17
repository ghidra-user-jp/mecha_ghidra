import threading
import types
import pathlib

import pytest

from ghidra_headless import session


class DummyFlatAPI:
    def __init__(self, program, monitor) -> None:
        self.program = program
        self.monitor = monitor


class DummyDomainFile:
    def __init__(self, path: str) -> None:
        self._path = path

    def getPathname(self) -> str:
        return self._path


class DummyProgram:
    def __init__(self, path: str) -> None:
        self._domain_file = DummyDomainFile(path)

    def getDomainFile(self):
        return self._domain_file

    def getName(self) -> str:
        return pathlib.Path(self._domain_file.getPathname()).name


class DummyProject:
    def __init__(self) -> None:
        self.saved: list[DummyProgram] = []
        self.closed: list[DummyProgram | None] = []

    def openProgram(self, domain_dir, domain_name, flag):
        return DummyProgram((pathlib.PurePosixPath(domain_dir) / domain_name).as_posix())

    def save(self, program):
        self.saved.append(program)

    def close(self, program=None):
        self.closed.append(program)

    def getProject(self):
        return types.SimpleNamespace(getName=lambda: "DummyProject")


def build_handle(monkeypatch):
    monkeypatch.setattr(session, "_flat_program_api_class", lambda: DummyFlatAPI)
    monkeypatch.setattr(session, "_console_monitor", lambda: None)

    handle = session.ProjectHandle.__new__(session.ProjectHandle)
    handle._lock = threading.RLock()
    handle.project_location = "/project"
    handle.project_name = "Sample"
    handle.key = (handle.project_location, handle.project_name)
    handle.project = DummyProject()
    handle._refcount = 0
    handle._closed = False
    handle._open_programs = set()
    return handle


def test_open_program_rejects_duplicates(monkeypatch):
    handle = build_handle(monkeypatch)

    first_session = handle.open_program("/folder/firmware")
    with pytest.raises(RuntimeError, match="セッションがあります"):
        handle.open_program("/folder/firmware")

    assert handle._refcount == 1
    assert ("/folder", "firmware") in handle._open_programs

    first_session.close()
    assert handle._open_programs == set()
    assert handle._refcount == 0


def test_open_program_allows_reopen_after_release(monkeypatch):
    handle = build_handle(monkeypatch)

    session_one = handle.open_program("/folder/app")
    session_one.close()

    new_handle = build_handle(monkeypatch)
    session_two = new_handle.open_program("/folder/app")
    assert session_two.get_program().getDomainFile().getPathname() == "/folder/app"


def test_sync_status_raises_when_required_call_fails():
    class BrokenDomainFile:
        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _):
            return None

        def isVersioned(self):
            raise RuntimeError("backend unavailable")

    with pytest.raises(RuntimeError, match="SYNC_STATUS_UNAVAILABLE"):
        session._sync_status_from_domain_file(BrokenDomainFile())
