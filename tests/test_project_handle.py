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


def test_delete_program_locked_raises_when_delete_fails(monkeypatch):
    handle = build_handle(monkeypatch)

    class FailingDomainFile:
        def delete(self):
            raise RuntimeError("delete failed")

    class DummyProjectData:
        def getFile(self, _domain_path):
            return FailingDomainFile()

    class DummyProjectWithFailingDelete(DummyProject):
        def getProjectData(self):
            return DummyProjectData()

    handle.project = DummyProjectWithFailingDelete()

    with pytest.raises(RuntimeError, match="プログラム削除に失敗しました"):
        handle._delete_program_locked("/folder/app")


def test_release_program_clears_tracking_when_delete_fails(monkeypatch):
    handle = build_handle(monkeypatch)
    opened = handle.open_program("/folder/app")
    program = opened.get_program()

    monkeypatch.setattr(
        handle,
        "_delete_program_locked",
        lambda _path: (_ for _ in ()).throw(RuntimeError("delete failed")),
    )

    with pytest.raises(RuntimeError, match="delete failed"):
        handle.release_program(program, remove_program=True)

    assert handle._open_programs == set()
    assert handle._refcount == 0


def test_get_version_history(monkeypatch):
    handle = build_handle(monkeypatch)

    class DummyVersion:
        def __init__(self, version, user, comment, create_time):
            self._version = version
            self._user = user
            self._comment = comment
            self._create_time = create_time

        def getVersion(self):
            return self._version

        def getUser(self):
            return self._user

        def getComment(self):
            return self._comment

        def getCreateTime(self):
            return self._create_time

    class DummyVersionedDomainFile:
        def isVersioned(self):
            return True

        def getVersion(self):
            return 2

        def getLatestVersion(self):
            return 2

        def getVersionHistory(self):
            return [
                DummyVersion(1, "alice", "init", 1000),
                DummyVersion(2, "bob", "update", 2000),
            ]

    monkeypatch.setattr(handle, "_get_domain_file_locked", lambda _path: DummyVersionedDomainFile())

    result = handle.get_version_history("/folder/app", limit=1)

    assert result["program"] == "/folder/app"
    assert result["current_version"] == 2
    assert result["latest_version"] == 2
    assert result["total_versions"] == 2
    assert result["versions"][0]["version"] == 2
    assert result["versions"][0]["create_time_iso"] == "1970-01-01T00:00:02Z"


def test_get_version_diff(monkeypatch):
    handle = build_handle(monkeypatch)

    class DummyVersion:
        def __init__(self, version):
            self._version = version

        def getVersion(self):
            return self._version

    class DummyProgram:
        def __init__(self, version):
            self.version = version
            self.released = []

        def release(self, consumer):
            self.released.append(consumer)

    class DummyRange:
        def __init__(self, start, end, length):
            self._start = start
            self._end = end
            self._length = length

        def getMinAddress(self):
            return self._start

        def getMaxAddress(self):
            return self._end

        def getLength(self):
            return self._length

    class DummyAddressSet:
        def __init__(self, addresses, ranges):
            self._addresses = addresses
            self._ranges = ranges

        def getNumAddresses(self):
            return self._addresses

        def getNumAddressRanges(self):
            return len(self._ranges)

        def getAddressRanges(self):
            return self._ranges

    class DummyProgramDiffFilter:
        def getPrimaryTypes(self):
            return [1, 2]

        def typeToName(self, diff_type):
            return {1: "Bytes", 2: "Functions"}[int(diff_type)]

    class DummyProgramDiff:
        def __init__(self, _from_program, _to_program):
            self._diffs = DummyAddressSet(
                3,
                [
                    DummyRange("0x1000", "0x1001", 2),
                    DummyRange("0x2000", "0x2000", 1),
                ],
            )

        def getDifferences(self, _monitor):
            return self._diffs

        def getTypeDiffs(self, diff_type, _differences, _monitor):
            mapping = {
                1: DummyAddressSet(3, [DummyRange("0x1000", "0x1001", 2)]),
                2: DummyAddressSet(1, [DummyRange("0x2000", "0x2000", 1)]),
            }
            return mapping[int(diff_type)]

        def getWarnings(self):
            return "none"

    class DummyVersionedDomainFile:
        def __init__(self):
            self.programs = {}

        def isVersioned(self):
            return True

        def getVersionHistory(self):
            return [DummyVersion(1), DummyVersion(2)]

        def getReadOnlyDomainObject(self, consumer, version, _monitor):
            program = DummyProgram(version)
            self.programs[int(version)] = program
            return program

    domain_file = DummyVersionedDomainFile()
    monkeypatch.setattr(handle, "_get_domain_file_locked", lambda _path: domain_file)
    monkeypatch.setattr(session, "_program_diff_class", lambda: DummyProgramDiff)
    monkeypatch.setattr(session, "_program_diff_filter_class", lambda: DummyProgramDiffFilter)
    monkeypatch.setattr(session, "_console_monitor", lambda: None)
    consumers = []

    def fake_consumer():
        consumer = object()
        consumers.append(consumer)
        return consumer

    monkeypatch.setattr(session, "_java_object", fake_consumer)

    result = handle.get_version_diff("/folder/app", from_version=1, to_version=2, range_limit=1)

    assert result["program"] == "/folder/app"
    assert result["total_diff_addresses"] == 3
    assert result["total_diff_ranges"] == 2
    assert result["ranges_truncated"] is True
    assert len(result["ranges"]) == 1
    assert result["diff_types"] == [
        {"type": "Bytes", "count": 3},
        {"type": "Functions", "count": 1},
    ]
    assert result["warnings"] == "none"
    assert domain_file.programs[1].released == [consumers[0]]
    assert domain_file.programs[2].released == [consumers[1]]


def test_list_programs_from_metadata_parses_program_entries(tmp_path):
    idata = tmp_path / "sample.rep" / "idata" / "00"
    idata.mkdir(parents=True)

    (idata / "00000001.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Program" />
    <STATE NAME="PARENT" TYPE="string" VALUE="/folder" />
    <STATE NAME="NAME" TYPE="string" VALUE="a.bin" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )
    (idata / "00000002.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Folder" />
    <STATE NAME="PARENT" TYPE="string" VALUE="/" />
    <STATE NAME="NAME" TYPE="string" VALUE="folder" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )
    (idata / "00000003.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Program" />
    <STATE NAME="PARENT" TYPE="string" VALUE="/" />
    <STATE NAME="NAME" TYPE="string" VALUE="z.bin" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )

    result = session.ProjectHandle.list_programs_from_metadata(str(tmp_path), "sample")

    assert result == [
        {"domain_path": "/folder/a.bin", "domain_name": "a.bin", "contentType": "Program"},
        {"domain_path": "/z.bin", "domain_name": "z.bin", "contentType": "Program"},
    ]


def test_list_programs_from_metadata_returns_none_when_rep_missing(tmp_path):
    result = session.ProjectHandle.list_programs_from_metadata(str(tmp_path), "sample")
    assert result is None
