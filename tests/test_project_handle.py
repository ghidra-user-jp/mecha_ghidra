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
    def __init__(self, path: str, *, changed: bool = True) -> None:
        self._domain_file = DummyDomainFile(path)
        self._changed = changed

    def getDomainFile(self):
        return self._domain_file

    def getName(self) -> str:
        return pathlib.Path(self._domain_file.getPathname()).name

    def isChanged(self) -> bool:
        return self._changed


class DummyProject:
    def __init__(self) -> None:
        self.saved: list[DummyProgram] = []
        self.closed: list[DummyProgram | None] = []
        self._project_ref = types.SimpleNamespace(getName=lambda: "DummyProject")

    def openProgram(self, domain_dir, domain_name, flag):
        return DummyProgram((pathlib.PurePosixPath(domain_dir) / domain_name).as_posix())

    def save(self, program):
        self.saved.append(program)

    def close(self, program=None):
        self.closed.append(program)

    def getProject(self):
        return self._project_ref


def build_handle(monkeypatch):
    monkeypatch.setattr(session.java_bindings, "_flat_program_api_class", lambda: DummyFlatAPI)
    monkeypatch.setattr(session.java_bindings, "_console_monitor", lambda: None)

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
    with pytest.raises(RuntimeError, match="active session"):
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


def test_close_can_skip_save(monkeypatch):
    handle = build_handle(monkeypatch)

    opened = handle.open_program("/folder/app")
    program = opened.get_program()
    opened.close(save=False)

    assert handle.project.saved == []
    assert handle.project.closed == [program, None]
    assert handle._open_programs == set()
    assert handle._refcount == 0


def test_close_surfaces_save_failed_after_closing_program(monkeypatch):
    handle = build_handle(monkeypatch)

    class FailingSaveProject(DummyProject):
        def save(self, _program):
            raise RuntimeError("disk full")

    handle.project = FailingSaveProject()
    opened = handle.open_program("/folder/app")
    program = opened.get_program()

    with pytest.raises(RuntimeError, match="SAVE_FAILED: failed to save program before close: disk full"):
        opened.close()

    with pytest.raises(RuntimeError, match="Session is already closed"):
        opened.get_program()
    assert handle.project.saved == []
    assert handle.project.closed == [program, None]
    assert handle._open_programs == set()
    assert handle._refcount == 0


def test_close_surfaces_close_failed_and_marks_session_closed(monkeypatch):
    handle = build_handle(monkeypatch)

    class FailingCloseProject(DummyProject):
        def close(self, program=None):
            super().close(program)
            if program is not None:
                raise RuntimeError("close failed")

    handle.project = FailingCloseProject()
    opened = handle.open_program("/folder/app")
    program = opened.get_program()

    with pytest.raises(RuntimeError, match="SESSION_CLOSE_FAILED: failed to close program: close failed"):
        opened.close()

    with pytest.raises(RuntimeError, match="Session is already closed"):
        opened.get_program()
    assert handle.is_closed() is True
    assert handle.project.closed == [program, None]
    assert handle._open_programs == set()
    assert handle._refcount == 0


def test_close_skips_save_for_clean_program(monkeypatch):
    handle = build_handle(monkeypatch)

    class CleanProject(DummyProject):
        def openProgram(self, domain_dir, domain_name, flag):  # noqa: ARG002
            return DummyProgram((pathlib.PurePosixPath(domain_dir) / domain_name).as_posix(), changed=False)

    handle.project = CleanProject()
    opened = handle.open_program("/folder/app")
    program = opened.get_program()
    opened.close()

    assert handle.project.saved == []
    assert handle.project.closed == [program, None]
    assert handle._open_programs == set()
    assert handle._refcount == 0


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
        session.sync_utils._sync_status_from_domain_file(BrokenDomainFile())


def test_sync_status_normalizes_unversioned_version_fields():
    class UnversionedDomainFile:
        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _):
            return None

        def isVersioned(self):
            return False

        def isCheckedOut(self):
            return False

        def isCheckedOutExclusive(self):
            return False

        def modifiedSinceCheckout(self):
            return False

        def canAddToRepository(self):
            return True

        def canCheckout(self):
            return False

        def canCheckin(self):
            return False

        def canMerge(self):
            return False

        def isHijacked(self):
            return False

        def isLatestVersion(self):
            pytest.fail("isLatestVersion should not be read for unversioned files")

        def getVersion(self):
            pytest.fail("getVersion should not be read for unversioned files")

        def getLatestVersion(self):
            pytest.fail("getLatestVersion should not be read for unversioned files")

    result = session.sync_utils._sync_status_from_domain_file(UnversionedDomainFile())

    assert result["is_versioned"] is False
    assert result["version"] is None
    assert result["latest_version"] is None
    assert result["is_latest_version"] is None
    assert result["can_add_to_repository"] is True


def test_get_sync_status_auto_connects_shared_repository(monkeypatch):
    handle = build_handle(monkeypatch)

    class DummyRepository:
        def __init__(self) -> None:
            self.connected = False
            self.connect_calls = 0

        def isConnected(self):
            return self.connected

        def connect(self):
            self.connect_calls += 1
            self.connected = True

    repository = DummyRepository()

    class SharedDomainFile:
        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _consumer):
            if repository.connected:
                return "ghidra://127.0.0.1:13100/shared"
            return None

        def isVersioned(self):
            return False

        def isCheckedOut(self):
            return False

        def isCheckedOutExclusive(self):
            return False

        def isLatestVersion(self):
            return True

        def modifiedSinceCheckout(self):
            return False

        def canAddToRepository(self):
            return repository.connected

        def canCheckout(self):
            return False

        def canCheckin(self):
            return False

        def canMerge(self):
            return False

        def isHijacked(self):
            return False

        def getVersion(self):
            return 1

        def getLatestVersion(self):
            return 0

    class SharedProjectData:
        def getFile(self, _domain_path):
            return SharedDomainFile()

        def getRepository(self):
            return repository

    class SharedProject(DummyProject):
        def __init__(self) -> None:
            super().__init__()
            self._project_data = SharedProjectData()
            self._project_ref = types.SimpleNamespace(getName=lambda: "DummyProject", getRepository=lambda: repository)

        def getProjectData(self):
            return self._project_data

    handle.project = SharedProject()
    monkeypatch.setattr(
        session.ProjectHandle,
        "is_repository_project_from_metadata",
        staticmethod(lambda *_args: True),
    )

    result = handle.get_sync_status("/folder/app")

    assert repository.connect_calls == 1
    assert result["is_versioned"] is False
    assert result["version"] is None
    assert result["latest_version"] is None
    assert result["is_latest_version"] is None
    assert result["can_add_to_repository"] is True
    assert result["shared_project_url"] == "ghidra://127.0.0.1:13100/shared"


def test_add_program_to_version_control_auto_connects_shared_repository(monkeypatch):
    handle = build_handle(monkeypatch)

    class DummyRepository:
        def __init__(self) -> None:
            self.connected = False
            self.connect_calls = 0

        def isConnected(self):
            return self.connected

        def connect(self):
            self.connect_calls += 1
            self.connected = True

    repository = DummyRepository()
    calls: list[tuple[str, bool, object]] = []

    class SharedDomainFile:
        def canAddToRepository(self):
            return repository.connected

        def addToVersionControl(self, comment, keep_checked_out, monitor):
            calls.append((comment, bool(keep_checked_out), monitor))

    class SharedProjectData:
        def getFile(self, _domain_path):
            return SharedDomainFile()

        def getRepository(self):
            return repository

    class SharedProject(DummyProject):
        def __init__(self) -> None:
            super().__init__()
            self._project_data = SharedProjectData()
            self._project_ref = types.SimpleNamespace(getName=lambda: "DummyProject", getRepository=lambda: repository)

        def getProjectData(self):
            return self._project_data

    handle.project = SharedProject()
    monkeypatch.setattr(
        session.ProjectHandle,
        "is_repository_project_from_metadata",
        staticmethod(lambda *_args: True),
    )
    monkeypatch.setattr(session.java_bindings, "_console_monitor", lambda: "monitor")

    handle.add_program_to_version_control("/folder/app", "Initial import", keep_checked_out=True)

    assert repository.connect_calls == 1
    assert calls == [("Initial import", True, "monitor")]


def test_refresh_project_data_invokes_project_data_refresh(monkeypatch):
    handle = build_handle(monkeypatch)
    calls: list[bool] = []

    class RefreshProjectData:
        def refresh(self, force):
            calls.append(bool(force))

    class RefreshProject(DummyProject):
        def __init__(self) -> None:
            super().__init__()
            self._project_data = RefreshProjectData()

        def getProjectData(self):
            return self._project_data

    handle.project = RefreshProject()
    monkeypatch.setattr(
        session.ProjectHandle,
        "is_repository_project_from_metadata",
        staticmethod(lambda *_args: False),
    )

    handle.refresh_project_data(force=True)

    assert calls == [True]


def test_list_programs_refreshes_project_data_before_sync_summary(monkeypatch):
    handle = build_handle(monkeypatch)

    class RefreshingDomainFile:
        def __init__(self, project_data) -> None:  # noqa: ANN001
            self._project_data = project_data

        def getContentType(self):
            return "Program"

        def getPathname(self):
            return "/external.bin"

        def getName(self):
            return "external.bin"

        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _):
            return None

        def isVersioned(self):
            return self._project_data.versioned

        def isCheckedOut(self):
            return False

        def isCheckedOutExclusive(self):
            return False

        def isLatestVersion(self):
            return True

        def modifiedSinceCheckout(self):
            return False

        def canAddToRepository(self):
            return not self._project_data.versioned

        def canCheckout(self):
            return self._project_data.versioned

        def canCheckin(self):
            return False

        def canMerge(self):
            return False

        def isHijacked(self):
            return False

        def getVersion(self):
            return 1

        def getLatestVersion(self):
            return 1

    class RefreshingFolder:
        def __init__(self, project_data) -> None:  # noqa: ANN001
            self._project_data = project_data

        def getFiles(self):
            return [RefreshingDomainFile(self._project_data)]

        def getFolders(self):
            return []

    class RefreshingProjectData:
        def __init__(self) -> None:
            self.refresh_calls: list[bool] = []
            self.versioned = False

        def refresh(self, force):
            self.refresh_calls.append(bool(force))
            self.versioned = True

        def getRootFolder(self):
            return RefreshingFolder(self)

    class RefreshingProject(DummyProject):
        def __init__(self) -> None:
            super().__init__()
            self._project_data = RefreshingProjectData()

        def getProjectData(self):
            return self._project_data

    project = RefreshingProject()
    handle.project = project
    monkeypatch.setattr(
        session.ProjectHandle,
        "is_repository_project_from_metadata",
        staticmethod(lambda *_args: False),
    )

    result = handle.list_programs()

    assert project._project_data.refresh_calls == [True]
    assert result[0]["is_versioned"] is True
    assert result[0]["can_add_to_repository"] is False


def test_list_programs_includes_sync_summary(monkeypatch):
    handle = build_handle(monkeypatch)

    class ListedDomainFile:
        def __init__(self, path: str, *, versioned: bool) -> None:
            self._path = path
            self._versioned = versioned

        def getContentType(self):
            return "Program"

        def getPathname(self):
            return self._path

        def getName(self):
            return pathlib.PurePosixPath(self._path).name

        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _):
            return None

        def isVersioned(self):
            return self._versioned

        def isCheckedOut(self):
            return False

        def isCheckedOutExclusive(self):
            return False

        def isLatestVersion(self):
            return True

        def modifiedSinceCheckout(self):
            return False

        def canAddToRepository(self):
            return not self._versioned

        def canCheckout(self):
            return self._versioned

        def canCheckin(self):
            return False

        def canMerge(self):
            return False

        def isHijacked(self):
            return False

        def getVersion(self):
            return 3

        def getLatestVersion(self):
            return 4

    class ListedFolder:
        def getFiles(self):
            return [
                ListedDomainFile("/versioned.bin", versioned=True),
                ListedDomainFile("/new.bin", versioned=False),
            ]

        def getFolders(self):
            return []

    class ListedProjectData:
        def getRootFolder(self):
            return ListedFolder()

    class ListedProject(DummyProject):
        def getProjectData(self):
            return ListedProjectData()

    handle.project = ListedProject()

    result = handle.list_programs()

    assert result == [
        {
            "domain_path": "/versioned.bin",
            "domain_name": "versioned.bin",
            "contentType": "Program",
            "is_versioned": True,
            "version": 3,
            "latest_version": 4,
            "is_latest_version": True,
            "can_add_to_repository": False,
            "sync_status_error": None,
        },
        {
            "domain_path": "/new.bin",
            "domain_name": "new.bin",
            "contentType": "Program",
            "is_versioned": False,
            "version": None,
            "latest_version": None,
            "is_latest_version": None,
            "can_add_to_repository": True,
            "sync_status_error": None,
        },
    ]


def test_list_programs_reports_sync_status_error(monkeypatch):
    handle = build_handle(monkeypatch)

    class BrokenDomainFile:
        def getContentType(self):
            return "Program"

        def getPathname(self):
            return "/broken.bin"

        def getName(self):
            return "broken.bin"

        def getCheckoutStatus(self):
            return None

        def getCheckouts(self):
            return []

        def getSharedProjectURL(self, _):
            return None

        def isVersioned(self):
            raise RuntimeError("backend unavailable")

    class ListedFolder:
        def getFiles(self):
            return [BrokenDomainFile()]

        def getFolders(self):
            return []

    class ListedProjectData:
        def getRootFolder(self):
            return ListedFolder()

    class ListedProject(DummyProject):
        def getProjectData(self):
            return ListedProjectData()

    handle.project = ListedProject()

    result = handle.list_programs()

    assert result == [
        {
            "domain_path": "/broken.bin",
            "domain_name": "broken.bin",
            "contentType": "Program",
            "is_versioned": None,
            "version": None,
            "latest_version": None,
            "is_latest_version": None,
            "can_add_to_repository": None,
            "sync_status_error": "SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.isVersioned: backend unavailable",
        }
    ]


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

    with pytest.raises(RuntimeError, match="Failed to remove program"):
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
    monkeypatch.setattr(session.java_bindings, "_program_diff_class", lambda: DummyProgramDiff)
    monkeypatch.setattr(session.java_bindings, "_program_diff_filter_class", lambda: DummyProgramDiffFilter)
    monkeypatch.setattr(session.java_bindings, "_console_monitor", lambda: None)
    consumers = []

    def fake_consumer():
        consumer = object()
        consumers.append(consumer)
        return consumer

    monkeypatch.setattr(session.java_bindings, "_java_object", fake_consumer)

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


def test_is_repository_project_from_metadata_detects_server_backed_project(tmp_path):
    rep_dir = tmp_path / "sample.rep"
    rep_dir.mkdir(parents=True)
    (rep_dir / "project.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="SERVER" TYPE="string" VALUE="127.0.0.1" />
    <STATE NAME="REPOSITORY_NAME" TYPE="string" VALUE="shared" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )

    assert session.ProjectHandle.is_repository_project_from_metadata(str(tmp_path), "sample") is True


def test_is_repository_project_from_metadata_is_false_for_local_project(tmp_path):
    rep_dir = tmp_path / "sample.rep"
    rep_dir.mkdir(parents=True)
    (rep_dir / "project.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
  <BASIC_INFO>
    <STATE NAME="OWNER" TYPE="string" VALUE="ghidra" />
  </BASIC_INFO>
</FILE_INFO>
""",
        encoding="utf-8",
    )

    assert session.ProjectHandle.is_repository_project_from_metadata(str(tmp_path), "sample") is False


def test_import_program_auto_uses_legacy_import_path(monkeypatch, tmp_path):
    handle = build_handle(monkeypatch)
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x90")
    imported_program = DummyProgram("/sample.bin")

    class DummyProjectData:
        def getFile(self, _domain_path):
            return None

    class ImportProject(DummyProject):
        def __init__(self) -> None:
            super().__init__()
            self.saved_as = None
            self.imported = []

        def getProjectData(self):
            return DummyProjectData()

        def importProgram(self, java_file):
            self.imported.append(java_file)
            return imported_program

        def saveAs(self, program, program_dir, program_name, overwrite):
            self.saved_as = (program, program_dir, program_name, overwrite)

    monkeypatch.setattr(session.project_handle.pycore, "JClass", lambda _name: lambda value: value)
    handle.project = ImportProject()

    domain_file = handle.import_program(str(binary_path))

    assert domain_file.getPathname() == "/sample.bin"
    assert handle.project.imported == [str(binary_path)]
    assert handle.project.saved_as == (imported_program, "/", "sample.bin", True)
    assert handle.project.closed == [imported_program]


def test_import_program_raw_binary_uses_binary_loader(monkeypatch, tmp_path):
    handle = build_handle(monkeypatch)
    binary_path = tmp_path / "shellcode.bin"
    binary_path.write_bytes(b"\x90\xc3")

    class DummyProjectData:
        def getFile(self, _domain_path):
            return None

    class RawImportProject(DummyProject):
        def getProjectData(self):
            return DummyProjectData()

    class FakeLoaded:
        def save(self, _monitor):
            return DummyDomainFile("/shellcode.bin")

    class FakeLoadResults:
        def __init__(self) -> None:
            self.closed = False

        def getPrimary(self):
            return FakeLoaded()

        def close(self):
            self.closed = True

    class FakeBuilder:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []
            self.load_results = FakeLoadResults()

        def project(self, value):
            self.calls.append(("project", value))
            return self

        def projectFolderPath(self, value):
            self.calls.append(("projectFolderPath", value))
            return self

        def source(self, value):
            self.calls.append(("source", value))
            return self

        def name(self, value):
            self.calls.append(("name", value))
            return self

        def loaders(self, value):
            self.calls.append(("loaders", value))
            return self

        def language(self, value):
            self.calls.append(("language", value))
            return self

        def compiler(self, value):
            self.calls.append(("compiler", value))
            return self

        def addLoaderArg(self, key, value):
            self.calls.append(("addLoaderArg", (key, value)))
            return self

        def load(self):
            self.calls.append(("load", None))
            return self.load_results

    fake_builder = FakeBuilder()
    monkeypatch.setattr(session.project_handle.pyghidra, "program_loader", lambda: fake_builder, raising=False)
    handle.project = RawImportProject()

    domain_file = handle.import_program(
        str(binary_path),
        import_mode="raw_binary",
        language_id="x86:LE:32:default",
        compiler_spec_id="gcc",
        base_address="0x401000",
        file_offset=4,
        length=16,
        block_name=".text",
        overlay=True,
        analyze_imported=False,
    )

    assert domain_file.getPathname() == "/shellcode.bin"
    assert fake_builder.calls == [
        ("project", handle.project.getProject()),
        ("projectFolderPath", "/"),
        ("source", str(binary_path)),
        ("name", "shellcode.bin"),
        ("loaders", "ghidra.app.util.opinion.BinaryLoader"),
        ("language", "x86:LE:32:default"),
        ("compiler", "gcc"),
        ("addLoaderArg", ("Base Address", "0x401000")),
        ("addLoaderArg", ("File Offset", "4")),
        ("addLoaderArg", ("Length", "16")),
        ("addLoaderArg", ("Block Name", ".text")),
        ("addLoaderArg", ("Overlay", "true")),
        ("load", None),
    ]
    assert fake_builder.load_results.closed is True


def test_post_process_imported_program_bootstraps_entry_and_analysis(monkeypatch):
    handle = build_handle(monkeypatch)
    created_flat_apis = []

    class DummyAddress:
        def __init__(self, offset: int) -> None:
            self._offset = offset

        def getOffset(self) -> int:
            return self._offset

    class DummyAddressSpace:
        def getAddress(self, offset: int):
            return DummyAddress(offset)

    class DummyAddressFactory:
        def getDefaultAddressSpace(self):
            return DummyAddressSpace()

    class DummyAddressSet:
        def getMinAddress(self):
            return DummyAddress(0x401000)

    class DummyMemory:
        def getLoadedAndInitializedAddressSet(self):
            return DummyAddressSet()

    class DummyListing:
        def __init__(self) -> None:
            self.instructions: dict[int, object] = {}

        def getInstructionAt(self, address):
            return self.instructions.get(address.getOffset())

    class DummyFunctionManager:
        def __init__(self) -> None:
            self.functions: dict[int, object] = {}

        def getFunctionAt(self, address):
            return self.functions.get(address.getOffset())

    class DummySymbolTable:
        def __init__(self) -> None:
            self.entry_points: set[int] = set()

        def isExternalEntryPoint(self, address):
            return address.getOffset() in self.entry_points

    class DummyImportedProgram:
        def __init__(self) -> None:
            self.listing = DummyListing()
            self.function_manager = DummyFunctionManager()
            self.symbol_table = DummySymbolTable()
            self.transactions: list[tuple[int, bool]] = []
            self._tx_id = 0

        def startTransaction(self, _description):
            self._tx_id += 1
            return self._tx_id

        def endTransaction(self, tx, commit):
            self.transactions.append((tx, commit))

        def getListing(self):
            return self.listing

        def getFunctionManager(self):
            return self.function_manager

        def getSymbolTable(self):
            return self.symbol_table

        def getMemory(self):
            return DummyMemory()

        def getAddressFactory(self):
            return DummyAddressFactory()

    class TrackingFlatAPI:
        def __init__(self, program, _monitor) -> None:
            self.program = program
            self.calls: list[tuple[str, int | None]] = []
            created_flat_apis.append(self)

        def disassemble(self, address):
            self.calls.append(("disassemble", address.getOffset()))
            self.program.listing.instructions[address.getOffset()] = object()
            return True

        def createFunction(self, address, _name):
            self.calls.append(("createFunction", address.getOffset()))
            self.program.function_manager.functions[address.getOffset()] = object()
            return object()

        def addEntryPoint(self, address):
            self.calls.append(("addEntryPoint", address.getOffset()))
            self.program.symbol_table.entry_points.add(address.getOffset())

        def analyzeAll(self, _program):
            self.calls.append(("analyzeAll", None))

    class DummyUtilities:
        def __init__(self) -> None:
            self.marked = []

        def shouldAskToAnalyze(self, _program):
            return True

        def markProgramAnalyzed(self, program):
            self.marked.append(program)

    class DummyScriptUtil:
        def __init__(self) -> None:
            self.calls = []

        def acquireBundleHostReference(self):
            self.calls.append("acquire")

        def releaseBundleHostReference(self):
            self.calls.append("release")

    imported_program = DummyImportedProgram()
    utilities = DummyUtilities()
    script_util = DummyScriptUtil()

    class PostProcessProject(DummyProject):
        def openProgram(self, domain_dir, domain_name, flag):  # noqa: ARG002
            assert (domain_dir, domain_name) == ("/", "shellcode.bin")
            return imported_program

    handle.project = PostProcessProject()
    monkeypatch.setattr(session.java_bindings, "_flat_program_api_class", lambda: TrackingFlatAPI)
    monkeypatch.setattr(session.java_bindings, "_ghidra_program_utilities", lambda: utilities)
    monkeypatch.setattr(session.java_bindings, "_ghidra_script_util", lambda: script_util)

    handle._post_process_imported_program_locked(
        "/shellcode.bin",
        entry_address=None,
        entry_offset=0,
        analyze_imported=True,
    )

    assert created_flat_apis[0].calls == [
        ("disassemble", 0x401000),
        ("createFunction", 0x401000),
        ("addEntryPoint", 0x401000),
        ("analyzeAll", None),
    ]
    assert utilities.marked == [imported_program]
    assert script_util.calls == ["acquire", "release"]
    assert imported_program.transactions == [(1, True)]
    assert handle.project.saved == [imported_program]
    assert handle.project.closed == [imported_program]
