"""Helpers for managing Ghidra projects/programs via PyGhidra."""

from __future__ import annotations

import datetime as _dt
import logging
import pathlib
import threading
from typing import Any, Dict, Optional

import pyghidra.core as pycore

__all__ = ["ProgramSession", "ProjectHandle"]

logger = logging.getLogger(__name__)

_FLAT_API_CLASS = None
_CONSOLE_MONITOR_CLASS = None
_DEFAULT_CHECKIN_HANDLER_CLASS = None
_PROGRAM_DIFF_CLASS = None
_PROGRAM_DIFF_FILTER_CLASS = None
_JAVA_OBJECT_CLASS = None


def _flat_program_api_class():
    global _FLAT_API_CLASS
    if _FLAT_API_CLASS is None:
        _FLAT_API_CLASS = pycore.JClass("ghidra.program.flatapi.FlatProgramAPI")
    return _FLAT_API_CLASS


def _console_monitor():
    global _CONSOLE_MONITOR_CLASS
    if _CONSOLE_MONITOR_CLASS is None:
        _CONSOLE_MONITOR_CLASS = pycore.JClass("ghidra.util.task.ConsoleTaskMonitor")
    return _CONSOLE_MONITOR_CLASS()


def _default_checkin_handler_class():
    global _DEFAULT_CHECKIN_HANDLER_CLASS
    if _DEFAULT_CHECKIN_HANDLER_CLASS is None:
        _DEFAULT_CHECKIN_HANDLER_CLASS = pycore.JClass("ghidra.framework.data.DefaultCheckinHandler")
    return _DEFAULT_CHECKIN_HANDLER_CLASS


def _program_diff_class():
    global _PROGRAM_DIFF_CLASS
    if _PROGRAM_DIFF_CLASS is None:
        _PROGRAM_DIFF_CLASS = pycore.JClass("ghidra.program.util.ProgramDiff")
    return _PROGRAM_DIFF_CLASS


def _program_diff_filter_class():
    global _PROGRAM_DIFF_FILTER_CLASS
    if _PROGRAM_DIFF_FILTER_CLASS is None:
        _PROGRAM_DIFF_FILTER_CLASS = pycore.JClass("ghidra.program.util.ProgramDiffFilter")
    return _PROGRAM_DIFF_FILTER_CLASS


def _java_object():
    global _JAVA_OBJECT_CLASS
    if _JAVA_OBJECT_CLASS is None:
        _JAVA_OBJECT_CLASS = pycore.JClass("java.lang.Object")
    return _JAVA_OBJECT_CLASS()


class ProgramSession:
    """Represents an opened Ghidra program (binary or project backed)."""

    def __init__(
        self,
        flat_api,
        program,
        project_handle: "ProjectHandle",
    ) -> None:
        self.flat_api = flat_api
        self.program = program
        self.project_handle: Optional["ProjectHandle"] = project_handle

    def get_program(self):
        if self.program is None:
            raise RuntimeError("セッションはすでにクローズしています")
        return self.program

    def get_project_handle(self) -> "ProjectHandle":
        if self.project_handle is None:
            raise RuntimeError("セッションはすでにクローズしています")
        return self.project_handle

    def close(self, *, remove_program: bool = False) -> None:
        if self.project_handle is None:
            raise RuntimeError("セッションはすでにクローズしています")
        self.project_handle.release_program(self.program, remove_program=remove_program)

        self.project_handle = None
        self.flat_api = None
        self.program = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        project_name: Optional[str] = None
        project_location: Optional[str] = None
        dmain_path: Optional[str] = _domain_path(self.program)

        handle = self.get_project_handle()
        project_name = handle.get_project_name()
        project_location = handle.get_project_location()

        return {
            "project_name": project_name,
            "project_location": project_location,
            "domain_path": dmain_path
        }


class ProjectHandle:
    """Shared handle for a Ghidra project, allowing multiple program sessions."""

    def __init__(self, project_location: str, project_name: Optional[str]) -> None:
        self._lock = threading.RLock()
        self.project_location, self.project_name = self.resolve_project_location_and_file(project_location, project_name)
        self.key = self.make_key(project_location, project_name)
        self._open_programs: set[tuple[str, str]] = set()

        from ghidra.base.project import GhidraProject
        self.project = GhidraProject.openProject(self.project_location, self.project_name, True)
        self._refcount = 0
        self._closed = False

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        path = pathlib.Path(project_location).expanduser().resolve()
        if project_name is None and path.suffix.lower() != ".gpr":
            raise ValueError("project_location には .gpr のGhidraプロジェクトファイルを指定してください")
        if project_name is None and not path.is_file():
            raise ValueError(f"指定した .gpr ファイルが見つかりません: {path}")
        if project_name is None and path.is_dir():
            raise ValueError("project_name を指定してください")
        effective = project_name or path.stem
        return (str(path.parent if path.is_file() else path), effective)

    @staticmethod
    def make_key(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        return ProjectHandle.resolve_project_location_and_file(project_location, project_name)

    def get_project_location(self) -> str:
        return self.project_location

    def get_project_name(self) -> str:
        return self.project_name

    def get_key(self) -> tuple[str, str]:
        return self.key

    def open_program(self, domain_path: Optional[str] = None) -> ProgramSession:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトは既にクローズされています")
            monitor = _console_monitor()
            domain_dir, domain_name = _parse_domain_path(self.project, domain_path)
            domain_path_key = (domain_dir, domain_name)
            if domain_path_key in self._open_programs:
                raise RuntimeError(f"プログラムには既にセッションがあります: {domain_path_key}")
            program = self.project.openProgram(domain_dir, domain_name, False)
            if program is None:
                raise RuntimeError(f"プログラムを取得できませんでした: {domain_path}")
            flat_api = _flat_program_api_class()(program, monitor)
            self._refcount += 1
            self._open_programs.add(domain_path_key)
            return ProgramSession(flat_api, program, project_handle=self)

    def import_program(self, binary_path: str):
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトは既にクローズされています")
            path = pathlib.Path(binary_path)
            if not path.exists():
                raise ValueError(f"バイナリが存在しません: {binary_path}")
            program_dir = "/"
            program_name = path.name
            data = self.project.getProjectData()
            domain_file = data.getFile(program_dir + program_name)
            if domain_file is not None:
                raise RuntimeError(f"プログラムはすでに存在します: {domain_file.getPathname()}")
            program = None

            try:
                java_file = pycore.JClass("java.io.File")(str(path))
                program = self.project.importProgram(java_file)
                self.project.saveAs(program, program_dir, program_name, True)
                domain_file = program.getDomainFile()
            finally:
                if program is not None:
                    self.project.close(program)
            if domain_file is None:
                raise RuntimeError(f"プログラムの追加に失敗しました: {binary_path}")

            return domain_file

    def get_sync_status(self, domain_path: str) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            domain_file = self._get_domain_file_locked(domain_path)
            return _sync_status_from_domain_file(domain_file)

    def get_version_history(self, domain_path: str, *, limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            normalized_limit = int(limit)
            if normalized_limit < 1:
                raise ValueError("limit は1以上を指定してください")
            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(_required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: 共有プロジェクトのバージョン管理対象ではありません")
            versions = _get_version_history_entries(domain_file)
            versions.sort(key=lambda item: item["version"], reverse=True)
            current_version = int(_required_call(domain_file, "getVersion"))
            latest_version = int(_required_call(domain_file, "getLatestVersion"))
            return {
                "program": domain_path,
                "current_version": current_version,
                "latest_version": latest_version,
                "total_versions": len(versions),
                "versions": versions[:normalized_limit],
            }

    def get_version_diff(
        self,
        domain_path: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
    ) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            source_version = int(from_version)
            target_version = int(to_version)
            if source_version < 1 or target_version < 1:
                raise ValueError("from_version と to_version は1以上を指定してください")
            normalized_range_limit = int(range_limit)
            if normalized_range_limit < 0:
                raise ValueError("range_limit は0以上を指定してください")

            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(_required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: 共有プロジェクトのバージョン管理対象ではありません")

            versions = _get_version_history_entries(domain_file)
            known_versions = {item["version"] for item in versions}
            if source_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: from_version={source_version} が履歴にありません"
                )
            if target_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: to_version={target_version} が履歴にありません"
                )

            result = {
                "program": domain_path,
                "from_version": source_version,
                "to_version": target_version,
                "total_diff_addresses": 0,
                "total_diff_ranges": 0,
                "diff_types": [],
                "ranges": [],
                "ranges_truncated": False,
                "warnings": None,
            }
            if source_version == target_version:
                return result

            monitor = _console_monitor()
            from_consumer = _java_object()
            to_consumer = _java_object()
            from_program = None
            to_program = None
            try:
                from_program = domain_file.getReadOnlyDomainObject(from_consumer, source_version, monitor)
                to_program = domain_file.getReadOnlyDomainObject(to_consumer, target_version, monitor)
                if from_program is None or to_program is None:
                    raise RuntimeError(
                        f"VERSION_LOAD_FAILED: version {source_version} または {target_version} を開けませんでした"
                    )
                program_diff = _program_diff_class()(from_program, to_program)
                differences = program_diff.getDifferences(monitor)

                type_counts = _collect_diff_type_counts(program_diff, differences, monitor)
                ranges, truncated = _collect_diff_ranges(differences, limit=normalized_range_limit)
                warnings = program_diff.getWarnings()
                result.update(
                    {
                        "total_diff_addresses": int(differences.getNumAddresses()) if differences is not None else 0,
                        "total_diff_ranges": int(differences.getNumAddressRanges()) if differences is not None else 0,
                        "diff_types": type_counts,
                        "ranges": ranges,
                        "ranges_truncated": truncated,
                        "warnings": None if warnings is None else str(warnings),
                    }
                )
                return result
            finally:
                _release_domain_object(from_program, from_consumer)
                _release_domain_object(to_program, to_consumer)

    def checkout_program(self, domain_path: str, *, exclusive: bool = False) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = _console_monitor()
            return bool(domain_file.checkout(bool(exclusive), monitor))

    def add_program_to_version_control(
        self,
        domain_path: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            text = (comment or "").strip()
            if not text:
                raise ValueError("comment を指定してください")
            domain_file = self._get_domain_file_locked(domain_path)
            can_add = _safe_call(domain_file, "canAddToRepository")
            if can_add is False:
                raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControlできない状態です")
            monitor = _console_monitor()
            domain_file.addToVersionControl(text, bool(keep_checked_out), monitor)

    def commit_program(
        self,
        domain_path: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        create_keep_file: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            text = (message or "").strip()
            if not text:
                raise ValueError("message を指定してください")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = _console_monitor()
            handler = _default_checkin_handler_class()(text, bool(keep_checked_out), bool(create_keep_file))
            domain_file.checkin(handler, monitor)

    def merge_program(self, domain_path: str, *, ok_to_upgrade: bool = True) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = _console_monitor()
            domain_file.merge(bool(ok_to_upgrade), monitor)

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.undoCheckout(bool(keep))

    def terminate_checkout_program(self, domain_path: str, checkout_id: int) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.terminateCheckout(int(checkout_id))

    def release_program(self, program, *, remove_program: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            domain_path = _domain_path(program)
            if domain_path is None:
                raise RuntimeError("削除対象プログラムのパスを取得できません")
            domain_key = _parse_domain_path(self.project, domain_path)
            try:
                if program is not None:
                    self.project.save(program)
            except Exception as exc:
                logger.warning("program save failed before close: %s", exc)
            try:
                if program is not None:
                    self.project.close(program)
            except Exception as exc:
                logger.warning("program close failed: %s", exc)
            if remove_program:
                self._delete_program_locked(domain_path)
            self._open_programs.discard(domain_key)
            self._refcount = max(0, self._refcount - 1)
            if self._refcount == 0:
                self._close_project_locked()

    def list_programs(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("プロジェクトはクローズ済みです")
            results = []
            root = self.project.getProjectData().getRootFolder()
            _collect_program_files(root, results)
            return results

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        with self._lock:
            self._close_project_locked()

    # ------------------------------------------------------------------

    def _close_project_locked(self) -> None:
        if self._closed:
            return
        try:
            self.project.close()
        except Exception as exc:
            logger.warning("project close failed: %s", exc)
        self._open_programs.clear()
        self._closed = True

    def _delete_program_locked(self, domain_path: str) -> None:
        if self._closed:
            return
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"削除対象のプログラムが見つかりません: {domain_path}")
        try:
            domain_file.delete()
        except Exception as exc:
            raise RuntimeError(f"プログラム削除に失敗しました: {domain_path}: {exc}")

    def _get_domain_file_locked(self, domain_path: str):
        if not domain_path:
            raise ValueError("domain_path を指定してください")
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"プログラムが見つかりません: {domain_path}")
        return domain_file


# ----------------------------------------------------------------------
# helper functions


def _parse_domain_path(project, domain_path: Optional[str]):
    if not domain_path:
        domain_path = _find_first_program_path(project)
    if not domain_path:
        raise ValueError("プロジェクト内にプログラムが見つかりません")
    domain_file = pathlib.PurePosixPath(domain_path)
    return domain_file.parent.as_posix(), domain_file.name


def _find_first_program_path(project) -> Optional[str]:
    data = project.getProjectData()
    queue = [data.getRootFolder()]
    while queue:
        folder = queue.pop(0)
        for f in list(folder.getFiles()):
            if f.getContentType() == "Program":
                return f.getPathname()
        queue.extend(list(folder.getFolders()))
    return None


def _collect_program_files(folder, results):
    for domain_file in list(folder.getFiles()):
        if domain_file.getContentType() == "Program":
            results.append(
                {
                    "domain_path": domain_file.getPathname(),
                    "domain_name": domain_file.getName(),
                    "contentType": domain_file.getContentType(),
                }
            )
    for sub in list(folder.getFolders()):
        _collect_program_files(sub, results)


def _domain_path(program, domain_file=None) -> Optional[str]:
    if program is None:
        return None

    if domain_file is None:
        domain_file = program.getDomainFile()
    if domain_file is not None:
        return domain_file.getPathname()
    return None


def _safe_call(obj, name: str, *args):
    method = getattr(obj, name, None)
    if method is None:
        return None
    try:
        return method(*args)
    except Exception:
        return None


def _required_call(obj, name: str, *args):
    method = getattr(obj, name, None)
    if method is None:
        raise RuntimeError(f"SYNC_STATUS_UNAVAILABLE: DomainFile.{name} が利用できません")
    try:
        return method(*args)
    except Exception as exc:
        raise RuntimeError(f"SYNC_STATUS_UNAVAILABLE: DomainFile.{name} の取得に失敗しました: {exc}")


def _to_checkout_status_dict(status) -> Optional[Dict[str, Any]]:
    if status is None:
        return None
    checkout_type = _safe_call(status, "getCheckoutType")
    return {
        "checkout_id": _safe_call(status, "getCheckoutId"),
        "checkout_type": None if checkout_type is None else str(checkout_type),
        "user": _safe_call(status, "getUser"),
        "checkout_version": _safe_call(status, "getCheckoutVersion"),
        "checkout_time": _safe_call(status, "getCheckoutTime"),
    }


def _sync_status_from_domain_file(domain_file) -> Dict[str, Any]:
    checkout_status = _to_checkout_status_dict(_safe_call(domain_file, "getCheckoutStatus"))
    checkouts = _safe_call(domain_file, "getCheckouts")
    checkouts_list = []
    if checkouts:
        for item in list(checkouts):
            converted = _to_checkout_status_dict(item)
            if converted is not None:
                checkouts_list.append(converted)
    shared_url = _safe_call(domain_file, "getSharedProjectURL", None)

    return {
        "is_versioned": bool(_required_call(domain_file, "isVersioned")),
        "is_checked_out": bool(_required_call(domain_file, "isCheckedOut")),
        "is_checked_out_exclusive": bool(_required_call(domain_file, "isCheckedOutExclusive")),
        "is_latest_version": bool(_required_call(domain_file, "isLatestVersion")),
        "modified_since_checkout": bool(_required_call(domain_file, "modifiedSinceCheckout")),
        "can_add_to_repository": bool(_safe_call(domain_file, "canAddToRepository")),
        "can_checkout": bool(_required_call(domain_file, "canCheckout")),
        "can_checkin": bool(_required_call(domain_file, "canCheckin")),
        "can_merge": bool(_required_call(domain_file, "canMerge")),
        "is_hijacked": bool(_required_call(domain_file, "isHijacked")),
        "version": _required_call(domain_file, "getVersion"),
        "latest_version": _required_call(domain_file, "getLatestVersion"),
        "checkout_status": checkout_status,
        "checkouts": checkouts_list,
        "shared_project_url": None if shared_url is None else str(shared_url),
    }


def _get_version_history_entries(domain_file) -> list[Dict[str, Any]]:
    history = _required_call(domain_file, "getVersionHistory")
    if history is None:
        return []
    entries: list[Dict[str, Any]] = []
    for item in list(history):
        version_num = _safe_call(item, "getVersion")
        if version_num is None:
            continue
        timestamp = _safe_call(item, "getCreateTime")
        entries.append(
            {
                "version": int(version_num),
                "user": _safe_call(item, "getUser"),
                "comment": _safe_call(item, "getComment"),
                "create_time": timestamp,
                "create_time_iso": _to_iso8601_utc(timestamp),
            }
        )
    return entries


def _collect_diff_type_counts(program_diff, differences, monitor) -> list[Dict[str, Any]]:
    if differences is None:
        return []
    diff_filter = _program_diff_filter_class()()
    counts: list[Dict[str, Any]] = []
    for diff_type in list(diff_filter.getPrimaryTypes()):
        normalized_type = int(diff_type)
        type_diffs = program_diff.getTypeDiffs(normalized_type, differences, monitor)
        count = 0 if type_diffs is None else int(type_diffs.getNumAddresses())
        if count <= 0:
            continue
        counts.append(
            {
                "type": str(diff_filter.typeToName(normalized_type)),
                "count": count,
            }
        )
    counts.sort(key=lambda item: item["count"], reverse=True)
    return counts


def _collect_diff_ranges(differences, *, limit: int) -> tuple[list[Dict[str, Any]], bool]:
    if differences is None:
        return [], False
    total_ranges = int(differences.getNumAddressRanges())
    if limit == 0:
        return [], total_ranges > 0
    ranges: list[Dict[str, Any]] = []
    for idx, addr_range in enumerate(differences.getAddressRanges()):
        if idx >= limit:
            break
        ranges.append(
            {
                "start": str(addr_range.getMinAddress()),
                "end": str(addr_range.getMaxAddress()),
                "length": int(addr_range.getLength()),
            }
        )
    return ranges, total_ranges > len(ranges)


def _release_domain_object(domain_object, consumer) -> None:
    if domain_object is None:
        return
    try:
        domain_object.release(consumer)
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to release domain object: %s", exc)


def _to_iso8601_utc(timestamp_millis) -> Optional[str]:
    if timestamp_millis is None:
        return None
    try:
        timestamp = int(timestamp_millis) / 1000.0
    except Exception:  # noqa: BLE001
        return None
    try:
        return _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:  # noqa: BLE001
        return None
