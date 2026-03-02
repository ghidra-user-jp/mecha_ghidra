"""Path and metadata parsing helpers for session/project operations."""

from __future__ import annotations

import datetime as _dt
import pathlib
import xml.etree.ElementTree as _et
from typing import Dict, Optional


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
        for file_item in list(folder.getFiles()):
            if file_item.getContentType() == "Program":
                return file_item.getPathname()
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


def _collect_program_files_from_idata(idata_dir: pathlib.Path) -> list[Dict[str, str]]:
    programs: list[Dict[str, str]] = []
    seen_paths: set[str] = set()

    for prp_path in sorted(idata_dir.rglob("*.prp")):
        info = _read_prp_basic_info(prp_path)
        if not info:
            continue
        if str(info.get("CONTENT_TYPE") or "") != "Program":
            continue

        name = info.get("NAME")
        if not name:
            continue

        parent = str(info.get("PARENT") or "/")
        parent_path = pathlib.PurePosixPath(parent)
        if not parent_path.is_absolute():
            parent_path = pathlib.PurePosixPath("/") / parent_path

        domain_path = (parent_path / name).as_posix()
        if not domain_path.startswith("/"):
            domain_path = "/" + domain_path
        if domain_path in seen_paths:
            continue
        seen_paths.add(domain_path)

        programs.append(
            {
                "domain_path": domain_path,
                "domain_name": str(name),
                "contentType": "Program",
            }
        )

    programs.sort(key=lambda item: item["domain_path"])
    return programs


def _read_prp_basic_info(prp_path: pathlib.Path) -> Optional[Dict[str, str]]:
    try:
        root = _et.parse(str(prp_path)).getroot()
    except Exception:
        return None

    info: Dict[str, str] = {}
    for state in root.findall(".//STATE"):
        key = state.attrib.get("NAME")
        if not key:
            continue
        value = state.attrib.get("VALUE")
        if value is None:
            continue
        info[str(key)] = str(value)
    return info or None


def _domain_path(program, domain_file=None) -> Optional[str]:
    if program is None:
        return None

    if domain_file is None:
        domain_file = program.getDomainFile()
    if domain_file is not None:
        return domain_file.getPathname()
    return None


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

