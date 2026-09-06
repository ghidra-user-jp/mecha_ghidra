"""Path and metadata parsing helpers for session/project operations."""

from __future__ import annotations

import datetime as _dt
import pathlib
import re
from typing import Dict, Optional

_MAX_PRP_METADATA_BYTES = 1024 * 1024
_STATE_TAG_RE = re.compile(r"<STATE\b[^>]*>", re.IGNORECASE)


def _extract_xml_attr(tag_text: str, attr_name: str) -> Optional[str]:
    pattern = rf"""\b{re.escape(attr_name)}\s*=\s*(['"])(.*?)\1"""
    match = re.search(pattern, tag_text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return match.group(2)


def _parse_domain_path(project, domain_path: Optional[str]):
    if not domain_path:
        domain_path = _find_first_program_path(project)
    if not domain_path:
        raise ValueError("No program found in the project")
    domain_file = pathlib.PurePosixPath(domain_path)
    if not domain_file.is_absolute():
        domain_file = pathlib.PurePosixPath("/") / domain_file
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
        raw = prp_path.read_bytes()
    except Exception:
        return None

    if not raw or len(raw) > _MAX_PRP_METADATA_BYTES:
        return None

    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return None

    text = raw.decode("utf-8", errors="replace")
    info: Dict[str, str] = {}
    for match in _STATE_TAG_RE.finditer(text):
        tag_text = match.group(0)
        key = _extract_xml_attr(tag_text, "NAME")
        if not key:
            continue
        value = _extract_xml_attr(tag_text, "VALUE")
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
    except Exception:
        return None
    try:
        return _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None
