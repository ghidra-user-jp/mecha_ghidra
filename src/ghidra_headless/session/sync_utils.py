"""Shared sync status/version/diff helper functions."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import java_bindings
from .path_utils import _to_iso8601_utc

logger = logging.getLogger(__name__)


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
        raise RuntimeError(f"SYNC_STATUS_UNAVAILABLE: DomainFile.{name} is unavailable")
    try:
        return method(*args)
    except Exception as exc:
        raise RuntimeError(f"SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.{name}: {exc}")


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
    diff_filter = java_bindings._program_diff_filter_class()()
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
