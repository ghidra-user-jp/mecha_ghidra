"""Shared sync status/version/diff helper functions."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ghidra_headless.errors import HeadlessError

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


def _required_call(obj, name: str, *args, owner: str = "DomainFile"):
    method = getattr(obj, name, None)
    if method is None:
        raise HeadlessError(f"SYNC_STATUS_UNAVAILABLE: {owner}.{name} is unavailable")
    try:
        return method(*args)
    except Exception as exc:
        raise HeadlessError(f"SYNC_STATUS_UNAVAILABLE: failed to call {owner}.{name}: {exc}") from exc


def _to_checkout_status_dict(status) -> Optional[Dict[str, Any]]:
    if status is None:
        return None
    checkout_id = _required_call(status, "getCheckoutId", owner="CheckoutStatus")
    if checkout_id is None:
        raise HeadlessError("SYNC_STATUS_UNAVAILABLE: CheckoutStatus.getCheckoutId returned None")
    checkout_type = _safe_call(status, "getCheckoutType")
    project_path = _safe_call(status, "getProjectPath")
    project_name = _safe_call(status, "getProjectName")
    project_location = _safe_call(status, "getProjectLocation")
    user_host_name = _safe_call(status, "getUserHostName")
    checkout_time = _safe_call(status, "getCheckoutTime")
    return {
        "checkout_id": checkout_id,
        "checkout_type": None if checkout_type is None else str(checkout_type),
        "user": _safe_call(status, "getUser"),
        "checkout_version": _safe_call(status, "getCheckoutVersion"),
        "checkout_time": checkout_time,
        "checkout_time_iso": _to_iso8601_utc(checkout_time),
        "project_path": None if project_path is None else str(project_path),
        "project_name": None if project_name is None else str(project_name),
        "project_location": None if project_location is None else str(project_location),
        "user_host_name": None if user_host_name is None else str(user_host_name),
    }


def _sync_status_from_domain_file(domain_file) -> Dict[str, Any]:
    shared_url = _safe_call(domain_file, "getSharedProjectURL", None)
    is_versioned = bool(_required_call(domain_file, "isVersioned"))

    if is_versioned:
        checkout_status = _to_checkout_status_dict(_required_call(domain_file, "getCheckoutStatus"))
        checkouts = _required_call(domain_file, "getCheckouts")
        checkouts_list = []
        if checkouts:
            for item in list(checkouts):
                converted = _to_checkout_status_dict(item)
                if converted is not None:
                    checkouts_list.append(converted)
        version = _required_call(domain_file, "getVersion")
        latest_version = _required_call(domain_file, "getLatestVersion")
        # GhidraFile.isLatestVersion() always returns true in Ghidra 12.1.2 and
        # 12.1.3, including for a stale checkout. Compare the actual versions.
        is_latest_version: bool | None = int(version) == int(latest_version)
        is_checked_out = bool(_required_call(domain_file, "isCheckedOut"))
        is_checked_out_exclusive = bool(_required_call(domain_file, "isCheckedOutExclusive"))
        if is_checked_out != (checkout_status is not None):
            raise HeadlessError(
                "SYNC_STATUS_UNAVAILABLE: DomainFile checkout state is inconsistent "
                "(isCheckedOut does not match getCheckoutStatus)"
            )
        if is_checked_out_exclusive and not is_checked_out:
            raise HeadlessError("SYNC_STATUS_UNAVAILABLE: exclusive checkout reported without an active checkout")
        modified_since_checkout = bool(_required_call(domain_file, "modifiedSinceCheckout"))
        can_checkout = bool(_required_call(domain_file, "canCheckout"))
        can_checkin = bool(_required_call(domain_file, "canCheckin"))
        can_merge = bool(_required_call(domain_file, "canMerge"))
    else:
        checkout_status = None
        checkouts_list = []
        is_latest_version = None
        version = None
        latest_version = None
        is_checked_out = False
        is_checked_out_exclusive = False
        modified_since_checkout = False
        can_checkout = False
        can_checkin = False
        can_merge = False

    # Ghidra defines a hijacked file as a private local file shadowing a
    # repository file, and deliberately reports isVersioned() == false for it.
    # Query this independently so callers can distinguish it from a private file.
    is_hijacked = bool(_required_call(domain_file, "isHijacked"))

    return {
        "is_versioned": is_versioned,
        "is_checked_out": is_checked_out,
        "is_checked_out_exclusive": is_checked_out_exclusive,
        "is_latest_version": is_latest_version,
        "modified_since_checkout": modified_since_checkout,
        "can_add_to_repository": bool(_required_call(domain_file, "canAddToRepository")),
        "can_checkout": can_checkout,
        "can_checkin": can_checkin,
        "can_merge": can_merge,
        "is_hijacked": is_hijacked,
        "version": version,
        "latest_version": latest_version,
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


def _collect_diff_details(
    from_program,
    to_program,
    ranges: list[Dict[str, Any]],
    *,
    limit: int,
) -> tuple[list[Dict[str, Any]], bool]:
    """Describe what differs at the start of each range (``ProgramDiffDetails``).

    Ghidra renders the details as the text its Diff tool shows: symbol, comment,
    code-unit and function changes at that address.  ``limit`` bounds the number
    of ranges described; the second value reports whether any were left out.
    """
    if limit <= 0 or not ranges:
        return [], bool(ranges) and limit <= 0
    details_class = java_bindings._program_diff_details_class()
    address_factory = from_program.getAddressFactory()
    details: list[Dict[str, Any]] = []
    for item in ranges[:limit]:
        start_text = str(item.get("start"))
        address = address_factory.getAddress(start_text)
        if address is None:
            details.append({"address": start_text, "details": None, "error": "address could not be resolved"})
            continue
        try:
            text = details_class.getDiffDetails(from_program, to_program, address)
        except Exception as exc:  # pragma: no cover - depends on Ghidra internals
            details.append({"address": start_text, "details": None, "error": str(exc)})
            continue
        details.append({"address": start_text, "details": None if text is None else str(text).rstrip()})
    return details, len(ranges) > limit


def _release_domain_object(domain_object, consumer) -> None:
    if domain_object is None:
        return
    try:
        domain_object.release(consumer)
    except Exception as exc:
        logger.warning("failed to release domain object: %s", exc)
