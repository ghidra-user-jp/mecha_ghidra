"""Shared defense-in-depth validation for paginated headless commands."""

from __future__ import absolute_import, print_function


MAX_PAGE_OFFSET = 1000000
MAX_PAGE_LIMIT = 10000


def normalize_pagination(params, to_int, default_limit):
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), default_limit)
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if offset > MAX_PAGE_OFFSET:
        raise ValueError("offset must be <= %d" % MAX_PAGE_OFFSET)
    if limit < 1:
        raise ValueError("limit must be >= 1")
    if limit > MAX_PAGE_LIMIT:
        raise ValueError("limit must be <= %d" % MAX_PAGE_LIMIT)
    return offset, limit


def normalize_limit(params, to_int, default_limit):
    _, limit = normalize_pagination(
        {"offset": 0, "limit": params.get("limit")},
        to_int,
        default_limit,
    )
    return limit


__all__ = [
    "MAX_PAGE_LIMIT",
    "MAX_PAGE_OFFSET",
    "normalize_limit",
    "normalize_pagination",
]
