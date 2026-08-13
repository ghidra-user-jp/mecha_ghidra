"""Helpers for masking credentials in BSim URLs."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_BSIM_URL_START_RE = r"[A-Za-z][A-Za-z0-9+.-]*:(?://|/)"
# Stop before another URL even when a backend concatenates values without
# whitespace (for example ``url1,url2``). A greedy token would parse the second
# URL as part of the first path and could return its userinfo unchanged.
_BSIM_URL_RE = re.compile(
    _BSIM_URL_START_RE
    + r"(?:(?![,;)(]"
    + _BSIM_URL_START_RE
    + r")[^\s<>])+"
)
_BSIM_QUERY_VALUE_RE = re.compile(r"(?P<prefix>(?:^|&)[^&=]*=)[^&]*")
_TRAILING_QUOTE_PUNCTUATION = frozenset(",.;:!?)]}")


def _mask_query_values(query: str) -> str:
    # Query parameters are not needed for diagnostics, and credential aliases can be
    # arbitrary or percent-encoded. Mask every value instead of maintaining a denylist.
    return _BSIM_QUERY_VALUE_RE.sub(r"\g<prefix>***", query)


def _mask_raw_url_query(text: str) -> str:
    fragment_start = text.find("#")
    fragment = "#***" if fragment_start >= 0 else ""
    url_without_fragment = text if fragment_start < 0 else text[:fragment_start]
    query_start = url_without_fragment.find("?")
    if query_start < 0:
        return url_without_fragment + fragment
    return (
        url_without_fragment[: query_start + 1]
        + _mask_query_values(url_without_fragment[query_start + 1 :])
        + fragment
    )


def _mask_url_token(text: str) -> str:
    scheme_match = re.match(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)", text)
    try:
        parts = urlsplit(text)
    except Exception:
        # A parser failure can quote the original authority, including its password.
        # Retain only the scheme so malformed input always fails closed.
        return f"{scheme_match.group('scheme')}***" if scheme_match else "***"

    _userinfo, separator, host_port = parts.netloc.rpartition("@")
    if not separator and scheme_match is not None and "@" in text[len(scheme_match.group(0)) :]:
        # Reserved characters such as an unescaped '/' or '?' can make urlsplit place
        # the tail of userinfo outside netloc. Do not try to reconstruct that malformed
        # URL because doing so risks returning the password verbatim.
        return f"{scheme_match.group('scheme')}***"

    if not separator:
        return _mask_raw_url_query(text)

    netloc = f"***:***@{host_port}" if separator else parts.netloc
    return urlunsplit(
        (
            parts.scheme,
            netloc,
            parts.path,
            _mask_query_values(parts.query),
            "***" if parts.fragment else "",
        )
    )


def mask_bsim_urls_in_text(message: str) -> str:
    """Mask BSim-style URLs embedded anywhere in an error or diagnostic message."""

    text = str(message)

    def mask_match(match: re.Match[str]) -> str:
        token = match.group(0)
        preceding = text[match.start() - 1] if match.start() else ""
        if preceding in {"'", '"'}:
            closing = token.rfind(preceding)
            if closing >= 0 and all(
                character in _TRAILING_QUOTE_PUNCTUATION
                for character in token[closing + 1 :]
            ):
                return _mask_url_token(token[:closing]) + token[closing:]
        return _mask_url_token(token)

    return _BSIM_URL_RE.sub(mask_match, text)


def mask_bsim_url(url: str | None) -> str | None:
    """Mask credentials embedded in a BSim URL."""

    if not url:
        return url
    text = str(url)
    return _mask_url_token(text)


__all__ = ["mask_bsim_url", "mask_bsim_urls_in_text"]
