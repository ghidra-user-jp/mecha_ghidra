"""Normalization of client-supplied identifiers."""

from __future__ import annotations

import re
from uuid import UUID

_HEX = "[0-9a-fA-F]"
_UUID_TEXT = re.compile(rf"{_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}|{_HEX}{{32}}")


def canonical_uuid(value: object) -> str:
    """Return the canonical lowercase spelling of a UUID string.

    The usual spellings are accepted (hyphenated or 32 hex digits, any case,
    optional braces or ``urn:uuid:`` prefix). The looser forms ``uuid.UUID``
    tolerates (signs, whitespace, underscores, non-ASCII digits) are rejected
    so that distinct client strings never alias one identifier.
    """
    if not isinstance(value, str):
        raise ValueError("must be a UUID string")
    text = value[9:] if value[:9].lower() == "urn:uuid:" else value
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    if not _UUID_TEXT.fullmatch(text):
        raise ValueError("must be a UUID such as 81c4ef95-fced-4c07-89a5-d026ef55bdee")
    return str(UUID(text))


__all__ = ["canonical_uuid"]
