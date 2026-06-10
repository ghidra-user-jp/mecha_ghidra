from __future__ import annotations

import pytest

from ghidra_headless.handlers.commands.mutating_bsim import (
    _CATEGORY_NAME_RE,
    _metadata_value_text,
)
from ghidra_mcp.infrastructure.bsim.cli_runner import mask_bsim_url
from ghidra_mcp.infrastructure.bsim.java_backend import (
    _format_address,
    _name_matches_exactly,
)


def test_mask_bsim_url_masks_credentials():
    assert mask_bsim_url("postgresql://user:pw@host:5432/db") == "postgresql://***:***@host:5432/db"


def test_mask_bsim_url_preserves_ipv6_brackets():
    assert mask_bsim_url("postgresql://u:p@[::1]:5432/db") == "postgresql://***:***@[::1]:5432/db"


def test_mask_bsim_url_returns_original_on_invalid_port():
    # The masking helper must never raise; an unparseable port falls back to the input.
    assert mask_bsim_url("postgresql://user:pw@host:99999/db") == "postgresql://user:pw@host:99999/db"


def test_mask_bsim_url_passes_through_without_credentials():
    assert mask_bsim_url("postgresql://host:5432/db") == "postgresql://host:5432/db"
    assert mask_bsim_url(None) is None


def test_format_address_masks_signed_long():
    assert _format_address(0x401000) == "0x401000"
    assert _format_address(-1) == "0xffffffffffffffff"


def test_name_matches_exactly_rejects_substring():
    # Substring matches (the ILIKE behavior) must be rejected so a mutating update never
    # acts on a different record.
    assert _name_matches_exactly("openssl-1.1", name="ssl") is False
    assert _name_matches_exactly("openssl-1.1", name="openssl-1.1") is True


def test_name_matches_exactly_passes_when_no_name_filter():
    # md5-only lookups (including md5 prefixes) must not be filtered out by the name check.
    assert _name_matches_exactly("anything.bin", name=None) is True


def test_metadata_value_text_rejects_non_scalar_values():
    for bad in ([1, 2], (1,), {1}, frozenset({1}), {"a": 1}):
        with pytest.raises(ValueError, match="BSIM_TARGET_METADATA_INVALID"):
            _metadata_value_text(bad)


def test_metadata_value_text_stringifies_scalars():
    assert _metadata_value_text("  Emotet  ") == "Emotet"
    assert _metadata_value_text(42) == "42"


def test_category_name_regex_matches_expected_charset():
    assert _CATEGORY_NAME_RE.match("FAMILY") is not None
    assert _CATEGORY_NAME_RE.match("Threat Actor (TA)") is not None
    assert _CATEGORY_NAME_RE.match("bad$name") is None
