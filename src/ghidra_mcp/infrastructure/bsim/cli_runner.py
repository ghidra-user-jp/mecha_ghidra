"""Compatibility re-export; masking helpers live in ``ghidra_mcp.domain.bsim_url_masking``."""

from ghidra_mcp.domain.bsim_url_masking import mask_bsim_url, mask_bsim_urls_in_text

__all__ = ["mask_bsim_url", "mask_bsim_urls_in_text"]
