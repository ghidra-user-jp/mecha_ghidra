from __future__ import annotations

from ghidra_mcp.domain.error_utils import is_project_lock_error, safe_cause_details, sanitize_cause_message


def test_sanitize_cause_message_redacts_paths_and_truncates():
    posix = sanitize_cause_message("Unable to lock project /Users/alice/ghidra/proj.rep (locked)")
    assert "/Users/alice" not in posix
    assert posix.startswith("Unable to lock project <path>")

    windows = sanitize_cause_message("cannot open C:\\Users\\bob\\x.gpr: denied")
    assert "C:\\Users" not in windows
    assert "<path>" in windows

    unc = sanitize_cause_message("share \\\\server\\share\\proj.rep unavailable")
    assert "\\\\server" not in unc
    assert "<path>" in unc

    long_message = "x" * 1000
    assert len(sanitize_cause_message(long_message)) == 240
    assert sanitize_cause_message(long_message).endswith("...")


def test_sanitize_cause_message_keeps_urls():
    assert (
        sanitize_cause_message("connect to ghidra://host:13100/repo failed")
        == "connect to ghidra://host:13100/repo failed"
    )


def test_safe_cause_details_reports_type_and_redacted_message():
    class CustomError(Exception):
        pass

    details = safe_cause_details(CustomError("failed at /srv/secret/file"))
    assert details["cause_type"].endswith("CustomError")
    assert details["cause_message"] == "failed at <path>"

    empty = safe_cause_details(ValueError())
    assert empty["cause_type"] == "ValueError"
    assert empty["cause_message"] == "ValueError"


def test_is_project_lock_error_matches_lock_message_or_type():
    class LockException(Exception):
        pass

    assert is_project_lock_error(LockException("Unable to lock project /x"))
    assert is_project_lock_error(RuntimeError("Unable to lock project"))
    assert not is_project_lock_error(RuntimeError("something else"))
