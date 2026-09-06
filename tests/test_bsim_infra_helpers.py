from __future__ import annotations

import pytest

from ghidra_headless.handlers.commands.mutating_bsim import (
    _CATEGORY_NAME_RE,
    _metadata_value_text,
)
from ghidra_mcp.infrastructure.bsim.cli_runner import (
    mask_bsim_url,
    mask_bsim_urls_in_text,
)
from ghidra_mcp.infrastructure.bsim.java_backend import (
    _format_address,
    _iter_java_items,
    _load_executable_update_manager,
    _name_matches_exactly,
    _select_unique_executable_record,
)


def test_mask_bsim_url_masks_credentials():
    assert mask_bsim_url("postgresql://user:pw@host:5432/db") == "postgresql://***:***@host:5432/db"


def test_mask_bsim_url_preserves_ipv6_brackets():
    assert mask_bsim_url("postgresql://u:p@[::1]:5432/db") == "postgresql://***:***@[::1]:5432/db"


def test_mask_bsim_url_masks_credentials_on_invalid_port():
    assert mask_bsim_url("postgresql://user:pw@host:99999/db") == "postgresql://***:***@host:99999/db"


def test_mask_bsim_url_masks_query_credentials():
    assert (
        mask_bsim_url("postgresql://host/db?user=alice&password=topsecret&token=opaque&mode=ro")
        == "postgresql://host/db?user=***&password=***&token=***&mode=***"
    )


def test_mask_bsim_urls_in_exception_text_masks_userinfo_and_query_credentials():
    masked = mask_bsim_urls_in_text("failed for postgresql://alice:topsecret@host/db?password=second&mode=ro")

    assert masked == "failed for postgresql://***:***@host/db?password=***&mode=***"


@pytest.mark.parametrize("separator", [",", ";", ")("])
def test_mask_bsim_urls_in_text_masks_adjacent_urls(separator):
    masked = mask_bsim_urls_in_text(
        "failed for postgresql://host/one" + separator + "postgresql://alice:secondsecret@host/two"
    )

    assert masked == ("failed for postgresql://host/one" + separator + "postgresql://***:***@host/two")
    assert "secondsecret" not in masked


def test_mask_bsim_urls_in_text_does_not_split_scheme_like_password():
    masked = mask_bsim_urls_in_text("failed for postgresql://secret-user:foo://bar@host/db")

    assert masked == "failed for postgresql://***"
    assert "secret-user" not in masked
    assert "bar" not in masked


def test_mask_bsim_url_masks_all_query_values_and_fragment():
    masked = mask_bsim_url(
        "postgresql://host/db?sslpassword=TLSSECRET&auth_token=BEARER&"
        "credential=PRIVATE&pass%77ord=ENCODED&mode=ro#section"
    )

    assert masked == ("postgresql://host/db?sslpassword=***&auth_token=***&credential=***&pass%77ord=***&mode=***#***")


def test_mask_bsim_url_masks_oauth_style_fragment():
    masked = mask_bsim_url("postgresql://host/db#token=secret/OAuth")

    assert masked == "postgresql://host/db#***"
    assert "secret" not in masked


def test_mask_bsim_urls_in_text_masks_quote_inside_userinfo():
    masked = mask_bsim_urls_in_text("failed for postgresql://alice:top'secret@host/db while connecting")

    assert masked == "failed for postgresql://***:***@host/db while connecting"
    assert "secret" not in masked


@pytest.mark.parametrize("quote", ["'", '"'])
def test_mask_bsim_urls_in_text_preserves_wrapping_quote(quote):
    masked = mask_bsim_urls_in_text(f"failed for {quote}postgresql://user:pw@host/db{quote}, retrying")

    assert masked == (f"failed for {quote}postgresql://***:***@host/db{quote}, retrying")


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://alice:top?secret@host/db",
        "postgresql://alice:top/secret@host/db",
        "postgresql://alice:topsecret@host／evil/db?password=second",
    ],
)
def test_mask_bsim_url_fails_closed_for_malformed_userinfo(url):
    masked = mask_bsim_url(url)

    assert masked == "postgresql://***"
    assert "alice" not in masked
    assert "secret" not in masked


def test_mask_bsim_urls_in_text_fails_closed_for_malformed_userinfo():
    masked = mask_bsim_urls_in_text("connection failed: postgresql://alice:top?secret@host/db")

    assert masked == "connection failed: postgresql://***"


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


def test_iter_java_items_propagates_type_error_during_iteration():
    class PartiallyBrokenIterable:
        def __iter__(self):
            yield "first"
            raise TypeError("bridge failed during iteration")

    with pytest.raises(TypeError, match="bridge failed"):
        list(_iter_java_items(PartiallyBrokenIterable()))


def test_unique_executable_lookup_rejects_truncated_candidate_set():
    class Record:
        def __init__(self, name: str) -> None:
            self._name = name

        def getNameExec(self) -> str:
            return self._name

    records = [Record("target.exe"), *(Record(f"noise-{index}") for index in range(100))]

    with pytest.raises(RuntimeError, match="BSIM_EXECUTABLE_LOOKUP_TRUNCATED"):
        _select_unique_executable_record(records, name="target.exe")


def test_get_executable_rejects_truncated_candidate_set(monkeypatch):
    from ghidra_mcp.infrastructure.bsim.java_backend import BsimJavaBackend

    backend = BsimJavaBackend()
    observed: dict[str, int] = {}

    def list_executables(_bsim_url: str, **kwargs):
        observed["limit"] = int(kwargs["limit"])
        return {
            "items": [
                {"name": "target.exe"},
                *({"name": f"noise-{index}"} for index in range(100)),
            ],
            "truncated": True,
        }

    monkeypatch.setattr(backend, "list_executables", list_executables)

    with pytest.raises(RuntimeError, match="BSIM_EXECUTABLE_LOOKUP_TRUNCATED"):
        backend.get_executable("file:/tmp/bsim", name="target.exe")

    assert observed == {"limit": 101}


def test_metadata_update_loads_a_real_function_before_query_update():
    class Spec:
        transferred = None

        def transfer(self, record) -> None:  # noqa: ANN001
            self.transferred = record

    class QueryName:
        def __init__(self) -> None:
            self.spec = Spec()

    class Manager:
        def numFunctions(self) -> int:
            return 1

        def findExecutable(self, md5: str):
            assert md5 == "a" * 32
            return "fresh-record"

    class Response:
        uniqueexecutable = True
        manage = Manager()

    class Database:
        query_seen = None

        def query(self, query):  # noqa: ANN001
            self.query_seen = query
            return Response()

    class SourceRecord:
        def getMd5(self) -> str:
            return "a" * 32

    database = Database()
    source = SourceRecord()
    manager, record = _load_executable_update_manager(database, QueryName, source)

    assert manager is Response.manage
    assert record == "fresh-record"
    assert database.query_seen.spec.transferred is source
    assert database.query_seen.maxfunc == 1
    assert database.query_seen.fillinSigs is False
    assert database.query_seen.fillinCallgraph is False
    assert database.query_seen.fillinCategories is True


def test_metadata_update_rejects_empty_function_manager_before_ghidra_crash():
    class Spec:
        def transfer(self, _record) -> None:  # noqa: ANN001
            pass

    class QueryName:
        def __init__(self) -> None:
            self.spec = Spec()

    class Manager:
        def numFunctions(self) -> int:
            return 0

    class Response:
        uniqueexecutable = True
        manage = Manager()

    class Database:
        def query(self, _query):  # noqa: ANN001
            return Response()

    class SourceRecord:
        def getMd5(self) -> str:
            return "a" * 32

    with pytest.raises(RuntimeError, match="BSIM_EXECUTABLE_UPDATE_UNSUPPORTED"):
        _load_executable_update_manager(Database(), QueryName, SourceRecord())


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
