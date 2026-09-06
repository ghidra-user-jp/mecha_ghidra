from __future__ import annotations

import pytest

from ghidra_headless.session import path_utils


def _prp(*states: tuple[str, str]) -> bytes:
    body = "".join(f'  <STATE NAME="{name}" TYPE="string" VALUE="{value}" />\n' for name, value in states)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<FILE_INFO>\n{body}</FILE_INFO>\n'.encode()


def test_well_formed_prp_is_parsed(tmp_path):
    prp = tmp_path / "prog.prp"
    prp.write_bytes(_prp(("NAME", "prog"), ("CONTENT_TYPE", "Program"), ("PARENT", "/folder")))

    info = path_utils._read_prp_basic_info(prp)

    assert info == {"NAME": "prog", "CONTENT_TYPE": "Program", "PARENT": "/folder"}


@pytest.mark.parametrize("marker", [b"<!DOCTYPE foo>", b"<!doctype foo>", b"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"])
def test_prp_with_doctype_or_entity_is_rejected_case_insensitively(tmp_path, marker):
    prp = tmp_path / "prog.prp"
    prp.write_bytes(marker + _prp(("NAME", "prog"), ("CONTENT_TYPE", "Program")))
    assert path_utils._read_prp_basic_info(prp) is None


def test_prp_size_limit_is_enforced_at_the_boundary(tmp_path):
    prp = tmp_path / "prog.prp"
    payload = _prp(("NAME", "prog"), ("CONTENT_TYPE", "Program"))
    padding = b" " * (path_utils._MAX_PRP_METADATA_BYTES - len(payload))
    prp.write_bytes(payload + padding)
    assert path_utils._read_prp_basic_info(prp) is not None

    prp.write_bytes(payload + padding + b" ")
    assert path_utils._read_prp_basic_info(prp) is None


def test_unreadable_or_empty_prp_returns_none(tmp_path):
    assert path_utils._read_prp_basic_info(tmp_path / "missing.prp") is None
    empty = tmp_path / "empty.prp"
    empty.write_bytes(b"")
    assert path_utils._read_prp_basic_info(empty) is None


def test_collect_program_files_from_idata_dedupes_and_sorts(tmp_path):
    idata = tmp_path / "idata"
    (idata / "a").mkdir(parents=True)
    (idata / "b").mkdir()
    (idata / "a" / "x.prp").write_bytes(_prp(("NAME", "zeta"), ("CONTENT_TYPE", "Program"), ("PARENT", "sub")))
    (idata / "b" / "y.prp").write_bytes(_prp(("NAME", "alpha"), ("CONTENT_TYPE", "Program")))
    (idata / "b" / "dup.prp").write_bytes(_prp(("NAME", "alpha"), ("CONTENT_TYPE", "Program")))
    (idata / "b" / "folder.prp").write_bytes(_prp(("NAME", "notes"), ("CONTENT_TYPE", "Folder")))

    programs = path_utils._collect_program_files_from_idata(idata)

    assert [item["domain_path"] for item in programs] == ["/alpha", "/sub/zeta"]
    assert all(item["contentType"] == "Program" for item in programs)


def test_parse_domain_path_normalizes_relative_paths():
    assert path_utils._parse_domain_path(None, "folder/prog") == ("/folder", "prog")
    assert path_utils._parse_domain_path(None, "/prog") == ("/", "prog")
