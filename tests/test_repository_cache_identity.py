"""Existing shared caches must belong to the requested server repository."""

from xml.etree import ElementTree

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import ProjectHandle


def _write_cache(tmp_path, *, host="server.example", port="13100", repository="Corpus"):
    marker = tmp_path / "cache.gpr"
    marker.touch()
    rep = tmp_path / "cache.rep"
    rep.mkdir()
    tree = ElementTree.Element("FILE_INFO")
    info = ElementTree.SubElement(tree, "BASIC_INFO")
    values = {"SERVER": host, "REPOSITORY_NAME": repository}
    if port is not None:
        values["PORT_NUMBER"] = port
    for key, value in values.items():
        ElementTree.SubElement(info, "STATE", NAME=key, VALUE=value)
    metadata = rep / "project.prp"
    metadata.write_bytes(ElementTree.tostring(tree))
    return metadata


@pytest.mark.parametrize(
    "url",
    [
        "ghidra://other.example:13100/Corpus",
        "ghidra://server.example:15100/Corpus",
        "ghidra://other.example:15100/Corpus",
        "ghidra://server.example:13100/Other",
    ],
)
def test_cache_reuse_rejects_different_server_port_or_repository(tmp_path, url):
    metadata = _write_cache(tmp_path)
    before = metadata.read_bytes()

    with pytest.raises(HeadlessError, match="PROJECT_ALREADY_EXISTS"):
        ProjectHandle.create_repository_cache_project(str(tmp_path), "cache", repository_url=url)

    assert metadata.read_bytes() == before
    assert (tmp_path / "cache.gpr").exists()


@pytest.mark.parametrize("port", [None, "-1", "0", "13100"])
def test_cache_reuse_accepts_ghidra_default_port_spellings(tmp_path, port):
    _write_cache(tmp_path, port=port)

    result = ProjectHandle.create_repository_cache_project(
        str(tmp_path), "cache", repository_url="ghidra://server.example/Corpus"
    )

    assert result["status"] == "exists"
    assert result["repository_url"] == "ghidra://server.example:13100/Corpus"
    assert result["created"] is False


def test_cache_reuse_accepts_case_and_dns_root_dot_with_matching_custom_port(tmp_path):
    _write_cache(tmp_path, host="SERVER.EXAMPLE.", port="15100")

    result = ProjectHandle.create_repository_cache_project(
        str(tmp_path), "cache", repository_url="ghidra://server.example:15100/Corpus"
    )

    assert result["status"] == "exists"


def test_cache_reuse_does_not_treat_missing_port_as_any_port(tmp_path):
    _write_cache(tmp_path, port=None)

    with pytest.raises(HeadlessError, match="PROJECT_ALREADY_EXISTS"):
        ProjectHandle.create_repository_cache_project(
            str(tmp_path), "cache", repository_url="ghidra://server.example:15100/Corpus"
        )
