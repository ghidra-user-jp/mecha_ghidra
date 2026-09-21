from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ghidra_mcp.application.services.script_catalog import (
    ORIGIN_BUNDLED,
    ORIGIN_OPERATOR,
    ScriptCatalog,
    discover_bundled_roots,
    parse_root_argument,
    parse_script_header,
)
from ghidra_mcp.domain import DomainError, ErrorCode

JAVA_SOURCE = """/* ###
 * IP: GHIDRA
 */
// Renames every function to have a prefix.
// Second description line.
// @category Examples.Rename
// @author Someone
// @importpackage com.example.helper
import ghidra.app.script.GhidraScript;

public class PrefixFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {}
}
"""

PYGHIDRA_SOURCE = """# Prints the program name.
# @category Examples
# @runtime PyGhidra
print(currentProgram.getName())
"""

JYTHON_SOURCE = """# Legacy script.
#@category Examples
#@runtime Jython
print currentProgram.getName()
"""

HEADERLESS_PY = """# No runtime header at all.
print("hi")
"""


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_header_parsing_matches_ghidra_conventions():
    header = parse_script_header(JAVA_SOURCE, comment_prefix="//")
    assert header.description == "Renames every function to have a prefix. Second description line."
    assert header.category == "Examples.Rename"
    assert header.author == "Someone"
    assert header.runtime is None
    assert header.import_packages == ("com.example.helper",)

    py = parse_script_header(PYGHIDRA_SOURCE, comment_prefix="#")
    assert py.runtime == "PyGhidra"
    assert py.category == "Examples"

    jy = parse_script_header(JYTHON_SOURCE, comment_prefix="#")
    assert jy.runtime == "Jython"

    weird = parse_script_header("# @runtime IronPython\n", comment_prefix="#")
    assert weird.runtime == "IronPython"


def test_parse_root_argument_accepts_label_and_plain_directory(tmp_path):
    label, path = parse_root_argument(f"team={tmp_path}")
    assert label == "team"
    assert path == tmp_path
    label, path = parse_root_argument(str(tmp_path))
    assert label is None
    assert path == tmp_path
    with pytest.raises(ValueError):
        parse_root_argument("   ")


def test_catalog_default_labels_normalize_leading_punctuation_and_resolve_collisions(tmp_path):
    roots = []
    for name in ("scripts", "_scripts", ".scripts", "___", "._-", "kept_"):
        root = tmp_path / name
        _write(root, "Hello.py", PYGHIDRA_SOURCE)
        roots.append(str(root))
    # Run startup in a subprocess so a regression fails within the deadline,
    # rather than hanging the whole test suite in the label-generation loop.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, sys; from pathlib import Path; "
            "from ghidra_mcp.application.services.script_catalog import ScriptCatalog, ORIGIN_OPERATOR; "
            "catalog = ScriptCatalog(snapshot_base=Path(sys.argv[1])); "
            "catalog.build([(None, Path(root), ORIGIN_OPERATOR) for root in sys.argv[2:]]); "
            "print(json.dumps(list(catalog.roots)))",
            str(tmp_path / "snap"),
            *roots,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == ["scripts", "scripts-2", "scripts-3", "root", "root-2", "kept_"]


def _build_catalog(tmp_path: Path) -> tuple[ScriptCatalog, Path]:
    source = tmp_path / "scripts"
    _write(source, "PrefixFunctions.java", JAVA_SOURCE)
    _write(source, "Print.py", PYGHIDRA_SOURCE)
    _write(source, "Legacy.py", JYTHON_SOURCE)
    _write(source, "NoHeader.py", HEADERLESS_PY)
    _write(source, "notes.txt", "ignored")
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("team", source, ORIGIN_OPERATOR)])
    return catalog, source


def test_catalog_snapshots_roots_and_indexes_scripts(tmp_path):
    catalog, source = _build_catalog(tmp_path)
    entries = {entry.script_id: entry for entry in catalog.list_entries()}
    assert set(entries) == {
        "team:PrefixFunctions.java",
        "team:Print.py",
        "team:Legacy.py",
        "team:NoHeader.py",
    }
    java = entries["team:PrefixFunctions.java"]
    assert java.runtime == "Java"
    assert java.available is True
    assert java.category == "Examples.Rename"
    assert java.path.is_relative_to(tmp_path / "snap")
    assert not java.path.is_relative_to(source)
    assert "sha256" not in java.to_detail()

    assert entries["team:Print.py"].runtime == "PyGhidra"
    assert entries["team:Legacy.py"].runtime == "Jython"
    no_header = entries["team:NoHeader.py"]
    assert no_header.runtime is None
    assert no_header.available is False
    assert no_header.unavailable_reason == "runtime_ambiguous"
    assert catalog.revision
    # The snapshot directory is private to the process owner.
    assert (os.stat(tmp_path / "snap").st_mode & 0o077) == 0


def test_resolve_by_bare_name_and_ambiguity(tmp_path):
    source_a = tmp_path / "a"
    source_b = tmp_path / "b"
    _write(source_a, "Dup.java", JAVA_SOURCE)
    _write(source_b, "Dup.java", JAVA_SOURCE)
    _write(source_a, "Only.java", JAVA_SOURCE)
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("a", source_a, ORIGIN_OPERATOR), ("b", source_b, ORIGIN_OPERATOR)])

    assert catalog.resolve("Only").script_id == "a:Only.java"
    assert catalog.resolve("Only.java").script_id == "a:Only.java"
    assert catalog.resolve("b:Dup.java").root_label == "b"
    with pytest.raises(DomainError) as ambiguous:
        catalog.resolve("Dup")
    assert ambiguous.value.code == ErrorCode.AMBIGUOUS_SCRIPT
    assert ambiguous.value.details["candidates"] == ["a:Dup.java", "b:Dup.java"]
    with pytest.raises(DomainError) as missing:
        catalog.resolve("Nope.java")
    assert missing.value.code == ErrorCode.SCRIPT_NOT_FOUND
    with pytest.raises(DomainError) as missing_qualified:
        catalog.resolve("a:Nope.java")
    assert missing_qualified.value.code == ErrorCode.SCRIPT_NOT_FOUND


def test_operator_edits_after_startup_do_not_affect_the_snapshot(tmp_path):
    catalog, source = _build_catalog(tmp_path)
    (source / "PrefixFunctions.java").write_text("// tampered\n", encoding="utf-8")
    entry = catalog.get("team:PrefixFunctions.java")
    assert entry.path.read_text(encoding="utf-8") == JAVA_SOURCE


def test_runtime_availability_marks_entries(tmp_path):
    catalog, _ = _build_catalog(tmp_path)
    catalog.set_runtime_availability({"Java": True, "PyGhidra": True, "Jython": False})
    legacy = catalog.get("team:Legacy.py")
    assert legacy.available is False
    assert legacy.unavailable_reason == "runtime_unavailable:Jython"
    catalog.set_runtime_availability({"Jython": True})
    assert catalog.get("team:Legacy.py").available is True


def test_bundled_entries_are_filtered_unless_requested(tmp_path):
    source = tmp_path / "team"
    _write(source, "A.java", JAVA_SOURCE)
    fake_install = tmp_path / "ghidra"
    _write(fake_install, "Ghidra/Features/Base/ghidra_scripts/Bundled.java", JAVA_SOURCE)
    _write(fake_install, "Ghidra/Features/Base/lib/Base.jar", "")
    roots = discover_bundled_roots(fake_install)
    assert roots == [("bundled-Base", fake_install / "Ghidra/Features/Base/ghidra_scripts")]
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("team", source, ORIGIN_OPERATOR), *[(label, path, ORIGIN_BUNDLED) for label, path in roots]])
    assert {e.script_id for e in catalog.list_entries()} == {"team:A.java"}
    assert {e.script_id for e in catalog.list_entries(include_bundled=True)} == {
        "team:A.java",
        "bundled-Base:Bundled.java",
    }
    assert [e.script_id for e in catalog.list_entries(include_bundled=True, origin="bundled")] == [
        "bundled-Base:Bundled.java"
    ]


def test_root_with_manifest_is_indexed_and_copied(tmp_path):
    source = tmp_path / "scripts"
    _write(source, "A.java", JAVA_SOURCE)
    _write(source, "META-INF/MANIFEST.MF", "Bundle-SymbolicName: x\n")
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("team", source, ORIGIN_OPERATOR)])
    assert [entry.script_id for entry in catalog.list_entries()] == ["team:A.java"]
    assert (catalog.roots["team"].snapshot_dir / "META-INF/MANIFEST.MF").read_text() == "Bundle-SymbolicName: x\n"


def test_build_rejects_bad_configuration(tmp_path):
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap", max_files_per_root=1)
    source = tmp_path / "scripts"
    _write(source, "A.java", JAVA_SOURCE)
    _write(source, "B.java", JAVA_SOURCE)
    with pytest.raises(ValueError, match="limit"):
        catalog.build([("team", source, ORIGIN_OPERATOR)])
    with pytest.raises(ValueError, match="not a directory"):
        ScriptCatalog(snapshot_base=tmp_path / "snap2").build([("team", tmp_path / "missing", ORIGIN_OPERATOR)])
    with pytest.raises(ValueError, match="duplicate"):
        ScriptCatalog(snapshot_base=tmp_path / "snap3").build(
            [("team", source, ORIGIN_OPERATOR), ("team", source, ORIGIN_OPERATOR)]
        )


# ---- header parsing like ScriptInfo.parseHeader (fix 3) ----------------------


def test_header_blank_lines_between_comment_sections_are_skipped():
    header = parse_script_header("# Description\n\n# @runtime PyGhidra\n", comment_prefix="#")
    assert header.runtime == "PyGhidra"
    assert header.description == "Description"


def test_header_skips_python_certification_block():
    text = "## ###\n# IP: GHIDRA\n##\n# Finds things\n# @category Examples\n"
    header = parse_script_header(text, comment_prefix="#")
    assert header.description == "Finds things"
    assert header.category == "Examples"
    assert "###" not in (header.description or "")
    assert "IP: GHIDRA" not in (header.description or "")


def test_header_skips_java_certification_block():
    text = "/* ###\n * IP: GHIDRA\n */\n// My script\n// @category Test\npublic class X extends GhidraScript {}"
    header = parse_script_header(text, comment_prefix="//")
    assert header.description == "My script"
    assert header.category == "Test"


def test_header_skips_python_block_comments_and_stops_at_code():
    text = "'''\nlicense text\n'''\n# Real description\n# @runtime Jython\nimport os\n# @category NotAHeader\n"
    header = parse_script_header(text, comment_prefix="#")
    assert header.description == "Real description"
    assert header.runtime == "Jython"
    assert header.category is None


# ---- symlinks in script roots (fix 5) ---------------------------------------


def test_snapshot_copies_file_symlinks_but_not_directory_symlinks_or_dangling_links(tmp_path):
    source = tmp_path / "scripts"
    _write(source, "Top.java", JAVA_SOURCE)
    elsewhere = tmp_path / "elsewhere"
    _write(elsewhere, "Linked.py", PYGHIDRA_SOURCE)
    _write(elsewhere, "Inner.java", JAVA_SOURCE)
    (source / "LinkedFile.py").symlink_to(elsewhere / "Linked.py")
    (source / "linked_dir").symlink_to(elsewhere, target_is_directory=True)
    (source / "loop").symlink_to(source, target_is_directory=True)
    (source / "Dangling.py").symlink_to(tmp_path / "missing.py")
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("team", source, ORIGIN_OPERATOR)])
    assert catalog.roots["team"].file_count == 2
    assert {p.name for p in catalog.roots["team"].snapshot_dir.iterdir()} == {"Top.java", "LinkedFile.py"}
    linked = catalog.get("team:LinkedFile.py")
    assert linked is not None and linked.runtime == "PyGhidra"
    assert not linked.path.is_symlink()
    assert not (tmp_path / "snap" / "team" / "linked_dir").exists()
    assert not (tmp_path / "snap" / "team" / "loop").exists()
    assert not (tmp_path / "snap" / "team" / "Dangling.py").is_symlink()


def test_snapshot_copy_failure_is_a_loud_configuration_error(tmp_path, monkeypatch):
    source = tmp_path / "scripts"
    _write(source, "Top.java", JAVA_SOURCE)

    def failing_copytree(*_args, **_kwargs):
        raise shutil.Error([("a", "b", "permission denied")])

    monkeypatch.setattr(shutil, "copytree", failing_copytree)
    with pytest.raises(ValueError, match="script root team could not be snapshotted"):
        ScriptCatalog(snapshot_base=tmp_path / "snap").build([("team", source, ORIGIN_OPERATOR)])


# ---- nested files (fix 6) ----------------------------------------------------


def test_nested_files_are_copied_for_children_but_not_indexed(tmp_path):
    source = tmp_path / "scripts"
    _write(source, "Top.java", JAVA_SOURCE)
    _write(source, "sub/Nested.java", JAVA_SOURCE)
    _write(source, "sub/Helper.py", PYGHIDRA_SOURCE)
    catalog = ScriptCatalog(snapshot_base=tmp_path / "snap")
    catalog.build([("team", source, ORIGIN_OPERATOR)])
    assert {entry.script_id for entry in catalog.list_entries()} == {"team:Top.java"}
    snapshot = catalog.roots["team"].snapshot_dir
    assert catalog.roots["team"].file_count == 3
    assert (snapshot / "sub" / "Nested.java").read_text(encoding="utf-8") == JAVA_SOURCE
    assert (snapshot / "sub" / "Helper.py").read_text(encoding="utf-8") == PYGHIDRA_SOURCE
    with pytest.raises(DomainError) as missing:
        catalog.resolve("team:sub/Nested.java")
    assert missing.value.code == ErrorCode.SCRIPT_NOT_FOUND
    with pytest.raises(DomainError) as bare:
        catalog.resolve("Nested")
    assert bare.value.code == ErrorCode.SCRIPT_NOT_FOUND
    (source / "sub" / "Helper.py").write_text("# changed\n", encoding="utf-8")
    assert (snapshot / "sub" / "Helper.py").read_text(encoding="utf-8") == PYGHIDRA_SOURCE


# ---- reserved labels (fix 7) -------------------------------------------------


@pytest.mark.parametrize("label", ["inline", "probe", "Inline", "PROBE"])
def test_reserved_root_labels_are_rejected(tmp_path, label):
    source = tmp_path / "scripts"
    _write(source, "Top.java", JAVA_SOURCE)
    with pytest.raises(ValueError, match="reserved"):
        parse_root_argument(f"{label}={source}")
    with pytest.raises(ValueError, match="reserved") as exc:
        ScriptCatalog(snapshot_base=tmp_path / "snap").build([(label, source, ORIGIN_OPERATOR)])
    assert "inline" in str(exc.value) and "probe" in str(exc.value)
    assert not (tmp_path / "snap" / label).exists()
