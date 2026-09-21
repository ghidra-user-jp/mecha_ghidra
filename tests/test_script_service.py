from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ghidra_mcp.application.services.script_service import ScriptConfig, ScriptService
from ghidra_mcp.domain import DomainError, ErrorCode

JAVA = "// Demo script.\n// @category Demo\nimport ghidra.app.script.GhidraScript;\npublic class Demo extends GhidraScript { public void run() {} }\n"
PYGHIDRA = "# @runtime PyGhidra\nprint('x')\n"
HEADERLESS = "print('x')\n"
JYTHON = "# @runtime Jython\nprint 'x'\n"


class FakeRuntime:
    def __init__(self, availability: dict[str, bool] | None = None) -> None:
        self.availability = availability or {"Java": True, "PyGhidra": True, "Jython": False}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def script_runtime_availability(self) -> dict[str, bool]:
        return dict(self.availability)

    def run_script(self, name: str, *, request: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("run", name, request))
        return {"status": "ok", "transaction_outcome": "committed"}

    def project_lock_key(self, name: str) -> str | None:
        return None


def _roots(tmp_path: Path) -> Path:
    root = tmp_path / "scripts"
    root.mkdir()
    (root / "Demo.java").write_text(JAVA, encoding="utf-8")
    (root / "Hello.py").write_text(PYGHIDRA, encoding="utf-8")
    (root / "NoHeader.py").write_text(HEADERLESS, encoding="utf-8")
    (root / "Old.py").write_text(JYTHON, encoding="utf-8")
    return root


def _service(tmp_path: Path, runtime: FakeRuntime | None = None, **overrides) -> tuple[ScriptService, FakeRuntime]:
    runtime = runtime or FakeRuntime()
    config = ScriptConfig(
        roots=(("team", _roots(tmp_path)),),
        snapshot_base=tmp_path / "snap",
        **overrides,
    )
    service = ScriptService(runtime, config=config)
    service.initialize()
    return service, runtime


def test_disabled_service_refuses_everything_with_scripts_disabled(tmp_path):
    """Before initialize() (scripts category not exposed) every tool answers SCRIPTS_DISABLED."""
    service = ScriptService(FakeRuntime(), config=ScriptConfig())
    for call in (
        lambda: service.list_scripts(),
        lambda: service.get_script_info("x"),
    ):
        with pytest.raises(DomainError) as exc:
            call()
        assert exc.value.code == ErrorCode.SCRIPTS_DISABLED
    with pytest.raises(DomainError) as run_exc:
        service.run_script("fw", "x")
    assert run_exc.value.code == ErrorCode.SCRIPTS_DISABLED


JAVA_INLINE = """import ghidra.app.script.GhidraScript;
public class InlinePlate extends GhidraScript { public void run() { println("hi"); } }
"""


def test_failed_catalog_initialization_removes_partial_snapshot(tmp_path):
    root = tmp_path / "scripts"
    root.mkdir()
    (root / "Demo.java").write_text(JAVA)
    snapshot = tmp_path / "snapshot"
    service = ScriptService(
        FakeRuntime(),
        config=ScriptConfig(roots=[("valid", root), ("missing", tmp_path / "missing")], snapshot_base=snapshot),
    )
    with pytest.raises(ValueError, match="not a directory"):
        service.initialize()
    assert not service.initialized
    assert not snapshot.exists()


def test_service_without_roots_runs_inline_source_only(tmp_path):
    runtime = FakeRuntime()
    service = ScriptService(runtime, config=ScriptConfig(snapshot_base=tmp_path / "s"))
    service.initialize()
    assert service.list_scripts()["total"] == 0
    with pytest.raises(DomainError) as exc:
        service.run_script("fw", "Demo")
    assert exc.value.code == ErrorCode.SCRIPT_NOT_FOUND
    assert "source" in exc.value.message
    result = service.run_script("fw", source=JAVA_INLINE)
    assert result["inline"] is True
    mode, _name, request = runtime.calls[-1]
    assert mode == "run"
    assert request["script_id"] == "inline:InlinePlate.java"
    assert request["runtime"] == "Java"
    assert Path(request["script_path"]).name == "InlinePlate.java"
    assert not Path(request["script_path"]).exists(), "the inline copy is removed after the run"
    assert str(Path(request["script_path"]).parent) in request["snapshot_roots"]


def test_inline_source_runtime_inference_and_validation(tmp_path):
    service, runtime = _service(tmp_path)
    result = service.run_script("fw", source="# @runtime PyGhidra\nprint(1)\n", script_name="hello")
    assert result["inline"] is True
    assert runtime.calls[-1][2]["script_id"] == "inline:hello.py"
    assert runtime.calls[-1][2]["runtime"] == "PyGhidra"
    # explicit runtime beats inference; aliases are accepted
    service.run_script("fw", source="print(1)\n", runtime="pyghidra")
    assert runtime.calls[-1][2]["runtime"] == "PyGhidra"
    with pytest.raises(DomainError) as ambiguous:
        service.run_script("fw", source="print(1)\n")
    assert ambiguous.value.code == ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS
    with pytest.raises(DomainError) as unavailable:
        service.run_script("fw", source="print 1\n", runtime="Jython")
    assert unavailable.value.code == ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE
    for bad in (
        dict(source="x", script_id="Demo"),
        dict(),
        dict(source="   "),
        dict(source="class NoPublic extends GhidraScript {}", runtime="Java"),
        dict(source="# @runtime PyGhidra\n", script_name="../evil"),
        dict(source="# @runtime PyGhidra\n" + "x" * (service.config.max_source_bytes + 1)),
    ):
        with pytest.raises(DomainError) as exc:
            service.run_script("fw", **bad)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR, bad


def test_list_scripts_reports_runtime_availability_and_pages(tmp_path):
    service, _ = _service(tmp_path)
    result = service.list_scripts(limit=2)
    assert result["total"] == 4
    assert result["count"] == 2
    assert result["has_more"] is True
    assert result["runtimes"] == {"Java": True, "Jython": False, "PyGhidra": True}
    by_id = {item["script_id"]: item for item in service.list_scripts(limit=100)["items"]}
    assert by_id["team:Old.py"]["available"] is False
    assert by_id["team:Old.py"]["unavailable_reason"] == "runtime_unavailable:Jython"
    assert by_id["team:NoHeader.py"]["unavailable_reason"] == "runtime_ambiguous"
    assert [item["script_id"] for item in service.list_scripts(runtime="java")["items"]] == ["team:Demo.java"]
    # include_bundled is only a filter: bundled scripts were never authorized here.
    assert service.list_scripts(include_bundled=True)["total"] == 4


def test_get_script_info_returns_source_when_asked(tmp_path):
    service, _ = _service(tmp_path)
    info = service.get_script_info("Demo")
    assert info["script_id"] == "team:Demo.java"
    assert "source" not in info
    with_source = service.get_script_info("team:Demo.java", include_source=True)
    assert with_source["source"] == JAVA
    assert with_source["source_truncated"] is False


def test_run_script_builds_the_request_from_the_catalog_entry(tmp_path):
    service, runtime = _service(tmp_path)
    result = service.run_script("fw", "Demo", args=["a", "b"], timeout_seconds=10)
    assert result["inline"] is False
    mode, name, request = runtime.calls[0]
    assert (mode, name) == ("run", "fw")
    assert request["script_id"] == "team:Demo.java"
    assert request["runtime"] == "Java"
    assert request["args"] == ["a", "b"]
    assert request["timeout_seconds"] == 10
    assert Path(request["script_path"]).is_relative_to(tmp_path / "snap")
    assert request["snapshot_roots"] == [str(tmp_path / "snap" / "team")]
    service.run_script("fw", "team:Hello.py")
    assert runtime.calls[-1][2]["runtime"] == "PyGhidra"


def test_run_script_rejects_unavailable_and_ambiguous_runtimes(tmp_path):
    service, runtime = _service(tmp_path)
    with pytest.raises(DomainError) as jython:
        service.run_script("fw", "team:Old.py")
    assert jython.value.code == ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE
    assert "Extension" in (jython.value.hint or "")
    with pytest.raises(DomainError) as ambiguous:
        service.run_script("fw", "team:NoHeader.py")
    assert ambiguous.value.code == ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS
    with pytest.raises(DomainError) as missing:
        service.run_script("fw", "Nope")
    assert missing.value.code == ErrorCode.SCRIPT_NOT_FOUND
    assert runtime.calls == []


def test_run_script_validates_args_and_timeout(tmp_path):
    service, runtime = _service(tmp_path, max_args=1, max_timeout_seconds=600)
    with pytest.raises(DomainError) as too_many:
        service.run_script("fw", "Demo", args=["a", "b"])
    assert too_many.value.code == ErrorCode.VALIDATION_ERROR
    with pytest.raises(DomainError) as too_long:
        service.run_script("fw", "Demo", timeout_seconds=601)
    assert too_long.value.code == ErrorCode.VALIDATION_ERROR
    service.run_script("fw", "Demo")
    assert len(runtime.calls) == 1


def test_run_script_uses_the_snapshot_without_a_content_integrity_gate(tmp_path):
    service, runtime = _service(tmp_path)
    snapshot = tmp_path / "snap" / "team" / "Hello.py"
    updated = "# @runtime PyGhidra\nprintln('updated')\n"
    snapshot.write_text(updated, encoding="utf-8")
    service.run_script("fw", "Hello", expected_revision="program-revision")
    request = runtime.calls[-1][2]
    assert Path(request["script_path"]) == snapshot
    assert Path(request["script_path"]).read_text(encoding="utf-8") == updated
    assert request["expected_revision"] == "program-revision"
    assert "sha256" not in request


def test_probe_failure_marks_pyghidra_unavailable(tmp_path):
    service, runtime = _service(tmp_path)
    service.mark_runtime_unavailable("PyGhidra", "propagation_probe_failed")
    with pytest.raises(DomainError) as exc:
        service.run_script("fw", "team:Hello.py")
    assert exc.value.code == ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE
    assert runtime.calls == []
    assert service.list_scripts()["runtimes"]["PyGhidra"] is False


def test_config_validation():
    with pytest.raises(ValueError):
        ScriptConfig(default_timeout_seconds=0)
    with pytest.raises(ValueError):
        ScriptConfig(default_timeout_seconds=10, max_timeout_seconds=5)


def test_catalog_run_accepts_an_explicit_runtime_for_headerless_python(tmp_path):
    service, runtime = _service(tmp_path)
    result = service.run_script("fw", "team:NoHeader.py", runtime="pyghidra")
    assert result["inline"] is False
    assert runtime.calls[-1][2]["runtime"] == "PyGhidra"
    with pytest.raises(DomainError) as jython:
        service.run_script("fw", "team:NoHeader.py", runtime="Jython")
    assert jython.value.code == ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE
    for bad in (
        dict(runtime="Java"),  # a .py cannot be Java
        dict(script_name="x.py"),  # inline-only argument
    ):
        with pytest.raises(DomainError) as exc:
            service.run_script("fw", "team:NoHeader.py", **bad)
        assert exc.value.code == ErrorCode.VALIDATION_ERROR, bad
    with pytest.raises(DomainError) as contradict:
        service.run_script("fw", "Demo", runtime="PyGhidra")
    assert contradict.value.code == ErrorCode.VALIDATION_ERROR


def test_script_catalog_and_execution_do_not_compute_sha256(tmp_path, monkeypatch):
    import hashlib

    def unexpected_hash(*args, **kwargs):
        raise AssertionError("script operations must not compute SHA-256")

    monkeypatch.setattr(hashlib, "sha256", unexpected_hash)
    service, runtime = _service(tmp_path)
    revision = service.list_scripts()["catalog_revision"]
    assert revision
    info = service.get_script_info("Demo", include_source=True)
    assert info["source"] == JAVA
    assert info["catalog_revision"] == revision
    assert "sha256" not in info
    for kwargs in ({"script_id": "Demo"}, {"script_id": "NoHeader", "runtime": "PyGhidra"}, {"source": JAVA_INLINE}):
        result = service.run_script("fw", **kwargs)
        assert "sha256" not in result
        assert "sha256" not in runtime.calls[-1][2]
    inline_root = service.snapshot_base / "inline"
    assert list(inline_root.iterdir()) == [], "inline staging is cleaned up"


def test_snapshot_base_is_created_privately_when_unset(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    service = ScriptService(FakeRuntime(), config=ScriptConfig())
    service.initialize()
    base = service.snapshot_base
    assert base is not None and base.is_dir() and base.parent == tmp_path
    assert (base.stat().st_mode & 0o077) == 0
    service.shutdown()
    assert not base.exists()
