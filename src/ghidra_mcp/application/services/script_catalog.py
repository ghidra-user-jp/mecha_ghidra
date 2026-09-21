"""Catalog of Ghidra scripts the server may execute.

The catalog is pure Python: it copies every operator-configured script root
(and, when allowed, Ghidra's bundled ``ghidra_scripts`` directories) into a
private per-process snapshot directory at startup and parses each top-level
script's Ghidra header (``@category``,
``@runtime`` ...) the same way ``ghidra.app.script.ScriptInfo`` does.  Files in
subdirectories are copied for use by scripts but, as in the Script Manager,
are not catalog entries of their own.

Scripts are always executed from the snapshot, never from the operator
directory. The copy isolates scripts from later edits to the operator's
directory; it does not enforce immutable execution contents.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
import stat
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ghidra_mcp.domain import DomainError, ErrorCode

RUNTIME_JAVA = "Java"
RUNTIME_JYTHON = "Jython"
RUNTIME_PYGHIDRA = "PyGhidra"
SUPPORTED_RUNTIMES: tuple[str, ...] = (RUNTIME_JAVA, RUNTIME_JYTHON, RUNTIME_PYGHIDRA)
_RUNTIME_ALIASES = {name.lower(): name for name in SUPPORTED_RUNTIMES}
_PYTHON_RUNTIMES = (RUNTIME_JYTHON, RUNTIME_PYGHIDRA)

ORIGIN_OPERATOR = "operator"
ORIGIN_BUNDLED = "bundled"

_SCRIPT_SUFFIXES = {".java": RUNTIME_JAVA, ".py": None}
_TAG_RE = re.compile(r"^@(\w+)\b\s*(.*)$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Snapshot sub-directories the server uses itself: ``inline`` stages ``run_script(source=...)``
# text, ``probe`` holds the startup exception-propagation probe.  A root with one of
# these labels would be copied into (and cleaned up with) those directories.
RESERVED_ROOT_LABELS: frozenset[str] = frozenset({"inline", "probe"})
DEFAULT_MAX_FILES_PER_ROOT = 2000


@dataclass(frozen=True)
class ScriptHeader:
    """Metadata parsed from a script's leading comment block."""

    description: str | None = None
    category: str | None = None
    author: str | None = None
    runtime: str | None = None
    import_packages: tuple[str, ...] = ()
    tags: dict[str, str] = field(default_factory=dict)


def _reject_reserved_label(label: str) -> None:
    if label.lower() in RESERVED_ROOT_LABELS:
        reserved = ", ".join(sorted(RESERVED_ROOT_LABELS))
        raise ValueError(f"script root label {label!r} is reserved (reserved words: {reserved})")


def parse_script_header(text: str, *, comment_prefix: str) -> ScriptHeader:
    """Parse a Ghidra script header from ``text``.

    Mirrors ``ScriptInfo.parseHeader``: blank lines are skipped, a certification
    header (``/* ### ... */`` for Java, ``## ### ... ##`` for Python) and block
    comments (``/* */``, ``'''``) are skipped, lines starting with
    ``comment_prefix`` are header lines, and parsing ends at the first other
    line.  Lines whose first token is ``@tag`` set that tag; the remaining lines
    (before the first tag) form the description.  ``@runtime`` values are
    normalized to ``Java``/``Jython``/``PyGhidra``; unknown runtimes are kept
    verbatim so the caller can report them.
    """

    python = comment_prefix == "#"
    certify_start = "## ###" if python else "/* ###"
    certify_end = "##" if python else "*/"
    block_start = "'''" if python else "/*"
    block_end = "'''" if python else "*/"
    in_certify = False
    in_block = False
    description_lines: list[str] = []
    tags: dict[str, str] = {}
    import_packages: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if in_certify:
            if line.startswith(certify_end) if python else line.endswith(certify_end):
                in_certify = False
            continue
        if in_block:
            if line.endswith(block_end):
                in_block = False
            continue
        if line.startswith(certify_start):
            in_certify = True
            continue
        if line.startswith(block_start):
            # A one-line block (``/* x */``) opens and closes here.
            if not (len(line) > len(block_start) and line.endswith(block_end)):
                in_block = True
            continue
        if not line.startswith(comment_prefix):
            break
        body = line[len(comment_prefix) :].strip()
        match = _TAG_RE.match(body)
        if match:
            tag, value = match.group(1).lower(), match.group(2).strip()
            if tag == "importpackage":
                import_packages.extend(part.strip() for part in value.split(",") if part.strip())
            tags[tag] = value
            continue
        if tags:
            # Description text after tags is ignored, like ScriptInfo.
            continue
        description_lines.append(body)
    runtime_raw = tags.get("runtime")
    runtime = None
    if runtime_raw:
        runtime = _RUNTIME_ALIASES.get(runtime_raw.strip().lower(), runtime_raw.strip())
    description = " ".join(part for part in description_lines if part).strip() or None
    return ScriptHeader(
        description=description,
        category=tags.get("category") or None,
        author=tags.get("author") or None,
        runtime=runtime,
        import_packages=tuple(import_packages),
        tags=tags,
    )


@dataclass(frozen=True)
class ScriptRoot:
    label: str
    source_dir: Path
    snapshot_dir: Path
    origin: str
    file_count: int = 0


@dataclass(frozen=True)
class ScriptEntry:
    script_id: str
    root_label: str
    origin: str
    relative_path: str
    name: str
    path: Path
    size: int
    runtime: str | None
    header_runtime: str | None
    runtime_reason: str | None
    category: str | None
    description: str | None
    author: str | None
    import_packages: tuple[str, ...]
    available: bool = True
    unavailable_reason: str | None = None

    def with_runtime(self, runtime: str) -> "ScriptEntry":
        """Copy of a header-less Python entry resolved with an explicit runtime (available flag recomputed)."""

        return dataclasses.replace(
            self, runtime=runtime, available=True, unavailable_reason=None, runtime_reason="explicit"
        )

    def to_summary(self) -> dict[str, Any]:
        return {
            "script_id": self.script_id,
            "name": self.name,
            "runtime": self.runtime,
            "category": self.category,
            "description": self.description,
            "author": self.author,
            "origin": self.origin,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
        }

    def to_detail(self) -> dict[str, Any]:
        detail = self.to_summary()
        detail.update(
            {
                "root_label": self.root_label,
                "relative_path": self.relative_path,
                "size": self.size,
                "header_runtime": self.header_runtime,
                "runtime_reason": self.runtime_reason,
                "import_packages": list(self.import_packages),
            }
        )
        return detail


def parse_root_argument(value: str) -> tuple[str | None, Path]:
    """Parse ``LABEL=DIR`` or ``DIR`` from ``--script-root``."""

    text = value.strip()
    if not text:
        raise ValueError("--script-root must not be empty")
    label: str | None = None
    if "=" in text:
        head, tail = text.split("=", 1)
        if head.strip() and not Path(head.strip()).is_absolute() and _LABEL_RE.match(head.strip()):
            label = head.strip()
            _reject_reserved_label(label)
            text = tail.strip()
    if not text:
        raise ValueError("--script-root is missing the directory")
    return label, Path(text).expanduser()


def _default_label(path: Path, taken: set[str]) -> str:
    base = (re.sub(r"[^A-Za-z0-9_.-]", "-", path.name or "root").strip("-") or "root")[:40]
    # Numeric suffixes resolve collisions, but cannot repair an invalid first
    # character (e.g. .scripts or _scripts). Normalize that before the loop.
    base = base.lstrip("._-") or "root"
    label = base
    counter = 2
    while label in taken:
        label = f"{base}-{counter}"
        counter += 1
    return label


def discover_bundled_roots(install_dir: Path) -> list[tuple[str, Path]]:
    """Return ``(label, dir)`` for every ``ghidra_scripts`` directory in a Ghidra install."""

    roots: list[tuple[str, Path]] = []
    ghidra_dir = install_dir / "Ghidra"
    if not ghidra_dir.is_dir():
        return roots
    for module_dir in sorted(ghidra_dir.glob("*/*")):
        scripts_dir = module_dir / "ghidra_scripts"
        if scripts_dir.is_dir():
            roots.append((f"bundled-{module_dir.name}", scripts_dir))
    return roots


_DERIVED_DIRS = {"__pycache__"}
_DERIVED_SUFFIXES = (".pyc", ".pyo", ".class")


def _skip_directory(parent: Path, name: str) -> bool:
    """Hidden and bytecode directories are never inputs; symlinked directories are not
    followed (a link into a larger tree or a loop would otherwise be copied)."""

    return name.startswith(".") or name in _DERIVED_DIRS or (parent / name).is_symlink()


def _iter_regular_files(root: Path) -> Iterable[Path]:
    """Regular files under ``root`` except hidden entries and interpreter-derived bytecode.

    Symlinks to files are followed (a dangling one is not a file and is skipped);
    symlinked directories are not. Interpreter-generated files are excluded
    from the source file count.
    """

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        parent = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames if not _skip_directory(parent, name))
        for filename in sorted(filenames):
            if filename.startswith(".") or filename.endswith(_DERIVED_SUFFIXES):
                continue
            path = parent / filename
            if path.is_file():
                yield path


def _snapshot_ignore(directory: str, names: list[str]) -> set[str]:
    """``shutil.copytree`` ignore callback: hidden entries, bytecode dirs and directory symlinks."""

    parent = Path(directory)
    return {
        name
        for name in names
        if name.startswith(".") or name in _DERIVED_DIRS or ((parent / name).is_symlink() and (parent / name).is_dir())
    }


def _snapshot_root(label: str, source: Path, snapshot_dir: Path) -> None:
    """Copy ``source`` to ``snapshot_dir``; file symlinks become regular files, directory symlinks are dropped."""

    try:
        shutil.copytree(source, snapshot_dir, symlinks=False, ignore=_snapshot_ignore, ignore_dangling_symlinks=True)
    except OSError as exc:  # shutil.Error is an OSError: a partial copy is a broken catalog
        raise ValueError(f"script root {label} could not be snapshotted: {exc}") from exc


class ScriptCatalog:
    """Snapshot-backed catalog of executable scripts."""

    def __init__(
        self,
        *,
        snapshot_base: Path,
        max_files_per_root: int = DEFAULT_MAX_FILES_PER_ROOT,
    ) -> None:
        self._snapshot_base = Path(snapshot_base)
        self._max_files = int(max_files_per_root)
        self._roots: dict[str, ScriptRoot] = {}
        self._entries: dict[str, ScriptEntry] = {}
        self._runtime_availability: dict[str, bool] = {}
        self._revision = ""

    # ---- construction -----------------------------------------------------

    @property
    def revision(self) -> str:
        """Opaque identifier for this catalog build, independent of file contents."""
        return self._revision

    @property
    def roots(self) -> dict[str, ScriptRoot]:
        return dict(self._roots)

    @property
    def snapshot_base(self) -> Path:
        return self._snapshot_base

    def build(self, roots: Iterable[tuple[str | None, Path, str]]) -> None:
        """Snapshot ``(label, dir, origin)`` roots and index their scripts.

        Raises ``ValueError`` for unusable configuration (missing directory,
        duplicate label, too many files) so startup fails loudly.
        """

        self._snapshot_base.mkdir(parents=True, exist_ok=True)
        os.chmod(self._snapshot_base, stat.S_IRWXU)
        taken: set[str] = set()
        built_roots: dict[str, ScriptRoot] = {}
        for requested_label, source_dir, origin in roots:
            source = Path(source_dir).expanduser()
            if not source.is_dir():
                raise ValueError(f"script root is not a directory: {source}")
            source = source.resolve()
            label = requested_label or _default_label(source, taken)
            if not _LABEL_RE.match(label):
                raise ValueError(f"invalid script root label: {label!r}")
            _reject_reserved_label(label)
            if label in taken:
                raise ValueError(f"duplicate script root label: {label!r}")
            taken.add(label)
            snapshot_dir = self._snapshot_base / label
            if snapshot_dir.exists():
                shutil.rmtree(snapshot_dir)
            file_count = sum(1 for _ in _iter_regular_files(source))
            if file_count > self._max_files:
                raise ValueError(f"script root {source} has {file_count} files; the limit is {self._max_files}")
            _snapshot_root(label, source, snapshot_dir)
            built_roots[label] = ScriptRoot(
                label=label,
                source_dir=source,
                snapshot_dir=snapshot_dir,
                origin=origin,
                file_count=sum(1 for _ in _iter_regular_files(snapshot_dir)),
            )
        self._roots = built_roots
        self._entries = {}
        for root in built_roots.values():
            for path in sorted(root.snapshot_dir.iterdir()):
                if not path.is_file():
                    # Only top-level files are scripts in Ghidra's Script Manager.
                    continue
                entry = self._entry_for(root, path.name)
                if entry is not None:
                    self._entries[entry.script_id] = entry
        self._revision = uuid.uuid4().hex
        self._apply_runtime_availability()

    def _entry_for(self, root: ScriptRoot, relative: str) -> ScriptEntry | None:
        rel_path = PurePosixPath(relative)
        suffix = rel_path.suffix.lower()
        if suffix not in _SCRIPT_SUFFIXES:
            return None
        path = root.snapshot_dir / Path(*rel_path.parts)
        comment_prefix = "//" if suffix == ".java" else "#"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        header = parse_script_header(text, comment_prefix=comment_prefix)
        runtime: str | None
        runtime_reason: str | None = None
        if suffix == ".java":
            runtime = RUNTIME_JAVA
            if header.runtime and header.runtime != RUNTIME_JAVA:
                runtime_reason = f"header_runtime_ignored:{header.runtime}"
        elif header.runtime in _PYTHON_RUNTIMES:
            runtime = header.runtime
        elif header.runtime:
            runtime = None
            runtime_reason = f"unsupported_runtime:{header.runtime}"
        else:
            # A .py without an ``@runtime`` header is refused: Jython and PyGhidra are different languages.
            runtime = None
            runtime_reason = "runtime_ambiguous"
        available = runtime is not None
        unavailable_reason = None if available else runtime_reason
        return ScriptEntry(
            script_id=f"{root.label}:{rel_path.as_posix()}",
            root_label=root.label,
            origin=root.origin,
            relative_path=rel_path.as_posix(),
            name=rel_path.name,
            path=path,
            size=path.stat().st_size,
            runtime=runtime,
            header_runtime=header.runtime,
            runtime_reason=runtime_reason,
            category=header.category,
            description=header.description,
            author=header.author,
            import_packages=header.import_packages,
            available=available,
            unavailable_reason=unavailable_reason,
        )

    def set_runtime_availability(self, availability: dict[str, bool]) -> None:
        """Mark entries whose runtime provider is not installed as unavailable."""

        self._runtime_availability = {
            _RUNTIME_ALIASES.get(str(name).lower(), str(name)): bool(flag) for name, flag in availability.items()
        }
        self._apply_runtime_availability()

    def _apply_runtime_availability(self) -> None:
        if not self._runtime_availability:
            return
        for script_id, entry in list(self._entries.items()):
            if entry.runtime is None:
                continue
            installed = self._runtime_availability.get(entry.runtime)
            if installed is False:
                self._entries[script_id] = replace(
                    entry, available=False, unavailable_reason=f"runtime_unavailable:{entry.runtime}"
                )
            elif installed and entry.unavailable_reason and entry.unavailable_reason.startswith("runtime_unavailable:"):
                self._entries[script_id] = replace(entry, available=True, unavailable_reason=None)

    def runtime_available(self, runtime: str) -> bool | None:
        return self._runtime_availability.get(runtime)

    # ---- queries ----------------------------------------------------------

    def list_entries(
        self,
        *,
        text: str | None = None,
        runtime: str | None = None,
        category: str | None = None,
        origin: str | None = None,
        include_bundled: bool = False,
    ) -> list[ScriptEntry]:
        needle = (text or "").strip().lower()
        wanted_runtime = _RUNTIME_ALIASES.get((runtime or "").strip().lower()) if runtime else None
        if runtime and wanted_runtime is None:
            raise ValueError(f"runtime must be one of: {', '.join(SUPPORTED_RUNTIMES)}")
        wanted_category = (category or "").strip().lower() or None
        results = []
        for script_id in sorted(self._entries):
            entry = self._entries[script_id]
            if entry.origin == ORIGIN_BUNDLED and not include_bundled:
                continue
            if origin and entry.origin != origin:
                continue
            if wanted_runtime and entry.runtime != wanted_runtime:
                continue
            if wanted_category and (entry.category or "").lower() != wanted_category:
                continue
            if (
                needle
                and needle
                not in " ".join(
                    part
                    for part in (entry.script_id, entry.name, entry.description or "", entry.category or "")
                    if part
                ).lower()
            ):
                continue
            results.append(entry)
        return results

    def get(self, script_id: str) -> ScriptEntry | None:
        return self._entries.get(script_id)

    def resolve(self, script_ref: str, *, include_bundled: bool = True) -> ScriptEntry:
        """Resolve a root-qualified ``script_id`` or an unambiguous bare name."""

        ref = (script_ref or "").strip()
        if not ref:
            raise DomainError(ErrorCode.SCRIPT_NOT_FOUND, "script_id is required")
        entry = self._entries.get(ref)
        if entry is not None:
            return entry
        if ":" in ref:
            raise DomainError(ErrorCode.SCRIPT_NOT_FOUND, f"script not found: {ref}", details={"script_id": ref})
        matches = [
            candidate
            for candidate in self._entries.values()
            if (candidate.name == ref or PurePosixPath(candidate.relative_path).stem == ref)
            and (include_bundled or candidate.origin != ORIGIN_BUNDLED)
        ]
        if not matches:
            raise DomainError(ErrorCode.SCRIPT_NOT_FOUND, f"script not found: {ref}", details={"script_id": ref})
        if len(matches) > 1:
            raise DomainError(
                ErrorCode.AMBIGUOUS_SCRIPT,
                f"{len(matches)} scripts are named {ref}; pass the full script_id",
                details={"script_id": ref, "candidates": sorted(match.script_id for match in matches)},
            )
        return matches[0]

    def cleanup(self) -> None:
        shutil.rmtree(self._snapshot_base, ignore_errors=True)


__all__ = [
    "DEFAULT_MAX_FILES_PER_ROOT",
    "ORIGIN_BUNDLED",
    "ORIGIN_OPERATOR",
    "RESERVED_ROOT_LABELS",
    "RUNTIME_JAVA",
    "RUNTIME_JYTHON",
    "RUNTIME_PYGHIDRA",
    "SUPPORTED_RUNTIMES",
    "ScriptCatalog",
    "ScriptEntry",
    "ScriptHeader",
    "ScriptRoot",
    "discover_bundled_roots",
    "parse_root_argument",
    "parse_script_header",
]
