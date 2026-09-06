"""Filesystem path policy for operator-controlled import and project roots.

Without a policy every MCP client can import any file the server process can
read, create Ghidra projects anywhere it can write, and export programs to any
path.  Operators restrict these with ``--allowed-import-root``,
``--allowed-project-root`` and ``--allowed-export-root``; each check resolves
symlinks first so a link inside a root cannot escape it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ghidra_mcp.domain import DomainError, ErrorCode


def _resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _is_within(candidate: Path, roots: tuple[Path, ...]) -> bool:
    return any(candidate == root or root in candidate.parents for root in roots)


@dataclass(frozen=True)
class PathPolicy:
    allowed_import_roots: tuple[Path, ...] = ()
    allowed_project_roots: tuple[Path, ...] = ()
    allowed_export_roots: tuple[Path, ...] = ()

    @classmethod
    def from_roots(
        cls,
        *,
        import_roots: Iterable[str | Path] | None = None,
        project_roots: Iterable[str | Path] | None = None,
        export_roots: Iterable[str | Path] | None = None,
    ) -> PathPolicy:
        return cls(
            allowed_import_roots=cls._normalize_roots(import_roots, label="--allowed-import-root"),
            allowed_project_roots=cls._normalize_roots(project_roots, label="--allowed-project-root"),
            allowed_export_roots=cls._normalize_roots(export_roots, label="--allowed-export-root"),
        )

    @staticmethod
    def _normalize_roots(roots: Iterable[str | Path] | None, *, label: str) -> tuple[Path, ...]:
        normalized: list[Path] = []
        for root in roots or ():
            resolved = _resolve(root)
            if not resolved.is_dir():
                raise ValueError(f"{label} must be an existing directory: {root}")
            if resolved not in normalized:
                normalized.append(resolved)
        return tuple(normalized)

    @property
    def restricts_imports(self) -> bool:
        return bool(self.allowed_import_roots)

    @property
    def restricts_projects(self) -> bool:
        return bool(self.allowed_project_roots)

    @property
    def restricts_exports(self) -> bool:
        return bool(self.allowed_export_roots)

    @property
    def is_unrestricted(self) -> bool:
        return not (self.restricts_imports or self.restricts_projects or self.restricts_exports)

    def validate_import_path(self, binary_path: str) -> None:
        if not self.restricts_imports:
            return
        candidate = _resolve(binary_path)
        if _is_within(candidate, self.allowed_import_roots):
            return
        raise self._denied("import", binary_path, self.allowed_import_roots)

    def validate_project_location(self, project_location: str) -> None:
        if not self.restricts_projects:
            return
        candidate = _resolve(project_location)
        if _is_within(candidate, self.allowed_project_roots):
            return
        raise self._denied("project", project_location, self.allowed_project_roots)

    def validate_export_path(self, output_path: str) -> None:
        if not self.restricts_exports:
            return
        candidate = _resolve(output_path)
        if _is_within(candidate, self.allowed_export_roots):
            return
        raise self._denied("export", output_path, self.allowed_export_roots)

    @staticmethod
    def _denied(kind: str, path: str, roots: tuple[Path, ...]) -> DomainError:
        allowed = ", ".join(str(root) for root in roots)
        return DomainError(
            code=ErrorCode.PATH_NOT_ALLOWED,
            message=f"PATH_NOT_ALLOWED: {kind} path is outside the allowed roots",
            hint=f"Allowed {kind} roots: {allowed}",
            retryable=False,
            details={"kind": kind, "path": str(path), "allowed_roots": [str(root) for root in roots]},
        )


UNRESTRICTED_PATH_POLICY = PathPolicy()

__all__ = ["UNRESTRICTED_PATH_POLICY", "PathPolicy"]
