"""Application service for the ``scripts`` tool category.

Owns the snapshot catalog, ``script_id`` resolution and the staging of inline
``source`` text; execution itself is the runtime's in-process ``run_script``
(the way the Ghidra Script Manager runs scripts, wrapped in a transaction).  Execution itself is delegated to the runtime
through ``ScriptRuntimePort`` in one of two modes:

"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghidra_mcp.application.locks import LockManager
from ghidra_mcp.application.services.ports import ScriptRuntimePort
from ghidra_mcp.application.services.script_catalog import (
    DEFAULT_MAX_FILES_PER_ROOT,
    ORIGIN_BUNDLED,
    ORIGIN_OPERATOR,
    RUNTIME_JAVA,
    RUNTIME_JYTHON,
    SUPPORTED_RUNTIMES,
    ScriptCatalog,
    ScriptEntry,
    discover_bundled_roots,
    parse_script_header,
)
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_mapping import to_domain_error

logger = logging.getLogger(__name__)

_RUNTIME_ALIASES = {name.lower(): name for name in SUPPORTED_RUNTIMES}

DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_TIMEOUT_SECONDS = 3600
DEFAULT_OUTPUT_LIMIT_BYTES = 64 * 1024
DEFAULT_MAX_ARGS = 64
DEFAULT_MAX_ARGS_BYTES = 64 * 1024
DEFAULT_MAX_SOURCE_BYTES = 256 * 1024


@dataclass(frozen=True)
class ScriptConfig:
    """Operator configuration for script execution."""

    roots: tuple[tuple[str | None, Path], ...] = ()
    # ``--script-root bundled`` adds Ghidra's own ghidra_scripts directories (origin=bundled).
    include_bundled: bool = False
    snapshot_base: Path | None = None
    ghidra_install_dir: Path | None = None
    max_files_per_root: int = DEFAULT_MAX_FILES_PER_ROOT
    default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_timeout_seconds: int = DEFAULT_MAX_TIMEOUT_SECONDS
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES
    max_args: int = DEFAULT_MAX_ARGS
    max_args_bytes: int = DEFAULT_MAX_ARGS_BYTES
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.default_timeout_seconds < 1 or self.max_timeout_seconds < self.default_timeout_seconds:
            raise ValueError("script timeout configuration is invalid")


class ScriptService:
    def __init__(
        self,
        runtime: ScriptRuntimePort | None,
        *,
        config: ScriptConfig | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self._runtime = runtime
        self._config = config or ScriptConfig()
        self._lock_manager = lock_manager or LockManager()
        self._catalog: ScriptCatalog | None = None
        self._availability_checked = False
        self._runtime_overrides: dict[str, str] = {}

    # ---- lifecycle --------------------------------------------------------

    @property
    def config(self) -> ScriptConfig:
        return self._config

    @property
    def enabled(self) -> bool:
        """Scripts tools work whenever they are exposed: inline ``source`` needs no root, catalog runs need one."""
        return True

    @property
    def initialized(self) -> bool:
        return self._catalog is not None

    def initialize(self) -> None:
        """Snapshot the configured roots.  Called once at server startup."""

        snapshot_base = self._config.snapshot_base
        if snapshot_base is None:
            # A fresh, unpredictable, 0700 directory: never reuse an existing path under a shared temp dir.
            snapshot_base = Path(tempfile.mkdtemp(prefix="mecha_ghidra_scripts_"))
        catalog = ScriptCatalog(
            snapshot_base=snapshot_base,
            max_files_per_root=self._config.max_files_per_root,
        )
        try:
            roots: list[tuple[str | None, Path, str]] = [
                (label, path, ORIGIN_OPERATOR) for label, path in self._config.roots
            ]
            if self._config.include_bundled:
                if self._config.ghidra_install_dir is None:
                    raise ValueError("--script-root bundled requires a Ghidra installation directory")
                roots.extend(
                    (label, path, ORIGIN_BUNDLED)
                    for label, path in discover_bundled_roots(self._config.ghidra_install_dir)
                )
            catalog.build(roots)
        except BaseException:
            catalog.cleanup()
            raise
        self._catalog = catalog
        logger.info(
            "script catalog ready: %d roots, %d scripts, revision=%s",
            len(catalog.roots),
            len(catalog.list_entries(include_bundled=True)),
            catalog.revision,
        )

    def shutdown(self) -> None:
        if self._catalog is not None:
            self._catalog.cleanup()

    @property
    def snapshot_base(self) -> Path | None:
        return None if self._catalog is None else self._catalog.snapshot_base

    def mark_runtime_unavailable(self, runtime: str, reason: str) -> None:
        """Operator-visible override, e.g. when the PyGhidra propagation probe fails at startup."""
        if self._catalog is None:
            return
        self._runtime_overrides[runtime] = reason
        self._catalog.set_runtime_availability({runtime: False})

    # ---- helpers ----------------------------------------------------------

    def _require_enabled(self) -> ScriptCatalog:
        if self._catalog is None:
            raise DomainError(
                ErrorCode.SCRIPTS_DISABLED,
                "the scripts tools were not initialized on this server (expose the scripts category at startup)",
                hint="Scripts run with the server's OS privileges; the operator decides whether to expose them.",
            )
        return self._catalog

    def _require_catalog_scripts(self, catalog: ScriptCatalog) -> ScriptCatalog:
        if not catalog.roots:
            raise DomainError(
                ErrorCode.SCRIPT_NOT_FOUND,
                "no script root is configured on this server; pass the script text as `source` instead, or start "
                "the server with --script-root DIR",
            )
        return catalog

    def _refresh_runtime_availability(self, catalog: ScriptCatalog) -> None:
        if self._availability_checked:
            return
        if self._runtime is None:
            return
        try:
            availability = self._runtime.script_runtime_availability()
        except Exception as exc:
            logger.warning("failed to query script runtime availability: %s", exc)
            return
        for runtime in self._runtime_overrides:
            availability[runtime] = False
        catalog.set_runtime_availability(availability)
        self._availability_checked = True

    def _to_domain_error(self, exc: Exception, *, operation: str, target: str | None = None) -> DomainError:
        return to_domain_error(
            exc,
            operation=operation,
            target=target,
            hint="See details for the script diagnostics",
            keep_none_details=("target",),
        )

    def _project_key(self, target: str) -> str | None:
        return None if self._runtime is None else self._runtime.project_lock_key(target)

    # ---- tools ------------------------------------------------------------

    def list_scripts(
        self,
        *,
        filter: str | None = None,
        runtime: str | None = None,
        category: str | None = None,
        origin: str | None = None,
        include_bundled: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        catalog = self._require_enabled()
        self._refresh_runtime_availability(catalog)
        if include_bundled and not self._config.include_bundled:
            # The client argument only filters an already-authorized catalog.
            include_bundled = False
        entries = catalog.list_entries(
            text=filter,
            runtime=runtime,
            category=category,
            origin=origin,
            include_bundled=include_bundled,
        )
        page = entries[offset : offset + limit]
        return {
            "items": [entry.to_summary() for entry in page],
            "count": len(page),
            "total": len(entries),
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < len(entries),
            "catalog_revision": catalog.revision,
            "bundled_scripts_included": self._config.include_bundled,
            "runtimes": {name: catalog.runtime_available(name) for name in SUPPORTED_RUNTIMES},
        }

    def get_script_info(self, script_id: str, *, include_source: bool = False) -> dict[str, Any]:
        catalog = self._require_enabled()
        self._refresh_runtime_availability(catalog)
        entry = catalog.resolve(script_id)
        detail = entry.to_detail()
        detail["catalog_revision"] = catalog.revision
        if include_source:
            limit = self._config.max_source_bytes
            data = entry.path.read_bytes()
            truncated = len(data) > limit
            detail["source"] = data[:limit].decode("utf-8", errors="replace")
            detail["source_truncated"] = truncated
            detail["source_bytes"] = len(data)
        return detail

    def _validate_args(self, args: list[str] | None) -> list[str]:
        values = [str(item) for item in (args or [])]
        if len(values) > self._config.max_args:
            raise ValueError(f"args accepts at most {self._config.max_args} values")
        total = sum(len(value.encode("utf-8")) for value in values)
        if total > self._config.max_args_bytes:
            raise ValueError(f"args exceed {self._config.max_args_bytes} bytes in total")
        return values

    def _validate_timeout(self, timeout_seconds: int | None) -> int:
        value = self._config.default_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
        if value < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if value > self._config.max_timeout_seconds:
            raise ValueError(f"timeout_seconds must be <= {self._config.max_timeout_seconds}")
        return value

    def _resolve_runnable(
        self,
        catalog: ScriptCatalog,
        script_id: str,
        *,
        runtime_override: str | None = None,
    ) -> ScriptEntry:
        entry = catalog.resolve(script_id)
        if runtime_override:
            wanted = _RUNTIME_ALIASES.get(runtime_override.strip().lower())
            if wanted is None:
                raise ValueError(f"runtime must be one of: {', '.join(SUPPORTED_RUNTIMES)}")
            if entry.runtime is not None and entry.runtime != wanted:
                raise ValueError(f"{entry.script_id} is a {entry.runtime} script; runtime={wanted} contradicts it")
            if entry.runtime is None:
                if wanted == RUNTIME_JAVA:
                    raise ValueError(f"{entry.script_id} is a Python script; runtime=Java is not possible")
                available = catalog.runtime_available(wanted)
                if available is False:
                    raise DomainError(
                        ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE,
                        f"the {wanted} runtime is not available on this server",
                        details={"script_id": entry.script_id, "runtime": wanted},
                    )
                return entry.with_runtime(wanted)
        if entry.runtime is None:
            reason = entry.unavailable_reason or "runtime_ambiguous"
            if reason.startswith("unsupported_runtime:"):
                raise DomainError(
                    ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE,
                    f"{entry.script_id} declares an unsupported runtime ({entry.header_runtime})",
                    details={"script_id": entry.script_id, "header_runtime": entry.header_runtime},
                )
            raise DomainError(
                ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS,
                f"{entry.script_id} has no @runtime header; add '# @runtime PyGhidra' or '# @runtime Jython' to the "
                "file, or pass runtime='PyGhidra' | 'Jython' to run_script",
                details={"script_id": entry.script_id},
            )
        if not entry.available:
            raise DomainError(
                ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE,
                f"{entry.script_id} cannot run: {entry.unavailable_reason}",
                hint=(
                    "Jython ships as a Ghidra Extension: unzip Extensions/Ghidra/*_Jython.zip into Ghidra/Extensions "
                    "and restart the server"
                    if (entry.unavailable_reason or "").endswith("Jython")
                    else None
                ),
                details={"script_id": entry.script_id, "reason": entry.unavailable_reason, "runtime": entry.runtime},
            )
        return entry

    def run_script(
        self,
        target: str,
        script_id: str | None = None,
        *,
        source: str | None = None,
        runtime: str | None = None,
        script_name: str | None = None,
        args: list[str] | None = None,
        timeout_seconds: int | None = None,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        inline_dir: Path | None = None
        try:
            catalog = self._require_enabled()
            self._refresh_runtime_availability(catalog)
            if (script_id is None) == (source is None):
                raise ValueError("pass exactly one of script_id (catalog script) or source (inline script text)")
            if source is not None:
                inline = self._stage_inline_source(catalog, source, runtime=runtime, script_name=script_name)
                inline_dir = inline["dir"]  # assigned first so the finally-cleanup covers every rejection below
                request_head = {
                    "script_id": inline["script_id"],
                    "script_path": str(inline["path"]),
                    "script_name": inline["name"],
                    "runtime": inline["runtime"],
                    "inline": True,
                }
                extra_roots = [str(inline_dir)]
            else:
                assert script_id is not None
                if script_name:
                    raise ValueError("script_name applies to inline source only")
                entry = self._resolve_runnable(
                    self._require_catalog_scripts(catalog), script_id, runtime_override=runtime
                )
                request_head = {
                    "script_id": entry.script_id,
                    "script_path": str(entry.path),
                    "script_name": entry.name,
                    "runtime": entry.runtime,
                    "inline": False,
                }
                extra_roots = []
            request = {
                **request_head,
                "args": self._validate_args(args),
                "timeout_seconds": self._validate_timeout(timeout_seconds),
                "expected_revision": expected_revision,
                "output_limit_bytes": self._config.output_limit_bytes,
                "catalog_revision": catalog.revision,
                "snapshot_base": str(catalog.snapshot_base),
                "snapshot_roots": [str(root.snapshot_dir) for root in catalog.roots.values()] + extra_roots,
            }
            with self._lock_manager.acquire(target=target, project_key=self._project_key(target)):
                result = self._runtime.run_script(target, request=request)
            result["inline"] = source is not None
            return result
        except Exception as exc:
            raise self._to_domain_error(exc, operation="run_script", target=target) from exc
        finally:
            if inline_dir is not None:
                shutil.rmtree(inline_dir, ignore_errors=True)

    _JAVA_CLASS_RE = re.compile(r"^\s*public\s+(?:final\s+)?class\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _NAME_RE = re.compile(r"^[A-Za-z_][\w.-]{0,120}$")

    def _stage_inline_source(
        self, catalog: ScriptCatalog, source: str, *, runtime: str | None, script_name: str | None
    ) -> dict[str, Any]:
        """Write client-supplied script text into a private per-run directory and describe it like a catalog entry.

        The runtime comes from ``runtime`` when given, else from ``public class X extends GhidraScript`` (Java)
        or a ``# @runtime`` header (Python); a Python script without either is refused as ambiguous.
        """

        if not source.strip():
            raise ValueError("source is empty")
        encoded = source.encode("utf-8")
        if len(encoded) > self._config.max_source_bytes:
            raise ValueError(f"source exceeds {self._config.max_source_bytes} bytes")
        wanted = _RUNTIME_ALIASES.get((runtime or "").strip().lower()) if runtime else None
        if runtime and wanted is None:
            raise ValueError(f"runtime must be one of: {', '.join(SUPPORTED_RUNTIMES)}")
        java_match = self._JAVA_CLASS_RE.search(source)
        looks_java = java_match is not None and "GhidraScript" in source
        if wanted is None:
            if looks_java:
                wanted = RUNTIME_JAVA
            else:
                header = parse_script_header(source, comment_prefix="#")
                wanted = _RUNTIME_ALIASES.get((header.runtime or "").lower()) if header.runtime else None
        if wanted is None:
            raise DomainError(
                ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS,
                "cannot tell which runtime the source needs; pass runtime='PyGhidra' | 'Jython' | 'Java' or add a "
                "'# @runtime ...' header (Java is recognised by 'public class X extends GhidraScript')",
            )
        if wanted == RUNTIME_JAVA:
            if java_match is None:
                raise ValueError("a Java script needs 'public class <Name> extends GhidraScript'")
            name = f"{java_match.group(1)}.java"
            if script_name and script_name not in (name, java_match.group(1)):
                raise ValueError(f"script_name must match the public class ({java_match.group(1)})")
        else:
            name = (script_name or "inline_script").strip()
            if not name.endswith(".py"):
                name += ".py"
            if not self._NAME_RE.match(name[:-3]) or "/" in name or "\\" in name:
                raise ValueError("script_name must be a plain file name")
        available = catalog.runtime_available(wanted)
        if available is False:
            raise DomainError(
                ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE,
                f"the {wanted} runtime is not available on this server",
                hint=(
                    "Jython ships as a Ghidra Extension: unzip Extensions/Ghidra/*_Jython.zip into Ghidra/Extensions "
                    "and restart the server"
                    if wanted == RUNTIME_JYTHON
                    else None
                ),
                details={"runtime": wanted},
            )
        run_dir = catalog.snapshot_base / "inline" / uuid.uuid4().hex[:12]
        run_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(run_dir, 0o700)
        path = run_dir / name
        path.write_bytes(encoded)
        return {
            "dir": run_dir,
            "path": path,
            "name": name,
            "runtime": wanted,
            "script_id": f"inline:{name}",
        }


__all__ = [
    "DEFAULT_OUTPUT_LIMIT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ScriptConfig",
    "ScriptService",
]
