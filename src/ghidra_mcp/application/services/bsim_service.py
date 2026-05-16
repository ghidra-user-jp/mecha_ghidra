"""Application service for BSim MCP tools."""

from __future__ import annotations

import getpass
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from ghidra_mcp.infrastructure.bsim import BsimJavaBackend, mask_bsim_url

from .core_command_service import CoreCommandService
from .target_service import TargetService


@dataclass(frozen=True)
class BsimConfig:
    bsim_url: str | None = None
    bsim_password: str | None = None
    bsim_password_env: str | None = None
    work_dir: str | None = None
    command_timeout: int = 300


def _resolve_config_password(config: BsimConfig) -> str | None:
    env_name = (config.bsim_password_env or "").strip()
    has_password = config.bsim_password is not None
    if has_password and env_name:
        raise ValueError("--bsim-password and --bsim-password-env cannot be used together")
    if has_password:
        if config.bsim_password == "":
            raise ValueError("--bsim-password is empty")
        return config.bsim_password
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None:
        raise ValueError(f"Environment variable '{env_name}' is not set")
    if value == "":
        raise ValueError(f"Environment variable '{env_name}' is empty")
    return value


def _hostport(parts) -> str:
    hostname = parts.hostname
    if not hostname:
        raise ValueError("--bsim-password requires bsim_url with a hostname")
    host = hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return host


def _bsim_url_with_password(bsim_url: str, password: str | None) -> str:
    if password is None:
        return bsim_url
    parts = urlsplit(bsim_url)
    if not parts.scheme or not parts.netloc:
        raise ValueError("--bsim-password requires a network BSim URL such as postgresql://user@host/database")
    if parts.password is not None:
        raise ValueError("bsim_url already contains a password; use either bsim_url credentials or --bsim-password")

    username = unquote(parts.username or "") or getpass.getuser()
    userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
    return urlunsplit((parts.scheme, f"{userinfo}@{_hostport(parts)}", parts.path, parts.query, parts.fragment))


def _normalize_domain_path(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not text.startswith("/"):
        text = "/" + text
    return pathlib.PurePosixPath(text).as_posix()


def _project_identity(project_location: str, project_name: str | None = None) -> tuple[str, str]:
    path = pathlib.Path(project_location).expanduser()
    if path.suffix.lower() == ".gpr":
        return (str(path.parent.resolve()), path.stem)
    if project_name:
        return (str(path.resolve()), str(project_name))
    raise ValueError("project_name is required when project_location is not a .gpr file")


def _project_from_ghidra_url(url: str | None) -> tuple[str, str | None]:
    if not url:
        raise ValueError("matched_ref requires repository or ghidra_url")
    parts = urlsplit(str(url))
    if parts.scheme != "ghidra":
        raise ValueError(f"unsupported BSim ghidra URL: {url}")
    if parts.netloc:
        raise ValueError(
            "BSIM_REMOTE_PROJECT_LOAD_UNSUPPORTED: matched_ref points to a remote ghidra:// repository; "
            "provide project_location/project_name in matched_ref or load it manually"
        )
    path = pathlib.Path(parts.path).expanduser()
    if path.suffix.lower() == ".gpr":
        return (str(path), None)
    return (str(path) + ".gpr", None)


def _default_match_target(md5: str | None, executable_name: str | None) -> str:
    if md5:
        return "bsim_" + re.sub(r"[^0-9a-fA-F]", "", md5)[:12].lower()
    base = re.sub(r"[^A-Za-z0-9_]+", "_", executable_name or "match").strip("_")
    return "bsim_" + (base or "match")


class BsimService:
    def __init__(
        self,
        *,
        core_command_service: CoreCommandService,
        target_service: TargetService,
        config: BsimConfig | None = None,
        java_backend: BsimJavaBackend | None = None,
    ) -> None:
        self._core_command_service = core_command_service
        self._target_service = target_service
        self._config = config or BsimConfig()
        self._java_backend = java_backend or BsimJavaBackend()
        self._loaded_match_index: dict[str, str] = {}

    def _resolve_bsim_url(self, bsim_url: str | None = None) -> str:
        resolved = (bsim_url or self._config.bsim_url or "").strip()
        if not resolved:
            raise ValueError("bsim_url is required; set --bsim-url or pass bsim_url")
        return _bsim_url_with_password(resolved, _resolve_config_password(self._config))

    @staticmethod
    def _mask_response_url(payload: dict[str, Any], bsim_url: str) -> dict[str, Any]:
        result = dict(payload)
        result["bsim_url"] = mask_bsim_url(bsim_url)
        return result

    def get_database_status(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        return self._mask_response_url(self._java_backend.get_database_status(resolved), resolved)

    def get_bsim_database_status(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        return self.get_database_status(bsim_url=bsim_url)

    def list_categories(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        return self._mask_response_url(self._java_backend.list_categories(resolved), resolved)

    def list_bsim_categories(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        return self.list_categories(bsim_url=bsim_url)

    def list_executables(
        self,
        *,
        bsim_url: str | None = None,
        name: str | None = None,
        md5: str | None = None,
        arch: str | None = None,
        compiler: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._java_backend.list_executables(
            resolved,
            name=name,
            md5=md5,
            arch=arch,
            compiler=compiler,
            limit=limit,
        )
        return self._mask_response_url(result, resolved)

    def list_bsim_executables(
        self,
        *,
        bsim_url: str | None = None,
        name: str | None = None,
        md5: str | None = None,
        arch: str | None = None,
        compiler: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        return self.list_executables(
            bsim_url=bsim_url,
            name=name,
            md5=md5,
            arch=arch,
            compiler=compiler,
            limit=limit,
        )

    def get_executable(
        self,
        *,
        bsim_url: str | None = None,
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._java_backend.get_executable(resolved, md5=md5, name=name)
        return self._mask_response_url(result, resolved)

    def get_bsim_executable(
        self,
        *,
        bsim_url: str | None = None,
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        return self.get_executable(bsim_url=bsim_url, md5=md5, name=name)

    def query_target(
        self,
        target: str,
        *,
        bsim_url: str | None = None,
        similarity_threshold: float = 0.7,
        significance_threshold: float = 0.0,
        matches_per_function: int = 10,
        max_results: int = 500,
    ) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._core_command_service.call(
            "bsim_query_target",
            {
                "bsim_url": resolved,
                "query_target": target,
                "similarity_threshold": similarity_threshold,
                "significance_threshold": significance_threshold,
                "matches_per_function": matches_per_function,
                "max_results": max_results,
            },
            target,
        )
        return self._mask_response_url(result, resolved)

    def bsim_query_target(
        self,
        target: str,
        *,
        bsim_url: str | None = None,
        similarity_threshold: float = 0.7,
        significance_threshold: float = 0.0,
        matches_per_function: int = 10,
        max_results: int = 500,
    ) -> dict[str, Any]:
        return self.query_target(
            target,
            bsim_url=bsim_url,
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )

    def query_function(
        self,
        target: str,
        *,
        bsim_url: str | None = None,
        address: str | None = None,
        function_name: str | None = None,
        similarity_threshold: float = 0.7,
        significance_threshold: float = 0.0,
        matches_per_function: int = 10,
        max_results: int = 100,
    ) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._core_command_service.call(
            "bsim_query_function",
            {
                "bsim_url": resolved,
                "query_target": target,
                "address": address,
                "function_name": function_name,
                "similarity_threshold": similarity_threshold,
                "significance_threshold": significance_threshold,
                "matches_per_function": matches_per_function,
                "max_results": max_results,
            },
            target,
        )
        return self._mask_response_url(result, resolved)

    def bsim_query_function(
        self,
        target: str,
        *,
        bsim_url: str | None = None,
        address: str | None = None,
        function_name: str | None = None,
        similarity_threshold: float = 0.7,
        significance_threshold: float = 0.0,
        matches_per_function: int = 10,
        max_results: int = 100,
    ) -> dict[str, Any]:
        return self.query_function(
            target,
            bsim_url=bsim_url,
            address=address,
            function_name=function_name,
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )

    def set_target_metadata(self, target: str, *, categories: dict[str, object]) -> dict[str, Any]:
        return self._core_command_service.call(
            "bsim_set_target_metadata",
            {"categories": categories},
            target,
        )

    def register_target(self, target: str, *, bsim_url: str | None = None) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._core_command_service.call(
            "bsim_register_target",
            {"bsim_url": resolved, "query_target": target},
            target,
        )
        return self._mask_response_url(result, resolved)

    def bsim_register_target(self, target: str, *, bsim_url: str | None = None) -> dict[str, Any]:
        return self.register_target(target, bsim_url=bsim_url)

    def load_matched_executable(
        self,
        *,
        matched_ref: dict[str, object],
        target: str | None = None,
    ) -> dict[str, Any]:
        executable_md5 = self._text(matched_ref.get("executable_md5"))
        executable_name = self._text(matched_ref.get("executable_name"))
        domain_path = _normalize_domain_path(
            self._text(matched_ref.get("domain_path")) or self._text(matched_ref.get("path"))
        )
        if domain_path is None:
            raise ValueError("matched_ref.domain_path is required")
        matched_address = self._text(matched_ref.get("address"))
        matched_name = self._text(matched_ref.get("name"))

        requested_target = (target or "").strip() or _default_match_target(executable_md5, executable_name)
        existing = self._find_loaded_match_target(
            executable_md5=executable_md5,
            matched_ref=matched_ref,
            domain_path=domain_path,
            requested_target=requested_target,
        )
        if existing is not None:
            return {
                "status": "already_loaded",
                "target": existing["target"],
                "program": existing["program"],
                "matched_function_address": matched_address,
                "matched_function_name": matched_name,
                "executable_md5": executable_md5,
            }

        project_location = self._text(matched_ref.get("project_location"))
        project_name = self._text(matched_ref.get("project_name"))
        if not project_location:
            project_location, project_name = _project_from_ghidra_url(
                self._text(matched_ref.get("repository")) or self._text(matched_ref.get("ghidra_url"))
            )

        created = self._target_service.create_session(
            requested_target,
            project_location,
            project_name=project_name,
            domain_path=domain_path,
        )
        self._remember_loaded_match(
            target=requested_target,
            executable_md5=executable_md5,
            matched_ref=matched_ref,
            project_location=created.get("project_location") or project_location,
            project_name=created.get("project_name") or project_name,
            domain_path=domain_path,
        )
        return {
            "status": "loaded",
            "target": requested_target,
            "program": created.get("domain_path") or domain_path,
            "matched_function_address": matched_address,
            "matched_function_name": matched_name,
            "executable_md5": executable_md5,
        }

    def bsim_load_matched_executable(
        self,
        *,
        matched_ref: dict[str, object],
        target: str | None = None,
    ) -> dict[str, Any]:
        return self.load_matched_executable(matched_ref=matched_ref, target=target)

    @staticmethod
    def _text(value: object | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _remember_loaded_match(
        self,
        *,
        target: str,
        executable_md5: str | None,
        matched_ref: dict[str, object],
        project_location: str,
        project_name: str | None,
        domain_path: str,
    ) -> None:
        if executable_md5:
            self._loaded_match_index[f"md5:{executable_md5.lower()}"] = target
        identity = _project_identity(project_location, project_name)
        self._loaded_match_index[f"program:{identity[0]}::{identity[1]}::{domain_path}"] = target
        repository = self._text(matched_ref.get("repository")) or self._text(matched_ref.get("ghidra_url"))
        if repository:
            self._loaded_match_index[f"url:{repository}::{domain_path}"] = target

    def _find_loaded_match_target(
        self,
        *,
        executable_md5: str | None,
        matched_ref: dict[str, object],
        domain_path: str,
        requested_target: str,
    ) -> dict[str, str] | None:
        candidates: list[str] = [requested_target]
        if executable_md5:
            indexed = self._loaded_match_index.get(f"md5:{executable_md5.lower()}")
            if indexed:
                candidates.append(indexed)
        repository = self._text(matched_ref.get("repository")) or self._text(matched_ref.get("ghidra_url"))
        if repository:
            indexed = self._loaded_match_index.get(f"url:{repository}::{domain_path}")
            if indexed:
                candidates.append(indexed)

        targets = self._target_service.list_targets()
        by_name = {str(item.get("target")): item for item in targets if item.get("target") is not None}
        for candidate in candidates:
            info = by_name.get(candidate)
            if info is None:
                continue
            if _normalize_domain_path(self._text(info.get("domain_path"))) == domain_path:
                return {"target": candidate, "program": domain_path}

        project_location = self._text(matched_ref.get("project_location"))
        project_name = self._text(matched_ref.get("project_name"))
        if not project_location and repository:
            try:
                project_location, project_name = _project_from_ghidra_url(repository)
            except ValueError:
                project_location = None
                project_name = None
        if project_location:
            try:
                expected_identity = _project_identity(project_location, project_name)
            except ValueError:
                expected_identity = None
            if expected_identity is not None:
                for item in targets:
                    item_domain = _normalize_domain_path(self._text(item.get("domain_path")))
                    if item_domain != domain_path:
                        continue
                    item_project_location = self._text(item.get("project_location"))
                    if not item_project_location:
                        continue
                    try:
                        identity = _project_identity(
                            item_project_location,
                            self._text(item.get("project_name")),
                        )
                    except Exception:
                        continue
                    if identity == expected_identity:
                        return {"target": str(item["target"]), "program": domain_path}
        return None


__all__ = ["BsimConfig", "BsimService"]
