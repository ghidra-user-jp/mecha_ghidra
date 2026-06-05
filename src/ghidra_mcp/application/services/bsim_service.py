"""Application service for BSim MCP tools."""

from __future__ import annotations

import getpass
import math
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Callable, NoReturn, TypeVar
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from ghidra_mcp.infrastructure.bsim import BsimJavaBackend, mask_bsim_url

from .core_command_service import CoreCommandService
from .target_service import TargetService


BSIM_MATCHED_REF_VERSION = 1
_BSIM_CODE_RE = re.compile(r"^BSIM_[A-Z0-9_]+(?::|$)")
_BSIM_SUPPORTED_URL_SCHEMES = frozenset({"postgresql", "elastic", "https", "file"})
_MAX_BSIM_LIST_LIMIT = 10_000
_MAX_BSIM_MATCHES_PER_FUNCTION = 1_000
_MAX_BSIM_QUERY_RESULTS = 10_000
_T = TypeVar("_T")


@dataclass(frozen=True)
class BsimConfig:
    bsim_url: str | None = None
    bsim_password: str | None = None
    bsim_password_env: str | None = None
    work_dir: str | None = None
    command_timeout: int = 300
    ghidra_install_dir: str | None = None


@dataclass(frozen=True)
class _MatchedRef:
    raw: dict[str, object]
    executable_md5: str
    executable_name: str
    domain_path: str
    address: str
    name: str
    project_location: str | None
    project_name: str | None
    repository: str | None
    ghidra_url: str | None


def _bsim_message(code: str, message: str) -> str:
    text = str(message).strip() or "unknown error"
    if _BSIM_CODE_RE.match(text):
        return text
    return f"{code}: {text}"


def _classify_bsim_message(message: str, *, default_code: str = "BSIM_OPERATION_FAILED") -> str:
    text = str(message).strip() or "unknown error"
    lower = text.lower()
    has_specific_code = _BSIM_CODE_RE.match(text) and not text.startswith(
        ("BSIM_DATABASE_INIT_FAILED:", "BSIM_QUERY_FAILED:", "BSIM_CLI_FAILED:")
    )
    if has_specific_code:
        return text
    if "function not found" in lower:
        return _bsim_message("BSIM_FUNCTION_NOT_FOUND", text)
    if "password" in lower or "authentication" in lower or "auth failed" in lower:
        return _bsim_message("BSIM_AUTHENTICATION_FAILED", text)
    if (
        "connection refused" in lower
        or "could not connect" in lower
        or "timed out" in lower
        or "timeout" in lower
        or "unknown host" in lower
        or "unreachable" in lower
    ):
        return _bsim_message("BSIM_DATABASE_UNREACHABLE", text)
    return _bsim_message(default_code, text)


def _raise_classified_bsim_error(exc: Exception, *, default_code: str = "BSIM_OPERATION_FAILED") -> NoReturn:
    message = _classify_bsim_message(str(exc), default_code=default_code)
    if message.startswith("BSIM_FUNCTION_NOT_FOUND:"):
        raise LookupError(message) from exc
    if isinstance(exc, ValueError):
        raise ValueError(message) from exc
    raise RuntimeError(message) from exc


def _resolve_config_password(config: BsimConfig) -> str | None:
    env_name = (config.bsim_password_env or "").strip()
    has_password = config.bsim_password is not None
    if has_password and env_name:
        raise ValueError(
            "BSIM_PASSWORD_CONFIG_INVALID: --bsim-password and --bsim-password-env cannot be used together"
        )
    if has_password:
        if config.bsim_password == "":
            raise ValueError("BSIM_PASSWORD_CONFIG_INVALID: --bsim-password is empty")
        return config.bsim_password
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None:
        raise ValueError(f"BSIM_PASSWORD_CONFIG_INVALID: Environment variable '{env_name}' is not set")
    if value == "":
        raise ValueError(f"BSIM_PASSWORD_CONFIG_INVALID: Environment variable '{env_name}' is empty")
    return value


def _hostport(parts) -> str:
    hostname = parts.hostname
    if not hostname:
        raise ValueError("BSIM_URL_INVALID: --bsim-password requires bsim_url with a hostname")
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
        raise ValueError(
            "BSIM_URL_INVALID: --bsim-password requires a network BSim URL such as "
            "postgresql://user@host/database"
        )
    if parts.password is not None:
        raise ValueError(
            "BSIM_PASSWORD_CONFIG_INVALID: bsim_url already contains a password; "
            "use either bsim_url credentials or --bsim-password"
        )

    username = unquote(parts.username or "") or getpass.getuser()
    userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
    return urlunsplit((parts.scheme, f"{userinfo}@{_hostport(parts)}", parts.path, parts.query, parts.fragment))


def _validate_bsim_url(bsim_url: str) -> str:
    parts = urlsplit(bsim_url)
    scheme = parts.scheme.lower()
    if not scheme:
        raise ValueError(
            "BSIM_URL_INVALID: bsim_url requires a scheme "
            "(supported: postgresql://, elastic://, https://, file:)"
        )
    if scheme not in _BSIM_SUPPORTED_URL_SCHEMES:
        supported = ", ".join(sorted(_BSIM_SUPPORTED_URL_SCHEMES))
        raise ValueError(f"BSIM_URL_INVALID: unsupported BSim URL scheme '{parts.scheme}' (supported: {supported})")
    if scheme in {"postgresql", "elastic", "https"} and not parts.netloc:
        raise ValueError(f"BSIM_URL_INVALID: {scheme} BSim URL requires a host")
    if scheme in {"postgresql", "elastic", "https"}:
        path = parts.path.strip("/")
        if not path:
            raise ValueError(f"BSIM_URL_INVALID: {scheme} BSim URL requires a database name")
        if "/" in path:
            raise ValueError(f"BSIM_URL_INVALID: {scheme} BSim URL database name must be one path element")
    if scheme == "file":
        path = parts.path
        normalized_path = path.replace("\\", "/")
        if parts.netloc:
            raise ValueError("BSIM_URL_INVALID: remote file BSim URL is not supported")
        if not path.strip("/"):
            raise ValueError("BSIM_URL_INVALID: file BSim URL requires a database path")
        if any(char in path for char in "';\""):
            raise ValueError("BSIM_URL_INVALID: file BSim URL contains an unsupported path character")
        if normalized_path.endswith("/") or not (
            normalized_path.startswith("/") or re.match(r"^[A-Za-z]:/", normalized_path)
        ):
            raise ValueError("BSIM_URL_INVALID: file BSim URL requires an absolute database path")
    return bsim_url


def _validate_float_range(value: float, *, name: str, minimum: float, maximum: float | None = None) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be a number") from exc
    if not math.isfinite(number):
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be finite")
    if number < minimum:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be >= {minimum:g}")
    if maximum is not None and number > maximum:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be <= {maximum:g}")
    return number


def _validate_positive_int(value: int, *, name: str, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be an integer") from exc
    if number < 1:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be >= 1")
    if number > maximum:
        raise ValueError(f"BSIM_PARAMETER_INVALID: {name} must be <= {maximum}")
    return number


def _validate_query_parameters(
    *,
    similarity_threshold: float,
    significance_threshold: float,
    matches_per_function: int,
    max_results: int,
) -> tuple[float, float, int, int]:
    return (
        _validate_float_range(
            similarity_threshold,
            name="similarity_threshold",
            minimum=0.0,
            maximum=1.0,
        ),
        _validate_float_range(significance_threshold, name="significance_threshold", minimum=0.0),
        _validate_positive_int(
            matches_per_function,
            name="matches_per_function",
            maximum=_MAX_BSIM_MATCHES_PER_FUNCTION,
        ),
        _validate_positive_int(max_results, name="max_results", maximum=_MAX_BSIM_QUERY_RESULTS),
    )


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
        raise ValueError("BSIM_INVALID_MATCHED_REF: matched_ref requires repository or ghidra_url")
    parts = urlsplit(str(url))
    if parts.scheme != "ghidra":
        raise ValueError(f"BSIM_INVALID_MATCHED_REF: unsupported BSim ghidra URL: {url}")
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


def _validate_matched_ref(matched_ref: dict[str, object]) -> _MatchedRef:
    if not isinstance(matched_ref, dict):
        raise ValueError("BSIM_INVALID_MATCHED_REF: matched_ref must be an object")

    raw_version = matched_ref.get("matched_ref_version")
    try:
        version = int(str(raw_version))
    except (TypeError, ValueError):
        version = None
    if version != BSIM_MATCHED_REF_VERSION:
        raise ValueError(
            "BSIM_INVALID_MATCHED_REF: matched_ref.matched_ref_version must be "
            f"{BSIM_MATCHED_REF_VERSION}"
        )

    def _field(name: str) -> str | None:
        return BsimService._text(matched_ref.get(name))

    executable_md5 = _field("executable_md5")
    executable_name = _field("executable_name")
    domain_path = _normalize_domain_path(_field("domain_path") or _field("path"))
    address = _field("address")
    name = _field("name")
    project_location = _field("project_location")
    project_name = _field("project_name")
    repository = _field("repository")
    ghidra_url = _field("ghidra_url")

    missing = [
        key
        for key, value in (
            ("executable_md5", executable_md5),
            ("executable_name", executable_name),
            ("domain_path", domain_path),
            ("address", address),
            ("name", name),
        )
        if value is None
    ]
    if missing:
        raise ValueError("BSIM_INVALID_MATCHED_REF: missing required keys: " + ", ".join(missing))
    if not project_location and not repository and not ghidra_url:
        raise ValueError(
            "BSIM_INVALID_MATCHED_REF: matched_ref requires project_location, repository, or ghidra_url"
        )

    return _MatchedRef(
        raw=matched_ref,
        executable_md5=executable_md5,
        executable_name=executable_name,
        domain_path=domain_path,
        address=address,
        name=name,
        project_location=project_location,
        project_name=project_name,
        repository=repository,
        ghidra_url=ghidra_url,
    )


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
            raise ValueError("BSIM_URL_REQUIRED: set --bsim-url or pass bsim_url")
        _validate_bsim_url(resolved)
        return _validate_bsim_url(_bsim_url_with_password(resolved, _resolve_config_password(self._config)))

    @staticmethod
    def _mask_response_url(payload: dict[str, Any], bsim_url: str) -> dict[str, Any]:
        result = dict(payload)
        result["bsim_url"] = mask_bsim_url(bsim_url)
        return result

    @staticmethod
    def _add_query_provenance(
        payload: dict[str, Any],
        *,
        scope: str,
        target: str,
        masked_bsim_url: str | None,
        similarity_threshold: float,
        significance_threshold: float,
        matches_per_function: int,
        max_results: int,
        address: str | None = None,
        function_name: str | None = None,
    ) -> dict[str, Any]:
        result = dict(payload)
        query: dict[str, Any] = {
            "scope": scope,
            "target": target,
            "program": result.get("program"),
            "bsim_url": masked_bsim_url,
            "similarity_threshold": float(similarity_threshold),
            "significance_threshold": float(significance_threshold),
            "matches_per_function": int(matches_per_function),
            "max_results": int(max_results),
        }
        if address is not None:
            query["address"] = address
        if function_name is not None:
            query["function_name"] = function_name
        result["query"] = query
        return result

    @staticmethod
    def _call_bsim(operation: Callable[[], _T], *, default_code: str = "BSIM_OPERATION_FAILED") -> _T:
        try:
            return operation()
        except Exception as exc:
            _raise_classified_bsim_error(exc, default_code=default_code)

    def _ghidra_install_dir(self) -> str | None:
        configured = self._text(self._config.ghidra_install_dir) or self._text(os.environ.get("GHIDRA_INSTALL_DIR"))
        if configured is None:
            return None
        return str(pathlib.Path(configured).expanduser())

    def get_database_status(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._call_bsim(
            lambda: self._java_backend.get_database_status(resolved),
            default_code="BSIM_DATABASE_STATUS_FAILED",
        )
        masked = self._mask_response_url(result, resolved)
        masked["ghidra_install_dir"] = self._ghidra_install_dir()
        masked["ghidra_version"] = self._call_bsim(
            self._java_backend.get_ghidra_version,
            default_code="BSIM_GHIDRA_VERSION_FAILED",
        )
        return masked

    def get_bsim_database_status(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        return self.get_database_status(bsim_url=bsim_url)

    def list_categories(self, *, bsim_url: str | None = None) -> dict[str, Any]:
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._call_bsim(
            lambda: self._java_backend.list_categories(resolved),
            default_code="BSIM_LIST_CATEGORIES_FAILED",
        )
        return self._mask_response_url(result, resolved)

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
        limit = _validate_positive_int(limit, name="limit", maximum=_MAX_BSIM_LIST_LIMIT)
        result = self._call_bsim(
            lambda: self._java_backend.list_executables(
                resolved,
                name=name,
                md5=md5,
                arch=arch,
                compiler=compiler,
                limit=limit,
            ),
            default_code="BSIM_LIST_EXECUTABLES_FAILED",
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
        result = self._call_bsim(
            lambda: self._java_backend.get_executable(resolved, md5=md5, name=name),
            default_code="BSIM_GET_EXECUTABLE_FAILED",
        )
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
        (
            similarity_threshold,
            significance_threshold,
            matches_per_function,
            max_results,
        ) = _validate_query_parameters(
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._call_bsim(
            lambda: self._core_command_service.call(
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
            ),
            default_code="BSIM_QUERY_FAILED",
        )
        masked = self._mask_response_url(result, resolved)
        return self._add_query_provenance(
            masked,
            scope="target",
            target=target,
            masked_bsim_url=masked.get("bsim_url"),
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )

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
        (
            similarity_threshold,
            significance_threshold,
            matches_per_function,
            max_results,
        ) = _validate_query_parameters(
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )
        resolved = self._resolve_bsim_url(bsim_url)
        result = self._call_bsim(
            lambda: self._core_command_service.call(
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
            ),
            default_code="BSIM_QUERY_FAILED",
        )
        masked = self._mask_response_url(result, resolved)
        return self._add_query_provenance(
            masked,
            scope="function",
            target=target,
            masked_bsim_url=masked.get("bsim_url"),
            address=address,
            function_name=function_name,
            similarity_threshold=similarity_threshold,
            significance_threshold=significance_threshold,
            matches_per_function=matches_per_function,
            max_results=max_results,
        )

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
        result = self._call_bsim(
            lambda: self._core_command_service.call(
                "bsim_register_target",
                {"bsim_url": resolved, "query_target": target},
                target,
            ),
            default_code="BSIM_REGISTER_FAILED",
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
        ref = _validate_matched_ref(matched_ref)
        executable_md5 = ref.executable_md5
        executable_name = ref.executable_name
        domain_path = ref.domain_path
        matched_address = ref.address
        matched_name = ref.name

        requested_target = (target or "").strip() or _default_match_target(executable_md5, executable_name)
        existing = self._find_loaded_match_target(
            executable_md5=executable_md5,
            matched_ref=ref.raw,
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
                "matched_ref_version": BSIM_MATCHED_REF_VERSION,
            }

        project_location = ref.project_location
        project_name = ref.project_name
        if not project_location:
            project_location, project_name = _project_from_ghidra_url(
                ref.repository or ref.ghidra_url
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
            matched_ref=ref.raw,
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
            "matched_ref_version": BSIM_MATCHED_REF_VERSION,
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

    def _matched_ref_project_identity(self, matched_ref: dict[str, object]) -> tuple[str, str] | None:
        project_location = self._text(matched_ref.get("project_location"))
        project_name = self._text(matched_ref.get("project_name"))
        repository = self._text(matched_ref.get("repository")) or self._text(matched_ref.get("ghidra_url"))
        if not project_location and repository:
            try:
                project_location, project_name = _project_from_ghidra_url(repository)
            except ValueError:
                return None
        if not project_location:
            return None
        try:
            return _project_identity(project_location, project_name)
        except ValueError:
            return None

    def _target_matches_ref(
        self,
        item: dict[str, object],
        *,
        domain_path: str,
        expected_identity: tuple[str, str] | None,
    ) -> bool:
        item_domain = _normalize_domain_path(self._text(item.get("domain_path")))
        if item_domain != domain_path or expected_identity is None:
            return False
        item_project_location = self._text(item.get("project_location"))
        if not item_project_location:
            return False
        try:
            identity = _project_identity(
                item_project_location,
                self._text(item.get("project_name")),
            )
        except Exception:
            return False
        return identity == expected_identity

    def _find_loaded_match_target(
        self,
        *,
        executable_md5: str | None,
        matched_ref: dict[str, object],
        domain_path: str,
        requested_target: str,
    ) -> dict[str, str] | None:
        candidates: list[str] = []
        seen_candidates: set[str] = set()

        def _add_candidate(candidate: str | None) -> None:
            if candidate and candidate not in seen_candidates:
                candidates.append(candidate)
                seen_candidates.add(candidate)

        expected_identity = self._matched_ref_project_identity(matched_ref)
        _add_candidate(requested_target)
        if executable_md5:
            indexed = self._loaded_match_index.get(f"md5:{executable_md5.lower()}")
            _add_candidate(indexed)
        repository = self._text(matched_ref.get("repository")) or self._text(matched_ref.get("ghidra_url"))
        if repository:
            indexed = self._loaded_match_index.get(f"url:{repository}::{domain_path}")
            _add_candidate(indexed)
        if expected_identity is not None:
            indexed = self._loaded_match_index.get(
                f"program:{expected_identity[0]}::{expected_identity[1]}::{domain_path}"
            )
            _add_candidate(indexed)

        targets = self._target_service.list_targets()
        by_name = {str(item.get("target")): item for item in targets if item.get("target") is not None}
        for candidate in candidates:
            info = by_name.get(candidate)
            if info is None:
                continue
            if self._target_matches_ref(info, domain_path=domain_path, expected_identity=expected_identity):
                return {"target": candidate, "program": domain_path}

        for item in targets:
            if self._target_matches_ref(item, domain_path=domain_path, expected_identity=expected_identity):
                return {"target": str(item["target"]), "program": domain_path}
        return None


__all__ = ["BsimConfig", "BsimService"]
