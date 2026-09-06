# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=2.1.1,<3",
#     "pyghidra>=2.0.0",
#     "fasteners>=0.19",
#     "pydantic>=2.11,<3",
#     "regex>=2024.4.16",
# ]
# ///

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any, Dict

import pyghidra.core as pycore
from mcp.server.mcpserver import MCPServer

from ghidra_headless.launcher import start_headless_jvm
from ghidra_mcp.application.services.bsim_service import BsimConfig
from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.contracts.tool_spec import (
    ToolCategoryTag,
    ToolOperationLevel,
    ToolProfile,
    ToolSafetyTag,
    ToolSpec,
    filter_tool_specs,
    get_all_tool_specs,
    get_checkout_required_tool_names,
)
from ghidra_mcp.domain import (
    DEFAULT_LOCK_TIMEOUT_SECONDS,
    configure_exclusive_checkout_default,
    configure_lock_timeout_seconds,
)
from ghidra_mcp.ghidra_installation import validate_linux_arm64_decompiler_install
from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter, create_cli_runtime
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import build_tool_functions
from ghidra_mcp.presentation.transport import (
    normalize_transport as _normalize_transport,
)
from ghidra_mcp.presentation.transport import (
    run_kwargs_for_transport as _run_kwargs_for_transport,
)
from ghidra_mcp.presentation.transport import (
    sse_run_kwargs as _sse_run_kwargs,
)
from ghidra_mcp.presentation.transport import (
    streamable_http_run_kwargs as _streamable_http_run_kwargs,
)

logger = logging.getLogger(__name__)

_core_module = None
_PASSWORD_CLIENT_AUTHENTICATOR_CLASS = None
_CLIENT_UTIL_CLASS = None
_registry = None
_bsim_config = BsimConfig()
mcp: MCPServer = MCPServer("GhidraMCP Headless")

_ALL_TOOL_SPECS = get_all_tool_specs()
_DEFAULT_TOOL_SPECS = filter_tool_specs(specs=_ALL_TOOL_SPECS, profile=ToolProfile.DEFAULT)
_TOOL_NAMES = sorted(_ALL_TOOL_SPECS)
# Single source of truth for presentation defaults: the config dataclass.
_PRESENTATION_DEFAULTS = ToolPresentationConfig()


def _core():
    global _core_module
    if _core_module is None:
        from ghidra_headless.handlers import core as core_module

        _core_module = core_module
    return _core_module


def _password_client_authenticator_class():
    global _PASSWORD_CLIENT_AUTHENTICATOR_CLASS
    if _PASSWORD_CLIENT_AUTHENTICATOR_CLASS is None:
        _PASSWORD_CLIENT_AUTHENTICATOR_CLASS = pycore.JClass("ghidra.framework.client.PasswordClientAuthenticator")
    return _PASSWORD_CLIENT_AUTHENTICATOR_CLASS


def _client_util_class():
    global _CLIENT_UTIL_CLASS
    if _CLIENT_UTIL_CLASS is None:
        _CLIENT_UTIL_CLASS = pycore.JClass("ghidra.framework.client.ClientUtil")
    return _CLIENT_UTIL_CLASS


def _get_registry(
    selected_specs: dict[str, ToolSpec] | None = None,
    bsim_config: BsimConfig | None = None,
    presentation_config: ToolPresentationConfig | None = None,
    server_log_level: str | None = None,
    path_policy: PathPolicy | None = None,
) -> ServiceRegistryAdapter:
    global _registry, _bsim_config, mcp
    if selected_specs is None and _registry is not None:
        return _registry
    if bsim_config is not None:
        _bsim_config = bsim_config
    effective_specs = _DEFAULT_TOOL_SPECS if selected_specs is None else selected_specs
    runtime_kwargs = {
        "registered_specs": effective_specs,
        "core_accessor": _core,
        "checkout_required_commands": get_checkout_required_tool_names(effective_specs),
        "bsim_config": _bsim_config,
        "dispatcher_provider": lambda: dispatch_tool,
        "registry_provider": lambda: _registry,
    }
    if presentation_config is not None:
        runtime_kwargs["presentation_config"] = presentation_config
    if server_log_level is not None:
        runtime_kwargs["server_log_level"] = server_log_level
    if path_policy is not None:
        runtime_kwargs["path_policy"] = path_policy
    bundle = create_cli_runtime(**runtime_kwargs)
    _registry = bundle.registry
    mcp = bundle.runtime.mcp
    return _registry


_PUBLIC_TOOL_FUNCTIONS = build_tool_functions(
    specs=_ALL_TOOL_SPECS,
    dispatcher_provider=lambda: dispatch_tool,
    registry_provider=_get_registry,
)
for _tool_name, _tool_fn in _PUBLIC_TOOL_FUNCTIONS.items():
    globals()[_tool_name] = _tool_fn


def configure_logging(level: int) -> None:
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def _parse_session_definition(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"Session definition is missing '=': {part}")
        key, value = part.split("=", 1)
        result[key.strip()] = value.strip()
    if "name" not in result:
        raise ValueError("Session definition requires name=...")
    if "project_location" not in result:
        raise ValueError("Session definition requires project_location")
    return result


def _enum_choices(enum_cls) -> list[str]:
    return [member.value for member in enum_cls]


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(description="PyGhidra-based Ghidra MCP server")
    parser.add_argument("--project-location", help="Ghidra project directory for the default session")
    parser.add_argument("--project-name", help="Project name for the default session")
    parser.add_argument("--domain-path", help="Domain path for the default session (e.g. /folder/program)")
    parser.add_argument("--target-name", default="default", help="Target name for the default session")
    parser.add_argument(
        "--session",
        action="append",
        metavar="name=...,project_location=...,domain_path=...",
        help="Additional session definitions as comma-separated key/value pairs (repeatable)",
    )
    parser.add_argument(
        "--ghidra-path",
        help="Ghidra installation path. If omitted, use GHIDRA_INSTALL_DIR.",
    )
    parser.add_argument(
        "--ghidra-server-user",
        help="Ghidra server username for shared-project connections",
    )
    parser.add_argument(
        "--ghidra-server-password",
        help="Ghidra server password for shared-project connections",
    )
    parser.add_argument(
        "--ghidra-server-password-env",
        help="Environment variable name holding the Ghidra server password",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "http", "streamable-http"],
        help="MCP transport",
    )
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="SSE/Streamable HTTP host (unused for stdio)")
    parser.add_argument("--mcp-port", type=int, help="SSE/Streamable HTTP port (unused for stdio)")
    parser.add_argument("--mcp-path", type=str, default="/mcp", help="Streamable HTTP path (e.g. /mcp)")
    parser.add_argument(
        "--bsim-url",
        help="Default BSim database URL used by BSim tools when bsim_url is omitted",
    )
    parser.add_argument(
        "--bsim-password",
        help="BSim database password. Prefer --bsim-password-env for persistent configurations.",
    )
    parser.add_argument(
        "--bsim-password-env",
        help="Environment variable name holding the BSim database password",
    )
    parser.add_argument(
        "--bsim-remote-cache-dir",
        metavar="DIR",
        help=(
            "Directory where bsim_load_matched_executable creates local caches of Ghidra Server "
            "repositories referenced by ghidra:// matches. Without it remote matches cannot be loaded. "
            "Must lie under an --allowed-project-root when project roots are restricted."
        ),
    )
    parser.add_argument(
        "--tool-profile",
        default=ToolProfile.DEFAULT.value,
        choices=_enum_choices(ToolProfile),
        help="Tool exposure profile. 'default' matches the no-argument startup behavior.",
    )
    parser.add_argument(
        "--allow-category",
        action="append",
        choices=_enum_choices(ToolCategoryTag),
        help="Replace the profile category set with the specified category (repeatable, OR within category).",
    )
    parser.add_argument(
        "--add-category",
        action="append",
        choices=_enum_choices(ToolCategoryTag),
        help="Add categories on top of the current profile/allow-category set (repeatable).",
    )
    parser.add_argument(
        "--allow-safety",
        action="append",
        choices=_enum_choices(ToolSafetyTag),
        help="Keep only tools with the specified safety tag (repeatable, OR within safety).",
    )
    parser.add_argument(
        "--allow-operation-level",
        action="append",
        choices=_enum_choices(ToolOperationLevel),
        help="Keep only tools with the specified operation level (repeatable, OR within operation level).",
    )
    parser.add_argument(
        "--enable-tool",
        action="append",
        choices=_TOOL_NAMES,
        help="Add a specific tool after tag/profile filtering (repeatable).",
    )
    parser.add_argument(
        "--disable-tool",
        action="append",
        choices=_TOOL_NAMES,
        help="Remove a specific tool after all other filtering. Highest priority (repeatable).",
    )
    parser.add_argument(
        "--tool-description-mode",
        default=_PRESENTATION_DEFAULTS.description_mode,
        choices=["short", "full", "none"],
        help=(
            "Control MCP tool description verbosity. 'short' prefers an explicit "
            "short_description and otherwise uses a bounded first-sentence fallback; "
            "'none' omits descriptions from tools/list."
        ),
    )
    parser.add_argument(
        "--large-result-mode",
        default=_PRESENTATION_DEFAULTS.large_result_mode,
        choices=["resource", "inline"],
        help=(
            "Use resource-backed compaction for eligible large results only when the "
            "complete response becomes smaller; 'inline' always returns full payloads."
        ),
    )
    parser.add_argument(
        "--large-result-threshold-chars",
        type=int,
        default=_PRESENTATION_DEFAULTS.large_result_threshold_chars,
        help=("Consider successful results above this character threshold for resource-backed compaction."),
    )
    parser.add_argument(
        "--large-result-preview-chars",
        type=int,
        default=_PRESENTATION_DEFAULTS.large_result_preview_chars,
        help=(
            "Initial preview character upper bound; the preview may be reduced to keep "
            "the complete compact response within its response budget."
        ),
    )
    parser.add_argument(
        "--result-cache-max-entries",
        type=int,
        default=_PRESENTATION_DEFAULTS.result_cache_max_entries,
        help="Maximum number of in-memory result resources retained by the MCP server.",
    )
    parser.add_argument(
        "--result-cache-max-bytes",
        type=int,
        default=_PRESENTATION_DEFAULTS.result_cache_max_bytes,
        help=(
            "Maximum accounted bytes for cached UTF-8 payloads plus retained metadata. "
            "An entry that cannot fit returns a successful result-unavailable notice "
            "without its full content when that notice is smaller; otherwise the inline "
            "result is preserved. Do not automatically retry side-effecting calls."
        ),
    )
    parser.add_argument(
        "--allowed-import-root",
        action="append",
        metavar="DIR",
        help=(
            "Restrict import_program to files under this directory (repeatable). "
            "Without it any file readable by the server process can be imported."
        ),
    )
    parser.add_argument(
        "--allowed-project-root",
        action="append",
        metavar="DIR",
        help=(
            "Restrict project creation and project opening to this directory (repeatable). "
            "Without it a Ghidra project can be created or opened anywhere the server can access."
        ),
    )
    parser.add_argument(
        "--allowed-export-root",
        action="append",
        metavar="DIR",
        help=(
            "Restrict export_program to output paths under this directory (repeatable). "
            "Without it a program can be written anywhere the server process can write."
        ),
    )
    parser.add_argument(
        "--lock-timeout-seconds",
        type=float,
        default=DEFAULT_LOCK_TIMEOUT_SECONDS,
        help=(
            "How long a tool call waits for a busy target/project before returning a "
            "retryable LOCK_TIMEOUT. Parallel tool calls queue up to this long."
        ),
    )
    parser.add_argument(
        "--shared-sync-exclusive-checkout",
        action="store_true",
        help=(
            "Make checkout_project_program (and commit_project_program's automatic checkout) request an "
            "exclusive checkout when the caller does not pass exclusive explicitly. Headless Ghidra cannot "
            "merge, so exclusive checkouts prevent the conflicts that would otherwise force a discard."
        ),
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args(argv)
    if args.lock_timeout_seconds <= 0:
        parser.error("--lock-timeout-seconds must be > 0")
    try:
        # Surface presentation-config range/cross-field errors as a standard
        # argparse usage error (exit 2) instead of an unhandled traceback.
        presentation_config_from_args(args)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def presentation_config_from_args(args) -> ToolPresentationConfig:
    return ToolPresentationConfig(
        description_mode=args.tool_description_mode,
        large_result_mode=args.large_result_mode,
        large_result_threshold_chars=args.large_result_threshold_chars,
        large_result_preview_chars=args.large_result_preview_chars,
        result_cache_max_entries=args.result_cache_max_entries,
        result_cache_max_bytes=args.result_cache_max_bytes,
    )


def path_policy_from_args(args) -> PathPolicy:
    return PathPolicy.from_roots(
        import_roots=getattr(args, "allowed_import_root", None),
        project_roots=getattr(args, "allowed_project_root", None),
        export_roots=getattr(args, "allowed_export_root", None),
    )


def resolve_tool_specs_from_args(args) -> dict[str, ToolSpec]:
    return filter_tool_specs(
        specs=_ALL_TOOL_SPECS,
        profile=args.tool_profile,
        allow_categories=args.allow_category,
        add_categories=args.add_category,
        allow_safety=args.allow_safety,
        allow_operation_levels=args.allow_operation_level,
        enable_tools=args.enable_tool,
        disable_tools=args.disable_tool,
    )


def redirect_java_stdout_to_stderr() -> None:
    """Keep the JVM's System.out off the MCP stdio channel.

    Ghidra components (analysis progress, log4j console appenders) write to
    ``System.out``, which is the same fd 1 the stdio transport uses for
    JSON-RPC framing.  Redirecting it to ``System.err`` keeps that output
    visible without corrupting the protocol stream.
    """
    java_system = pycore.JClass("java.lang.System")
    java_system.setOut(java_system.err)


def configure_ghidra_server_auth(args) -> None:
    username = (getattr(args, "ghidra_server_user", None) or "").strip()
    password_arg = getattr(args, "ghidra_server_password", None)
    password_env_name = (getattr(args, "ghidra_server_password_env", None) or "").strip()
    has_password_arg = password_arg is not None
    has_password_env = bool(password_env_name)
    if not username and not has_password_arg and not has_password_env:
        return
    if not username or not (has_password_arg or has_password_env):
        raise ValueError(
            "--ghidra-server-user and one of --ghidra-server-password/--ghidra-server-password-env must be set together"
        )
    if has_password_arg and has_password_env:
        raise ValueError("--ghidra-server-password and --ghidra-server-password-env cannot be used together")

    if has_password_arg:
        if password_arg == "":
            raise ValueError("--ghidra-server-password is empty")
        password = password_arg
        password_log_hint = "password=<provided>"  # noqa: S105 - log label, not a secret
    else:
        password = os.environ.get(password_env_name)
        if password is None:
            raise ValueError(f"Environment variable '{password_env_name}' is not set")
        if password == "":
            raise ValueError(f"Environment variable '{password_env_name}' is empty")
        password_log_hint = f"password_env={password_env_name}"

    authenticator = _password_client_authenticator_class()(username, password)
    _client_util_class().setClientAuthenticator(authenticator)
    logger.info(
        "Configured Ghidra server authentication (user=%s, %s)",
        username,
        password_log_hint,
    )


def _ensure_supported_ghidra_installation(ghidra_path: str | None) -> None:
    if not ghidra_path:
        return
    validate_linux_arm64_decompiler_install(ghidra_path)


def _start_pyghidra_headless(ghidra_path: str | None) -> None:
    """Start the JVM through the shared headless launcher (see ghidra_headless.launcher)."""

    start_headless_jvm(ghidra_path)


def main(argv: list[str] | None = None) -> int:
    global _core_module
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    configure_logging(getattr(logging, args.log_level.upper(), logging.INFO))

    selected_specs = resolve_tool_specs_from_args(args)
    presentation_config = presentation_config_from_args(args)
    try:
        path_policy = path_policy_from_args(args)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    configure_lock_timeout_seconds(args.lock_timeout_seconds)
    configure_exclusive_checkout_default(bool(args.shared_sync_exclusive_checkout))
    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    bsim_remote_cache_dir = args.bsim_remote_cache_dir
    if bsim_remote_cache_dir:
        try:
            path_policy.validate_project_location(bsim_remote_cache_dir)
        except Exception as exc:
            logger.error("--bsim-remote-cache-dir is outside the allowed project roots: %s", exc)
            return 2
    registry = _get_registry(
        selected_specs,
        bsim_config=BsimConfig(
            bsim_url=args.bsim_url,
            bsim_password=args.bsim_password,
            bsim_password_env=args.bsim_password_env,
            ghidra_install_dir=ghidra_path,
            remote_cache_dir=bsim_remote_cache_dir,
        ),
        presentation_config=presentation_config,
        server_log_level=args.log_level,
        path_policy=path_policy,
    )
    transport = _normalize_transport(args.transport)
    if transport != "stdio" and path_policy.is_unrestricted:
        logger.warning(
            "No --allowed-import-root/--allowed-project-root/--allowed-export-root configured: every MCP "
            "client on the %s transport can import any file readable by this process, open or create "
            "projects anywhere it can write, and export programs to any path. Configure the roots for "
            "network deployments.",
            transport,
        )

    logger.info(
        "Starting PyGhidra MCP server with %d tools (profile=%s)",
        len(selected_specs),
        args.tool_profile,
    )

    if ghidra_path:
        os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path
        try:
            _ensure_supported_ghidra_installation(ghidra_path)
        except RuntimeError as exc:
            logger.error("%s", exc)
            return 1
        logger.debug("pyghidra.start install_dir=%s", ghidra_path)
        _start_pyghidra_headless(ghidra_path)
    else:
        _start_pyghidra_headless(None)
    if transport == "stdio":
        redirect_java_stdout_to_stderr()

    try:
        configure_ghidra_server_auth(args)
    except Exception as exc:
        logger.error("Failed to configure Ghidra server authentication: %s", exc)
        return 1

    if args.session:
        for definition in args.session:
            try:
                config = _parse_session_definition(definition)
                domain_path = config.get("domain_path")
                if domain_path:
                    registry.create_session(
                        config["name"],
                        project_location=config["project_location"],
                        project_name=config.get("project_name"),
                        domain_path=domain_path,
                    )
                    logger.info("Loaded session '%s'", config["name"])
                else:
                    registry.register_target(
                        config["name"],
                        project_location=config["project_location"],
                        project_name=config.get("project_name"),
                    )
                    logger.info("Registered target '%s' with project metadata only", config["name"])
            except Exception as exc:
                logger.error("Error while processing session definition '%s': %s", definition, exc)
                registry.close_all()
                return 1

    if args.project_location:
        try:
            if args.domain_path:
                registry.create_session(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                    domain_path=args.domain_path,
                )
                logger.info("Loaded default target '%s'", args.target_name)
            else:
                registry.register_target(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                )
                logger.info(
                    "Registered default target '%s' with project metadata only (program not loaded)",
                    args.target_name,
                )
        except Exception as exc:
            logger.error("Failed to initialize default session: %s", exc)
            registry.close_all()
            return 1

    if not registry.has_targets():
        logger.error("Specify at least one target via --session or --project-location")
        return 1

    _core_module = _core()

    # SIGINT/SIGTERM are handled by the SDK's transport loop (uvicorn for the
    # HTTP transports, anyio for stdio); both unwind through the ``finally``
    # below, so no extra signal handler is installed here.
    run_kwargs = _run_kwargs_for_transport(transport=transport, args=args, logger=logger)
    try:
        mcp.run(transport=transport, **run_kwargs)
    finally:
        registry.close_all()
    return 0


def configure_mcp_for_sse(args) -> dict[str, Any]:
    """Return the ``MCPServer.run("sse", ...)`` keyword arguments for ``args``."""
    return _sse_run_kwargs(args=args, logger=logger)


def configure_mcp_for_streamable_http(args) -> dict[str, Any]:
    """Return the ``MCPServer.run("streamable-http", ...)`` keyword arguments for ``args``."""
    return _streamable_http_run_kwargs(args=args, logger=logger)


# expose generated tool callables to static analysis/tests
PUBLIC_TOOL_FUNCTIONS = tuple(name for name in _PUBLIC_TOOL_FUNCTIONS)

if __name__ == "__main__":
    sys.exit(main())
