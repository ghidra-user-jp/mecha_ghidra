# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.26.0,<2",
#     "pyghidra>=2.0.0",
#     "fasteners>=0.19",
# ]
# ///

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from typing import Dict

import pyghidra
import pyghidra.core as pycore
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from ghidra_mcp.application.services.bsim_service import BsimConfig
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
from ghidra_mcp.ghidra_installation import validate_linux_arm64_decompiler_install
from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter, create_cli_runtime
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.tool_registry import build_tool_functions
from ghidra_mcp.presentation.transport import (
    configure_mcp_for_sse as _configure_mcp_for_sse,
    configure_mcp_for_streamable_http as _configure_mcp_for_streamable_http,
    configure_transport_security_for_host as _configure_transport_security_for_host_impl,
    normalize_host as _normalize_host_impl,
    normalize_streamable_http_path as _normalize_streamable_http_path_impl,
    normalize_transport as _normalize_transport_impl,
    resolve_transport_security_for_host as _resolve_transport_security_for_host_impl,
)
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool

logger = logging.getLogger(__name__)

_core_module = None
_PASSWORD_CLIENT_AUTHENTICATOR_CLASS = None
_CLIENT_UTIL_CLASS = None
_registry = None
_bsim_config = BsimConfig()
mcp = FastMCP("GhidraMCP Headless")

_ALL_TOOL_SPECS = get_all_tool_specs()
_DEFAULT_TOOL_SPECS = filter_tool_specs(specs=_ALL_TOOL_SPECS, profile=ToolProfile.DEFAULT)
_TOOL_NAMES = sorted(_ALL_TOOL_SPECS)


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
) -> ServiceRegistryAdapter:
    global _registry, _bsim_config, mcp
    if selected_specs is None and _registry is not None:
        return _registry
    if bsim_config is not None:
        _bsim_config = bsim_config
    effective_specs = _DEFAULT_TOOL_SPECS if selected_specs is None else selected_specs
    runtime_kwargs = {
        "registered_specs": effective_specs,
        "core_accessor": lambda: _core(),
        "checkout_required_commands": get_checkout_required_tool_names(effective_specs),
        "bsim_config": _bsim_config,
        "dispatcher_provider": lambda: dispatch_tool,
        "registry_provider": lambda: _registry,
    }
    if presentation_config is not None:
        runtime_kwargs["presentation_config"] = presentation_config
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
    for part in text.split(","):
        part = part.strip()
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
        default="full",
        choices=["short", "full", "none"],
        help=(
            "Control MCP tool description verbosity. Existing descriptions are already "
            "terse, so 'full' is the default; 'short' only helps once specs carry "
            "long descriptions with short_description overrides."
        ),
    )
    parser.add_argument(
        "--large-result-mode",
        default="resource",
        choices=["resource", "inline"],
        help="Return large tool results as MCP resources or inline payloads.",
    )
    parser.add_argument(
        "--large-result-threshold-chars",
        type=int,
        default=12000,
        help="Character threshold for moving large tool results to MCP resources.",
    )
    parser.add_argument(
        "--large-result-preview-chars",
        type=int,
        default=4000,
        help="Preview character count for resource-backed large tool results.",
    )
    parser.add_argument(
        "--result-cache-max-entries",
        type=int,
        default=512,
        help="Maximum in-memory result resources retained by the MCP server.",
    )
    parser.add_argument(
        "--result-cache-max-bytes",
        type=int,
        default=134217728,
        help="Maximum total bytes of in-memory result resources retained by the MCP server.",
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args(argv)
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


def _normalize_transport(transport: str) -> str:
    return _normalize_transport_impl(transport)


def _normalize_streamable_http_path(path: str) -> str:
    return _normalize_streamable_http_path_impl(path)


def _normalize_host(host: str) -> str:
    return _normalize_host_impl(host)


def _resolve_transport_security_for_host(host: str) -> TransportSecuritySettings:
    return _resolve_transport_security_for_host_impl(host)


def _configure_transport_security_for_host(host: str) -> None:
    _configure_transport_security_for_host_impl(mcp=mcp, host=host, logger=logger)


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
            "--ghidra-server-user and one of --ghidra-server-password/--ghidra-server-password-env "
            "must be set together"
        )
    if has_password_arg and has_password_env:
        raise ValueError("--ghidra-server-password and --ghidra-server-password-env cannot be used together")

    if has_password_arg:
        if password_arg == "":
            raise ValueError("--ghidra-server-password is empty")
        password = password_arg
        password_log_hint = "password=<provided>"
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


def main(argv: list[str] | None = None) -> int:
    global _core_module
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    configure_logging(getattr(logging, args.log_level.upper(), logging.INFO))

    selected_specs = resolve_tool_specs_from_args(args)
    presentation_config = presentation_config_from_args(args)
    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    registry = _get_registry(
        selected_specs,
        bsim_config=BsimConfig(
            bsim_url=args.bsim_url,
            bsim_password=args.bsim_password,
            bsim_password_env=args.bsim_password_env,
            ghidra_install_dir=ghidra_path,
        ),
        presentation_config=presentation_config,
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
        pyghidra.start(install_dir=ghidra_path)
    else:
        pyghidra.start()

    try:
        configure_ghidra_server_auth(args)
    except Exception as exc:  # noqa: BLE001
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
            except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize default session: %s", exc)
            registry.close_all()
            return 1

    if not registry.has_targets():
        logger.error("Specify at least one target via --session or --project-location")
        return 1

    _core_module = _core()

    def _shutdown_handler(signum, frame):
        logger.info("Received signal %s; starting shutdown", signum)
        registry.close_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    transport = _normalize_transport(args.transport)
    if transport == "sse":
        configure_mcp_for_sse(args)
    elif transport == "streamable-http":
        configure_mcp_for_streamable_http(args)

    try:
        mcp.run(transport=transport)
    finally:
        registry.close_all()
    return 0


def configure_mcp_for_sse(args) -> None:
    _configure_mcp_for_sse(mcp=mcp, args=args, logger=logger)


def configure_mcp_for_streamable_http(args) -> None:
    _configure_mcp_for_streamable_http(mcp=mcp, args=args, logger=logger)


# expose generated tool callables to static analysis/tests
PUBLIC_TOOL_FUNCTIONS = tuple(name for name in _PUBLIC_TOOL_FUNCTIONS)

if __name__ == "__main__":
    sys.exit(main())
