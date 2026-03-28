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
from mcp.server.transport_security import TransportSecuritySettings

from ghidra_mcp.ghidra_installation import validate_linux_arm64_decompiler_install
from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter, create_cli_runtime
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
_shared_project_sync_tools_registered = False
_PASSWORD_CLIENT_AUTHENTICATOR_CLASS = None
_CLIENT_UTIL_CLASS = None

_CHECKOUT_REQUIRED_COMMANDS = {
    "rename_function",
    "rename_function_by_address",
    "rename_data",
    "rename_variable",
    "set_decompiler_comment",
    "set_disassembly_comment",
    "set_function_prototype",
    "set_local_variable_type",
    "set_global_data_type",
    "create_struct",
    "create_class",
    "add_struct_members",
    "clear_struct",
    "create_enum",
    "add_enum_values",
    "add_class_members",
    "remove_class_members",
    "remove_enum_values",
    "remove_struct_members",
    "set_bytes",
    "add_bookmark",
}

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


_runtime_bundle = create_cli_runtime(
    core_accessor=lambda: _core(),
    checkout_required_commands=set(_CHECKOUT_REQUIRED_COMMANDS),
    dispatcher_provider=lambda: dispatch_tool,
    registry_provider=lambda: _registry,
)
_registry = _runtime_bundle.registry
_runtime = _runtime_bundle.runtime
mcp = _runtime.mcp

for _tool_name, _tool_fn in _runtime.tools.items():
    globals()[_tool_name] = _tool_fn


def register_shared_project_sync_tools() -> None:
    global _shared_project_sync_tools_registered
    if _shared_project_sync_tools_registered:
        return
    _runtime.register_shared_sync()
    _shared_project_sync_tools_registered = True


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
        "--enable-shared-project-sync",
        action="store_true",
        help="Expose shared-project commit/pull/checkout tools",
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")
    return parser.parse_args(argv)


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
    password_env_name = (getattr(args, "ghidra_server_password_env", None) or "").strip()
    if not username and not password_env_name:
        return
    if not username or not password_env_name:
        raise ValueError("--ghidra-server-user and --ghidra-server-password-env must be set together")

    password = os.environ.get(password_env_name)
    if password is None:
        raise ValueError(f"Environment variable '{password_env_name}' is not set")
    if password == "":
        raise ValueError(f"Environment variable '{password_env_name}' is empty")

    authenticator = _password_client_authenticator_class()(username, password)
    _client_util_class().setClientAuthenticator(authenticator)
    logger.info(
        "Configured Ghidra server authentication (user=%s, password_env=%s)",
        username,
        password_env_name,
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
    logger.info("Starting PyGhidra MCP server")

    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
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
                    _registry.create_session(
                        config["name"],
                        project_location=config.get("project_location"),
                        project_name=config.get("project_name"),
                        domain_path=domain_path,
                    )
                    logger.info("Loaded session '%s'", config["name"])
                else:
                    _registry.register_target(
                        config["name"],
                        project_location=config.get("project_location"),
                        project_name=config.get("project_name"),
                    )
                    logger.info("Registered target '%s' with project metadata only", config["name"])
            except Exception as exc:  # noqa: BLE001
                logger.error("Error while processing session definition '%s': %s", definition, exc)
                _registry.close_all()
                return 1

    if args.project_location:
        try:
            if args.domain_path:
                _registry.create_session(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                    domain_path=args.domain_path,
                )
                logger.info("Loaded default target '%s'", args.target_name)
            else:
                _registry.register_target(
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
            _registry.close_all()
            return 1

    if not _registry.has_targets():
        logger.error("Specify at least one target via --session or --project-location")
        return 1

    _core_module = _core()

    def _shutdown_handler(signum, frame):
        logger.info("Received signal %s; starting shutdown", signum)
        _registry.close_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    if args.enable_shared_project_sync:
        register_shared_project_sync_tools()
        logger.info("Enabled shared-project sync tools")

    transport = _normalize_transport(args.transport)
    if transport == "sse":
        configure_mcp_for_sse(args)
    elif transport == "streamable-http":
        configure_mcp_for_streamable_http(args)

    try:
        mcp.run(transport=transport)
    finally:
        _registry.close_all()
    return 0


def configure_mcp_for_sse(args) -> None:
    _configure_mcp_for_sse(mcp=mcp, args=args, logger=logger)


def configure_mcp_for_streamable_http(args) -> None:
    _configure_mcp_for_streamable_http(mcp=mcp, args=args, logger=logger)


# expose generated tool callables to static analysis/tests
PUBLIC_TOOL_FUNCTIONS = tuple(name for name in _runtime.tools)

if __name__ == "__main__":
    sys.exit(main())
