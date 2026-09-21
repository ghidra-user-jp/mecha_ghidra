# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=2.2.0,<3",
#     "pyghidra>=3.1.0",
#     "fasteners>=0.19",
#     "pydantic>=2.11,<3",
#     "regex>=2024.4.16",
#     "anyio>=4.5,<5",
#     "jsonschema>=4.20,<5",
#     "uvicorn>=0.31,<1",
# ]
#
# # Unreleased PyGhidra 3.2 snapshot with the script exception propagation fix
# # (ghidra#9288); mirrors [tool.uv.sources] in pyproject.toml.
# [tool.uv.sources]
# pyghidra = { url = "https://github.com/NationalSecurityAgency/ghidra/archive/263160cf57db21a9e25f1e0a8bc42fde5b8824eb.tar.gz", subdirectory = "Ghidra/Features/PyGhidra/src/main/py" }
# ///

from __future__ import annotations

import argparse
import functools
import logging
import os
import signal
import sys
import threading
import types
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Dict

import jpype

from ghidra_headless.launcher import start_headless_jvm
from ghidra_mcp.application.services.bsim_service import BsimConfig
from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.application.services.script_catalog import parse_root_argument
from ghidra_mcp.application.services.script_service import (
    ScriptConfig,
    ScriptService,
)
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
    DEFAULT_SCRIPT_QUEUE_TIMEOUT_SECONDS,
    configure_exclusive_checkout_default,
    configure_lock_timeout_seconds,
    configure_script_queue_timeout_seconds,
)
from ghidra_mcp.ghidra_installation import validate_linux_arm64_decompiler_install
from ghidra_mcp.presentation.cli_runtime import CLIRuntimeBundle, ServiceRegistryAdapter, create_cli_runtime
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
    run_mcp_server,
)
from ghidra_mcp.presentation.transport import (
    streamable_http_run_kwargs as _streamable_http_run_kwargs,
)

logger = logging.getLogger(__name__)

_ALL_TOOL_SPECS = get_all_tool_specs()
_DEFAULT_TOOL_SPECS = filter_tool_specs(specs=_ALL_TOOL_SPECS, profile=ToolProfile.DEFAULT)
_TOOL_NAMES = sorted(_ALL_TOOL_SPECS)
# Single source of truth for presentation defaults: the config dataclass.
_PRESENTATION_DEFAULTS = ToolPresentationConfig()
# Names of the tool callables an application exposes (``CLIApplication.tools``).
PUBLIC_TOOL_FUNCTIONS = tuple(_TOOL_NAMES)


@functools.cache
def _core():
    """The headless core handlers, imported once the JVM is up."""

    from ghidra_headless.handlers import core as core_module

    return core_module


@functools.cache
def _password_client_authenticator_class():
    return jpype.JClass("ghidra.framework.client.PasswordClientAuthenticator")


@functools.cache
def _client_util_class():
    return jpype.JClass("ghidra.framework.client.ClientUtil")


def bind_tools(
    registry_provider: Callable[[], Any],
    *,
    specs: dict[str, ToolSpec] | None = None,
    presentation_config: ToolPresentationConfig | None = None,
) -> types.SimpleNamespace:
    """Tool callables (``tools.list_functions(...)``) dispatching to the registry ``registry_provider`` returns.

    ``dispatch_tool`` is looked up on this module at call time so tests can replace it.
    """

    functions = build_tool_functions(
        specs=_ALL_TOOL_SPECS if specs is None else specs,
        dispatcher_provider=lambda: dispatch_tool,
        registry_provider=registry_provider,
        presentation_config=presentation_config,
    )
    return types.SimpleNamespace(**functions)


@dataclass(slots=True)
class CLIApplication:
    """One configured server: the runtime bundle and the tool callables bound to its registry.

    ``main()`` builds exactly one and passes it along; nothing about a running
    server lives in module state, so tests (and a second server in the same
    process) build their own.
    """

    bundle: CLIRuntimeBundle
    tools: types.SimpleNamespace

    @property
    def registry(self) -> ServiceRegistryAdapter:
        return self.bundle.registry

    @property
    def mcp(self) -> Any:
        return self.bundle.runtime.mcp

    @property
    def script_service(self) -> ScriptService:
        return self.bundle.script_service


def build_application(
    selected_specs: dict[str, ToolSpec] | None = None,
    *,
    bsim_config: BsimConfig | None = None,
    presentation_config: ToolPresentationConfig | None = None,
    path_policy: PathPolicy | None = None,
    script_config: ScriptConfig | None = None,
) -> CLIApplication:
    effective_specs = _DEFAULT_TOOL_SPECS if selected_specs is None else selected_specs
    bound: dict[str, Any] = {}

    def registry_provider() -> Any:
        return bound["registry"]

    runtime_kwargs: dict[str, Any] = {
        "registered_specs": effective_specs,
        "core_accessor": _core,
        "checkout_required_commands": get_checkout_required_tool_names(effective_specs),
        "bsim_config": BsimConfig() if bsim_config is None else bsim_config,
        "dispatcher_provider": lambda: dispatch_tool,
        "registry_provider": registry_provider,
    }
    if presentation_config is not None:
        runtime_kwargs["presentation_config"] = presentation_config
    if path_policy is not None:
        runtime_kwargs["path_policy"] = path_policy
    if script_config is not None:
        runtime_kwargs["script_config"] = script_config
    bundle = create_cli_runtime(**runtime_kwargs)
    bound["registry"] = bundle.registry
    return CLIApplication(bundle=bundle, tools=bind_tools(registry_provider, presentation_config=presentation_config))


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
        choices=["stdio", "http", "streamable-http"],
        help="MCP transport",
    )
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Streamable HTTP host (unused for stdio)")
    parser.add_argument("--mcp-port", type=int, help="Streamable HTTP port (unused for stdio)")
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
        "--result-cache-max-memory-bytes",
        type=int,
        default=_PRESENTATION_DEFAULTS.result_cache_max_memory_bytes,
        help="Maximum accounted memory of retained result strings, metadata and JSON indexes (not process RSS).",
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
        "--script-queue-timeout-seconds",
        type=float,
        default=DEFAULT_SCRIPT_QUEUE_TIMEOUT_SECONDS,
        help=(
            "How long run_script waits for in-flight operations to finish before the script starts. "
            "Other calls are held for at most about one second per queued script; a run that cannot "
            "start in time returns a retryable LOCK_TIMEOUT without executing."
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
    parser.add_argument(
        "--script-root",
        action="append",
        metavar="[LABEL=]DIR|bundled",
        help=(
            "Directory of operator-trusted Ghidra scripts (repeatable); the word 'bundled' adds Ghidra's own "
            "ghidra_scripts directories. Roots are copied into a private per-process snapshot at startup and "
            "scripts execute from that copy; script_id = '<LABEL>:<relative path>'. Inline source needs no root. "
            "Expose scripts through the tool profile / category flags. Scripts run with this process's OS privileges."
        ),
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args(argv)
    if args.lock_timeout_seconds <= 0:
        parser.error("--lock-timeout-seconds must be > 0")
    if args.script_queue_timeout_seconds <= 0:
        parser.error("--script-queue-timeout-seconds must be > 0")
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
        result_cache_max_memory_bytes=args.result_cache_max_memory_bytes,
    )


def path_policy_from_args(args) -> PathPolicy:
    return PathPolicy.from_roots(
        import_roots=getattr(args, "allowed_import_root", None),
        project_roots=getattr(args, "allowed_project_root", None),
        export_roots=getattr(args, "allowed_export_root", None),
    )


def script_config_from_args(args, ghidra_path: str | None) -> ScriptConfig:
    from pathlib import Path

    include_bundled = False
    roots = []
    for value in getattr(args, "script_root", None) or []:
        if value.strip().lower() == "bundled":
            include_bundled = True
            continue
        roots.append(parse_root_argument(value))
    return ScriptConfig(
        roots=tuple(roots),
        include_bundled=include_bundled,
        ghidra_install_dir=Path(ghidra_path) if ghidra_path else None,
    )


def _prepare_script_runtime(script_service: ScriptService | None) -> None:
    """After the JVM is up, verify exception propagation without patching upstream."""

    if script_service is None or not script_service.initialized:
        return
    from ghidra_headless.scripts import providers, runtime_check
    from ghidra_mcp.application.locks import SCRIPT_BARRIER

    if script_service.snapshot_base is None:
        return
    probe_dir = script_service.snapshot_base / "probe"
    with SCRIPT_BARRIER.write_lock():
        probe_ok = runtime_check.probe_exception_propagation(probe_dir)
    if not probe_ok:
        state = runtime_check.runtime_check_state()
        logger.error(
            "Script exception propagation probe failed (%s); all script runtimes are unavailable",
            state.get("probe_error"),
        )
        for runtime in providers.SUPPORTED_RUNTIMES:
            script_service.mark_runtime_unavailable(runtime, f"propagation_probe_failed:{state.get('probe_error')}")
    availability = providers.runtime_availability() if probe_ok else dict.fromkeys(providers.SUPPORTED_RUNTIMES, False)
    logger.info(
        "script runtimes: %s",
        ", ".join(f"{name}={'yes' if ok and probe_ok else 'no'}" for name, ok in availability.items()),
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
    java_system = jpype.JClass("java.lang.System")
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
    if not os.path.isdir(ghidra_path):
        raise RuntimeError(
            f"Ghidra installation directory does not exist: {ghidra_path} (check --ghidra-path / GHIDRA_INSTALL_DIR)"
        )
    validate_linux_arm64_decompiler_install(ghidra_path)


def _start_pyghidra_headless(ghidra_path: str | None) -> None:
    """Start the JVM through the shared headless launcher (see ghidra_headless.launcher)."""

    start_headless_jvm(ghidra_path)


def main(argv: list[str] | None = None) -> int:
    if threading.current_thread() is not threading.main_thread():
        return _run_cli(argv)

    def terminate(signum, _frame):
        # Uvicorn replays SIGTERM after graceful HTTP shutdown.  Raising here
        # also unwinds our project/script cleanup, including in stdio mode.
        raise SystemExit(128 + signum)

    previous_handler = signal.signal(signal.SIGTERM, terminate)
    try:
        return _run_cli(argv)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def _run_cli(argv: list[str] | None = None) -> int:
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
    configure_script_queue_timeout_seconds(args.script_queue_timeout_seconds)
    configure_exclusive_checkout_default(bool(args.shared_sync_exclusive_checkout))
    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    try:
        script_config = script_config_from_args(args, ghidra_path)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    bsim_remote_cache_dir = args.bsim_remote_cache_dir
    if bsim_remote_cache_dir:
        try:
            path_policy.validate_project_location(bsim_remote_cache_dir)
        except Exception as exc:
            logger.error("--bsim-remote-cache-dir is outside the allowed project roots: %s", exc)
            return 2
    app = build_application(
        selected_specs,
        bsim_config=BsimConfig(
            bsim_url=args.bsim_url,
            bsim_password=args.bsim_password,
            bsim_password_env=args.bsim_password_env,
            ghidra_install_dir=ghidra_path,
            remote_cache_dir=bsim_remote_cache_dir,
        ),
        presentation_config=presentation_config,
        path_policy=path_policy,
        script_config=script_config,
    )
    registry = app.registry
    script_service = app.script_service
    # The runtime owns no Ghidra resources until the JVM is up: closing it
    # earlier would import the core handlers (and fail) without a JVM and mask
    # the real startup error.
    jvm_started = False
    try:
        scripts_exposed = any(spec.category_tag == ToolCategoryTag.SCRIPTS for spec in selected_specs.values())
        if scripts_exposed:
            try:
                script_service.initialize()
            except Exception as exc:
                logger.error("script catalog initialization failed: %s", exc)
                return 2
            logger.warning(
                "scripts tools EXPOSED (%d catalog roots%s): scripts run with this process's OS privileges",
                len(script_config.roots),
                " + bundled" if script_config.include_bundled else "",
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
        try:
            _start_pyghidra_headless(ghidra_path or None)
        except Exception as exc:
            # A misconfigured installation is an operator error, not a crash:
            # one line and exit code 1, like every other startup failure.
            logger.error("Failed to start the Ghidra JVM: %s", exc)
            return 1
        jvm_started = True
        if transport == "stdio":
            redirect_java_stdout_to_stderr()
        try:
            _prepare_script_runtime(script_service)
        except Exception as exc:
            logger.error("Failed to prepare script runtimes: %s", exc)
            return 1

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
                return 1

        if not registry.has_targets():
            logger.error("Specify at least one target via --session or --project-location")
            return 1

        _core()  # import the headless core now that the JVM is up

        run_kwargs = _run_kwargs_for_transport(transport=transport, args=args, logger=logger)
        run_mcp_server(app.mcp, transport=transport, log_level=args.log_level, **run_kwargs)
    finally:
        try:
            if jvm_started:
                registry.close_all()
        finally:
            if script_service is not None:
                try:
                    script_service.shutdown()
                finally:
                    if script_service.enabled:
                        from ghidra_headless.scripts import providers

                        providers.shutdown()
    return 0


def configure_mcp_for_streamable_http(args) -> dict[str, Any]:
    """Return HTTP listener and public Server application options for ``args``."""
    return _streamable_http_run_kwargs(args=args, logger=logger)


if __name__ == "__main__":
    sys.exit(main())
