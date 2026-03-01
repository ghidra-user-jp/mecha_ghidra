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
from typing import Any, Dict

import pyghidra
import pyghidra.core as pycore
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent

from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.application.services.sync_service import SyncService
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.infrastructure import CoreGateway, LockManager, RuntimeBackend
from ghidra_mcp.presentation.mcp_server import create_mcp_server
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


def _normalize_empty_list_result(result: Any) -> Any:
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


def _core():
    global _core_module
    if _core_module is None:
        from ghidra_headless.handlers import core as core_module

        _core_module = core_module
    return _core_module


class _LazyCoreExecutor:
    """Resolve ghidra core module lazily to avoid import-time dependency on started JVM."""

    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        return _core().execute(command, params, key=key)


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


class ServiceRegistryAdapter:
    """Facade bridging dispatcher calls to core/target/sync services."""

    def __init__(
        self,
        *,
        core_command_service: CoreCommandService,
        target_service: TargetService,
        sync_service: SyncService,
    ) -> None:
        self._core_command_service = core_command_service
        self._target_service = target_service
        self._sync_service = sync_service

    # core command path
    def call(self, command: str, params: dict[str, Any], target: str):
        return self._core_command_service.call(command, params, target)

    # target/project path
    def list_targets(self):
        return self._target_service.list_targets()

    def list_programs(self, target: str):
        return self._target_service.list_programs(target)

    def register_target(self, target: str, *, project_location: str, project_name: str | None = None):
        return self._target_service.register_target(
            target,
            project_location,
            project_name=project_name,
        )

    def load_program(self, target: str, domain_path: str):
        return self._target_service.load_program(target, domain_path)

    def import_program(self, target: str, binary_path: str):
        return self._target_service.import_program(target, binary_path)

    def create_session(
        self,
        target: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        if domain_path is None:
            raise ValueError("domain_path を指定してください")
        return self._target_service.create_session(
            target,
            project_location,
            project_name=project_name,
            domain_path=domain_path,
        )

    def close_session(self, target: str, *, remove_program: bool = False):
        return self._target_service.close_session(target, remove_program=remove_program)

    # shared-sync path
    def get_project_sync_status(self, target: str, *, domain_path: str | None = None):
        return self._sync_service.get_project_sync_status(target, domain_path=domain_path)

    def checkout_project_program(self, target: str, *, exclusive: bool = False, domain_path: str | None = None):
        return self._sync_service.checkout_project_program(target, exclusive=exclusive, domain_path=domain_path)

    def add_project_program_to_version_control(
        self,
        target: str,
        *,
        comment: str,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        return self._sync_service.add_project_program_to_version_control(
            target,
            comment,
            keep_checked_out=keep_checked_out,
            domain_path=domain_path,
        )

    def commit_project_program(
        self,
        target: str,
        *,
        message: str,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ):
        return self._sync_service.commit_project_program(
            target,
            message,
            keep_checked_out=keep_checked_out,
            auto_checkout=auto_checkout,
            domain_path=domain_path,
        )

    def pull_project_program(
        self,
        target: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ):
        return self._sync_service.pull_project_program(
            target,
            on_local_changes=on_local_changes,
            domain_path=domain_path,
        )

    def undo_checkout_project_program(
        self,
        target: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        return self._sync_service.undo_checkout_project_program(
            target,
            discard_local_changes=discard_local_changes,
            domain_path=domain_path,
        )

    def terminate_project_program_checkout(
        self,
        target: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        return self._sync_service.terminate_project_program_checkout(
            target,
            checkout_id=checkout_id,
            domain_path=domain_path,
        )

    def reload_project_program(self, target: str, *, domain_path: str | None = None):
        return self._sync_service.reload_project_program(target, domain_path=domain_path)

    def get_version_history(self, target: str, *, limit: int = 50, domain_path: str | None = None):
        return self._sync_service.get_version_history(target, limit=limit, domain_path=domain_path)

    def get_version_diff(
        self,
        target: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        return self._sync_service.get_version_diff(
            target,
            from_version=from_version,
            to_version=to_version,
            range_limit=range_limit,
            domain_path=domain_path,
        )

    def has_targets(self) -> bool:
        return self._target_service.has_targets()

    def close_all(self) -> None:
        self._target_service.close_all()


_runtime_state = RuntimeState(
    core_accessor=lambda: _core(),
    checkout_required_commands=set(_CHECKOUT_REQUIRED_COMMANDS),
    normalize_result=_normalize_empty_list_result,
)
_runtime_backend = RuntimeBackend(state=_runtime_state)
_lock_manager = LockManager()
_target_service = TargetService(_runtime_backend, lock_manager=_lock_manager)
_sync_service = SyncService(_runtime_backend, lock_manager=_lock_manager)
_core_gateway = CoreGateway(_LazyCoreExecutor())
_core_command_service = CoreCommandService(_core_gateway)
_registry = ServiceRegistryAdapter(
    core_command_service=_core_command_service,
    target_service=_target_service,
    sync_service=_sync_service,
)
_runtime = create_mcp_server(
    registry_provider=lambda: _registry,
    dispatcher_provider=lambda: dispatch_tool,
    include_shared_sync=False,
)
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
            raise ValueError(f"セッション定義に'='が含まれていません: {part}")
        key, value = part.split("=", 1)
        result[key.strip()] = value.strip()
    if "name" not in result:
        raise ValueError("session定義にはname=...が必須です")
    if "project_location" not in result:
        raise ValueError("session定義にはproject_locationが必要です")
    return result


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(description="PyGhidraベースのGhidra MCPサーバー")
    parser.add_argument("--project-location", help="デフォルトセッション用のGhidraプロジェクトディレクトリ")
    parser.add_argument("--project-name", help="デフォルトセッションのプロジェクト名")
    parser.add_argument("--domain-path", help="デフォルトセッションのドメインパス (例: /folder/program)")
    parser.add_argument("--target-name", default="default", help="デフォルトセッションのターゲット名")
    parser.add_argument(
        "--session",
        action="append",
        metavar="name=...,project_location=...,domain_path=...",
        help="追加セッション定義をカンマ区切りで指定 (繰り返し可)",
    )
    parser.add_argument("--ghidra-path", help="Ghidraインストールパス。未指定時は環境変数GHIDRA_INSTALL_DIRを利用")
    parser.add_argument(
        "--ghidra-server-user",
        help="shared project接続時に利用するGhidra serverユーザー名",
    )
    parser.add_argument(
        "--ghidra-server-password-env",
        help="Ghidra serverパスワードを保持した環境変数名",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "http", "streamable-http"],
        help="MCPのトランスポート",
    )
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="SSE/Streamable HTTPホスト (stdioでは未使用)")
    parser.add_argument("--mcp-port", type=int, help="SSE/Streamable HTTPポート (stdioでは未使用)")
    parser.add_argument("--mcp-path", type=str, default="/mcp", help="Streamable HTTPパス (例: /mcp)")
    parser.add_argument(
        "--enable-shared-project-sync",
        action="store_true",
        help="shared project向けのcommit/pull/checkout系ツールを公開する",
    )
    parser.add_argument("--log-level", default="INFO", help="ログレベル")
    return parser.parse_args(argv)


def _normalize_transport(transport: str) -> str:
    return "streamable-http" if transport == "http" else transport


def _normalize_streamable_http_path(path: str) -> str:
    normalized = (path or "").strip()
    if not normalized:
        return "/mcp"
    if not normalized.startswith("/"):
        return "/" + normalized
    return normalized


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower()


def _resolve_transport_security_for_host(host: str) -> TransportSecuritySettings:
    normalized = _normalize_host(host)
    if normalized in {"127.0.0.1", "localhost", "::1"}:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        )
    if normalized in {"0.0.0.0", "::"}:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    if ":" in normalized and not normalized.startswith("["):
        host_pattern = f"[{normalized}]:*"
        origin_pattern = f"http://[{normalized}]:*"
    else:
        host_pattern = f"{normalized}:*"
        origin_pattern = f"http://{normalized}:*"
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host_pattern],
        allowed_origins=[origin_pattern],
    )


def _configure_transport_security_for_host(host: str) -> None:
    settings = _resolve_transport_security_for_host(host)
    if not settings.enable_dns_rebinding_protection:
        logger.warning(
            "mcp-host=%s のため DNS rebinding protection を無効化します。"
            " 本番運用では固定ホスト名/IPでの起動を推奨します。",
            host,
        )
    mcp.settings.transport_security = settings


def configure_ghidra_server_auth(args) -> None:
    username = (getattr(args, "ghidra_server_user", None) or "").strip()
    password_env_name = (getattr(args, "ghidra_server_password_env", None) or "").strip()
    if not username and not password_env_name:
        return
    if not username or not password_env_name:
        raise ValueError("--ghidra-server-user と --ghidra-server-password-env はセットで指定してください")

    password = os.environ.get(password_env_name)
    if password is None:
        raise ValueError(f"環境変数 '{password_env_name}' が未設定です")
    if password == "":
        raise ValueError(f"環境変数 '{password_env_name}' が空です")

    authenticator = _password_client_authenticator_class()(username, password)
    _client_util_class().setClientAuthenticator(authenticator)
    logger.info(
        "Ghidra server認証を設定しました (user=%s, password_env=%s)",
        username,
        password_env_name,
    )


def main(argv: list[str] | None = None) -> int:
    global _core_module
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    configure_logging(getattr(logging, args.log_level.upper(), logging.INFO))
    logger.info("PyGhidra MCPサーバーを起動します")

    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_path:
        logger.debug("pyghidra.start install_dir=%s", ghidra_path)
        pyghidra.start(install_dir=ghidra_path)
    else:
        pyghidra.start()

    try:
        configure_ghidra_server_auth(args)
    except Exception as exc:  # noqa: BLE001
        logger.error("Ghidra server認証設定に失敗: %s", exc)
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
                    logger.info("セッション '%s' をロードしました", config["name"])
                else:
                    _registry.register_target(
                        config["name"],
                        project_location=config.get("project_location"),
                        project_name=config.get("project_name"),
                    )
                    logger.info("ターゲット '%s' をプロジェクトのみで登録しました", config["name"])
            except Exception as exc:  # noqa: BLE001
                logger.error("セッション定義 '%s' の処理中にエラー: %s", definition, exc)
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
                logger.info("デフォルトターゲット '%s' をロードしました", args.target_name)
            else:
                _registry.register_target(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                )
                logger.info(
                    "デフォルトターゲット '%s' をプロジェクトのみで登録しました（program未ロード）",
                    args.target_name,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("デフォルトセッション初期化に失敗: %s", exc)
            _registry.close_all()
            return 1

    if not _registry.has_targets():
        logger.error("少なくとも1つのターゲットを --session または --project-location で指定してください")
        return 1

    _core_module = _core()

    def _shutdown_handler(signum, frame):
        logger.info("シグナル %s を受信したため終了処理を開始します", signum)
        _registry.close_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    if args.enable_shared_project_sync:
        register_shared_project_sync_tools()
        logger.info("shared project同期ツールを有効化しました")

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
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    _configure_transport_security_for_host(mcp.settings.host)
    logger.info("MCPをSSEモードで起動: http://%s:%s/sse", mcp.settings.host, mcp.settings.port)


def configure_mcp_for_streamable_http(args) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    mcp.settings.streamable_http_path = _normalize_streamable_http_path(args.mcp_path)
    _configure_transport_security_for_host(mcp.settings.host)
    logger.info(
        "MCPをStreamable HTTPモードで起動: http://%s:%s%s",
        mcp.settings.host,
        mcp.settings.port,
        mcp.settings.streamable_http_path,
    )


# expose generated tool callables to static analysis/tests
PUBLIC_TOOL_FUNCTIONS = tuple(name for name in _runtime.tools)

if __name__ == "__main__":
    sys.exit(main())
