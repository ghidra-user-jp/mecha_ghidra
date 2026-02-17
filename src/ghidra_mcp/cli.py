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
import fasteners
import threading
from pydantic import Field
from typing import Annotated, Any, Dict, List, Optional

import pyghidra
from mcp.server.fastmcp import FastMCP

from ghidra_headless.session import ProgramSession, ProjectHandle

logger = logging.getLogger(__name__)

mcp = FastMCP("GhidraMCP Headless")
_core_module = None


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: Dict[str, ProgramSession] = {}
        self._locks: Dict[str, threading.RLock] = {}
        self._project_handles: Dict[tuple[str, str], ProjectHandle] = {}
        self._registry_lock = fasteners.ReaderWriterLock()

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ) -> ProgramSession:
        handle: ProjectHandle | None = None
        session: ProgramSession | None = None
        with self._registry_lock.write_lock():
            if name in self._sessions:
                raise ValueError(f"セッション '{name}' は既に存在します")

            handle = self._get_or_create_project_handle(project_location, project_name)
            session = handle.open_program(domain_path)
            self._locks[name] = threading.RLock()
            self._sessions[name] = session

            try:
                program = session.get_program()
                _core().initialize(program, key=name)
                return session
            except Exception:
                self._cleanup_session(name, session, handle, remove_registry_entry=True)
                raise

    def _ensure(self, name: str) -> ProgramSession:
        try:
            return self._sessions[name]
        except KeyError:
            raise RuntimeError(f"セッション '{name}' は初期化されていません")

    def _lock(self, name: str) -> threading.RLock:
        try:
            return self._locks[name]
        except KeyError:
            raise RuntimeError(f"セッション '{name}' は初期化されていません")

    def list_targets(self) -> List[Dict[str, Optional[str]]]:
        with self._registry_lock.read_lock():
            return [
                {"target": name, **session.to_dict()}
                for name, session in sorted(self._sessions.items(), key=lambda item: item[0])
            ]

    def list_programs(self, name: str):
        with self._registry_lock.read_lock():
            session = self._ensure(name)
            handle = session.get_project_handle()
            return handle.list_programs()

    def load_program(
        self,
        name: str,
        domain_path: str,
    ) -> str:
        with self._registry_lock.write_lock():
            if not domain_path:
                raise ValueError("domain_path を指定してください")

            session = self._ensure(name)
            handle = session.get_project_handle()
            new_session = handle.open_program(domain_path)
            loaded_domain_path = new_session.to_dict().get("domain_path") or ""
            try:
                new_program = new_session.get_program()
                _core().initialize(new_program, key=name)
            except Exception:
                self._cleanup_session(
                    name,
                    new_session,
                    handle,
                    remove_registry_entry=False,
                    remove_context=False,
                )
                raise

            old_session = self._sessions.get(name)
            self._sessions[name] = new_session
            try:
                if old_session is not None:
                    old_session.close()
            finally:
                if handle.is_closed():
                    self._project_handles.pop(handle.get_key(), None)
            return loaded_domain_path

    def import_program(self, name: str, binary_path: str) -> str:
        with self._registry_lock.write_lock():
            if not binary_path:
                raise ValueError("binary_path を指定してください")
            session = self._ensure(name)
            handle = session.get_project_handle()
            domain_file = handle.import_program(binary_path)
            return domain_file.getPathname()

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        with self._registry_lock.write_lock():
            self._close_session_locked(name, remove_program=remove_program)

    def _close_session_locked(self, name: str, *, remove_program: bool) -> None:
        session = self._sessions.pop(name, None)
        if session is None:
            raise RuntimeError(f"セッション '{name}' は存在しません")
        self._locks.pop(name, None)
        handle = session.get_project_handle()
        self._cleanup_session(
            name,
            session,
            handle,
            remove_registry_entry=False,
            remove_program=remove_program,
        )

    def close_all(self) -> None:
        with self._registry_lock.write_lock():
            names = list(self._sessions.keys())
            for name in names:
                try:
                    self._close_session_locked(name, remove_program=False)
                except Exception:  # noqa: BLE001
                    pass
            self._sessions.clear()
            self._locks.clear()
            for handle in list(self._project_handles.values()):
                try:
                    handle.close()
                except Exception:
                    pass
            self._project_handles.clear()
            _core().clear_contexts()

    def _cleanup_session(
        self,
        name: str,
        session: ProgramSession | None,
        handle: ProjectHandle | None,
        *,
        remove_registry_entry: bool,
        remove_context: bool = True,
        remove_program: bool = False,
    ) -> None:
        if remove_registry_entry:
            self._sessions.pop(name, None)
            self._locks.pop(name, None)

        try:
            if session is not None:
                session.close(remove_program=remove_program)
        except Exception:
            pass

        if remove_context:
            _core().remove_context(name)

        if handle is not None and handle.is_closed():
            self._project_handles.pop(handle.get_key(), None)

    def has_sessions(self) -> bool:
        with self._registry_lock.read_lock():
            return bool(self._sessions)

    def _get_or_create_project_handle(self, project_location: str, project_name: Optional[str]) -> ProjectHandle:
        key = ProjectHandle.make_key(project_location, project_name)
        handle = self._project_handles.get(key)
        if handle is None or handle.is_closed():
            handle = ProjectHandle(project_location, project_name)
            self._project_handles[key] = handle
        return handle

    def call(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        with self._registry_lock.read_lock():
            _registry._ensure(target)
            lock = _registry._lock(target)
            with lock:
                return _core().execute(command, params or {}, key=target)

_registry = SessionRegistry()


def _core():
    global _core_module
    if _core_module is None:
        from ghidra_headless.handlers import core as core_module
        _core_module = core_module
    return _core_module


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, target: str = "default") -> List[str]:
    return _registry.call("list_methods", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_classes", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def decompile_function(name: str, target: str = "default") -> str:
    return _registry.call("decompile_function", {"name": name}, target)


@mcp.tool()
def rename_function(old_name: str, new_name: str, target: str = "default"):
    return _registry.call(
        "rename_function",
        {"oldName": old_name, "newName": new_name},
        target,
    )


@mcp.tool()
def rename_data(address: str, new_name: str, target: str = "default"):
    return _registry.call("rename_data", {"address": address, "newName": new_name}, target)


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_segments", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_imports", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_exports", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_namespaces", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_data_items", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def search_functions_by_name(
    query: str,
    offset: int = 0,
    limit: int = 100,
    target: str = "default",
):
    if not query:
        return ["Error: query string is required"]
    return _registry.call(
        "search_functions_by_name",
        {"query": query, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def rename_variable(
    function_name: str,
    old_name: str,
    new_name: str,
    target: str = "default",
):
    return _registry.call(
        "rename_variable",
        {"functionName": function_name, "oldName": old_name, "newName": new_name},
        target,
    )


@mcp.tool()
def get_function_by_address(address: str, target: str = "default"):
    return _registry.call("get_function_by_address", {"address": address}, target)


@mcp.tool()
def list_functions(target: str = "default"):
    return _registry.call("list_functions", {}, target)


@mcp.tool()
def decompile_function_by_address(address: str, target: str = "default") -> str:
    return _registry.call("decompile_function_by_address", {"address": address}, target)


@mcp.tool()
def disassemble_function(address: str, target: str = "default"):
    return _registry.call("disassemble_function", {"address": address}, target)


@mcp.tool()
def set_decompiler_comment(address: str, comment: str, target: str = "default"):
    return _registry.call(
        "set_decompiler_comment",
        {"address": address, "comment": comment},
        target,
    )


@mcp.tool()
def set_disassembly_comment(address: str, comment: str, target: str = "default"):
    return _registry.call(
        "set_disassembly_comment",
        {"address": address, "comment": comment},
        target,
    )


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, target: str = "default"):
    return _registry.call(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
        target,
    )


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, target: str = "default"):
    return _registry.call(
        "set_function_prototype",
        {"function_address": function_address, "prototype": prototype},
        target,
    )


@mcp.tool()
def set_local_variable_type(
    function_address: str,
    variable_name: str,
    new_type: str,
    target: str = "default",
):
    return _registry.call(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
        target,
    )


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_xrefs_to", {"address": address, "offset": offset, "limit": limit}, target
    )


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_xrefs_from",
        {"address": address, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_function_xrefs",
        {"name": name, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def list_strings(
    offset: int = 0,
    limit: int = 2000,
    filter: str | None = None,
    target: str = "default",
):
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return _registry.call("list_strings", params, target)


@mcp.tool()
def create_struct(
    name: str,
    category: str | None = None,
    size: int = 0,
    members: list[dict] | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"name": name, "size": size}
    if category:
        params["category"] = category
    if members:
        params["members"] = members
    return _registry.call("create_struct", params, target)


@mcp.tool()
def add_struct_members(
    struct_name: str,
    members: list[dict],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"struct_name": struct_name, "members": members}
    if category:
        params["category"] = category
    return _registry.call("add_struct_members", params, target)


@mcp.tool()
def clear_struct(struct_name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return _registry.call("clear_struct", params, target)


@mcp.tool()
def get_struct(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return _registry.call("get_struct", params, target)


@mcp.tool()
def get_data_by_label(label: str, target: str = "default"):
    return _registry.call("get_data_by_label", {"label": label}, target)


@mcp.tool()
def get_bytes(address: str, size: int = 16, target: str = "default"):
    return _registry.call("get_bytes", {"address": address, "size": size}, target)


@mcp.tool()
def search_bytes(pattern: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "search_bytes",
        {"bytes": pattern, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def create_enum(
    name: str,
    category: str | None = None,
    size: int = 4,
    values: list[dict] | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"name": name, "size": size}
    if category:
        params["category"] = category
    if values:
        params["values"] = values
    return _registry.call("create_enum", params, target)


@mcp.tool()
def add_enum_values(
    enum_name: str,
    values: list[dict],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"enum_name": enum_name, "values": values}
    if category:
        params["category"] = category
    return _registry.call("add_enum_values", params, target)


@mcp.tool()
def get_enum(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return _registry.call("get_enum", params, target)


@mcp.tool()
def set_global_data_type(
    address: str,
    data_type: str,
    length: int | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"address": address, "data_type": data_type}
    if length is not None:
        params["length"] = length
    return _registry.call("set_global_data_type", params, target)


@mcp.tool()
def add_class_members(
    class_name: str,
    members: list[dict],
    parent_namespace: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"class_name": class_name, "members": members}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace
    return _registry.call("add_class_members", params, target)


@mcp.tool()
def remove_class_members(
    class_name: str,
    members: list[str],
    parent_namespace: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"class_name": class_name, "members": members}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace
    return _registry.call("remove_class_members", params, target)


@mcp.tool()
def remove_enum_values(
    enum_name: str,
    values: list[str],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"enum_name": enum_name, "values": values}
    if category:
        params["category"] = category
    return _registry.call("remove_enum_values", params, target)


@mcp.tool()
def remove_struct_members(
    struct_name: str,
    members: list[str],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"struct_name": struct_name, "members": members}
    if category:
        params["category"] = category
    return _registry.call("remove_struct_members", params, target)


@mcp.tool()
def set_bytes(address: str, bytes_hex: str, target: str = "default"):
    return _registry.call("set_bytes", {"address": address, "bytes": bytes_hex}, target)


@mcp.tool()
def get_callee(address: str, target: str = "default"):
    return _registry.call("get_callee", {"address": address}, target)


@mcp.tool()
def add_bookmark(
    address: str,
    category: str,
    comment: str,
    type: str,
    target: str = "default",
):
    return _registry.call(
        "add_bookmark",
        {"address": address, "category": category, "comment": comment, "type": type},
        target,
    )


@mcp.tool()
def list_targets() -> List[Dict[str, Optional[str]]]:
    return _registry.list_targets()


@mcp.tool()
def list_project_programs(target: str):
    return _registry.list_programs(target)


@mcp.tool(description="Load an existing program in the current target's project by domain path")
def load_project_program(
    target: str,
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
):
    loaded_domain_path = _registry.load_program(target, domain_path=domain_path)
    return {"status": "ok", "target": target, "program": loaded_domain_path}


@mcp.tool(description="Import a binary or Ghidra archive (.gzf) into the current target's project")
def import_program(
    target: str,
    binary_path: Annotated[str, Field(description="Path to the binary or Ghidra archive (.gzf) to import")],
):
    imported_domain_path = _registry.import_program(target, binary_path=binary_path)
    return {"status": "ok", "target": target, "program": imported_domain_path}


@mcp.tool(description="Create a session by opening an existing program in a Ghidra project")
def create_session(
    target: str,
    project_location: Annotated[str, Field(description="Path to the Ghidra project (.gpr) file or project directory")],
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
    project_name: Annotated[str | None, Field(description="Project name; required when project_location is a directory")] = None,
):
    try:
        _registry.create_session(
            target,
            project_location=project_location,
            project_name=project_name,
            domain_path=domain_path,
        )
        return {"status": "ok", "target": target}
    except Exception as exc:
        raise RuntimeError(f"セッション '{target}' の作成に失敗しました: {exc}")


@mcp.tool()
def close_session(target: str):
    try:
        _registry.close_session(target)
        return {"status": "ok", "target": target}
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"セッション '{target}' のクローズに失敗しました: {exc}")


@mcp.tool()
def close_session_and_remove_program(target: str):
    try:
        _registry.close_session(target, remove_program=True)
        return {"status": "ok", "target": target}
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"セッション '{target}' のクローズ/削除に失敗しました: {exc}")


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
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "stream-http", "streamable-http"],
        help="MCPのトランスポート",
    )
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="SSE/Streamable HTTPホスト (stdioでは未使用)")
    parser.add_argument("--mcp-port", type=int, help="SSE/Streamable HTTPポート (stdioでは未使用)")
    parser.add_argument("--mcp-path", type=str, default="/mcp", help="Streamable HTTPパス (例: /mcp)")
    parser.add_argument("--log-level", default="INFO", help="ログレベル")
    return parser.parse_args(argv)


def _normalize_transport(transport: str) -> str:
    return "streamable-http" if transport == "stream-http" else transport


def _normalize_streamable_http_path(path: str) -> str:
    normalized = (path or "").strip()
    if not normalized:
        return "/mcp"
    if not normalized.startswith("/"):
        return "/" + normalized
    return normalized


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

    if args.session:
        for definition in args.session:
            try:
                config = _parse_session_definition(definition)
                _registry.create_session(
                    config["name"],
                    project_location=config.get("project_location"),
                    project_name=config.get("project_name"),
                    domain_path=config.get("domain_path"),
                )
                logger.info("セッション '%s' をロードしました", config["name"])
            except Exception as exc:  # noqa: BLE001
                logger.error("セッション定義 '%s' の処理中にエラー: %s", definition, exc)
                _registry.close_all()
                return 1

    if args.project_location:
        try:
            _registry.create_session(
                args.target_name,
                project_location=args.project_location,
                project_name=args.project_name,
                domain_path=args.domain_path,
            )
            logger.info("デフォルトターゲット '%s' をロードしました", args.target_name)
        except Exception as exc:  # noqa: BLE001
            logger.error("デフォルトセッション初期化に失敗: %s", exc)
            _registry.close_all()
            return 1

    if not _registry.has_sessions():
        logger.error("少なくとも1つのセッションを --session または --project-location で指定してください")
        return 1

    _core_module = _core()

    def _shutdown_handler(signum, frame):
        logger.info("シグナル %s を受信したため終了処理を開始します", signum)
        _registry.close_all()
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
        _registry.close_all()
    return 0


def configure_mcp_for_sse(args) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    logger.info("MCPをSSEモードで起動: http://%s:%s/sse", mcp.settings.host, mcp.settings.port)


def configure_mcp_for_streamable_http(args) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    mcp.settings.streamable_http_path = _normalize_streamable_http_path(args.mcp_path)
    logger.info(
        "MCPをStreamable HTTPモードで起動: http://%s:%s%s",
        mcp.settings.host,
        mcp.settings.port,
        mcp.settings.streamable_http_path,
    )


if __name__ == "__main__":
    sys.exit(main())
