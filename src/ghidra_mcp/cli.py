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
from pydantic import Field
from typing import Annotated, Any, Dict, List, Optional

import pyghidra
import pyghidra.core as pycore
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from ghidra_headless.session import ProgramSession, ProjectHandle
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.services.session_registry import SessionRegistry as _SessionRegistry

logger = logging.getLogger(__name__)

mcp = FastMCP("GhidraMCP Headless")
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
    """Return non-empty MCP content for empty-list results to keep clients compatible."""
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


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


class SessionRegistry(_SessionRegistry):
    def __init__(self) -> None:
        super().__init__(
            core_accessor=lambda: _core(),
            checkout_required_commands=_CHECKOUT_REQUIRED_COMMANDS,
            normalize_result=_normalize_empty_list_result,
        )


_registry = SessionRegistry()


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, target: str = "default") -> List[str]:
    return dispatch_tool(
        "list_methods",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_classes",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def decompile_function(name: str, target: str = "default") -> str:
    return dispatch_tool(
        "decompile_function",
        {"name": name},
        target,
        registry=_registry,
    )


@mcp.tool()
def rename_function(old_name: str, new_name: str, target: str = "default"):
    return dispatch_tool(
        "rename_function",
        {"oldName": old_name, "newName": new_name},
        target,
        registry=_registry,
    )


@mcp.tool()
def rename_data(address: str, new_name: str, target: str = "default"):
    return dispatch_tool(
        "rename_data",
        {"address": address, "newName": new_name},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_segments",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_imports",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_exports",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_namespaces",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_data_items",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def search_functions_by_name(
    query: str,
    offset: int = 0,
    limit: int = 100,
    target: str = "default",
):
    if not query:
        raise ValueError("queryが必要です")
    return dispatch_tool(
        "search_functions_by_name",
        {"query": query, "offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def rename_variable(
    function_name: str,
    old_name: str,
    new_name: str,
    target: str = "default",
):
    return dispatch_tool(
        "rename_variable",
        {"functionName": function_name, "oldName": old_name, "newName": new_name},
        target,
        registry=_registry,
    )


@mcp.tool()
def get_function_by_address(address: str, target: str = "default"):
    return dispatch_tool(
        "get_function_by_address",
        {"address": address},
        target,
        registry=_registry,
    )


@mcp.tool(
    description=(
        "List all functions in the loaded program for the target session. "
        "Requires an initialized target with a loaded program; call list_targets first, "
        "then use create_session or load_project_program when needed."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
)
def list_functions(offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "list_functions",
        {"offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def decompile_function_by_address(address: str, target: str = "default") -> str:
    return dispatch_tool(
        "decompile_function_by_address",
        {"address": address},
        target,
        registry=_registry,
    )


@mcp.tool()
def disassemble_function(address: str, target: str = "default"):
    return dispatch_tool(
        "disassemble_function",
        {"address": address},
        target,
        registry=_registry,
    )


@mcp.tool()
def set_decompiler_comment(address: str, comment: str, target: str = "default"):
    return dispatch_tool(
        "set_decompiler_comment",
        {"address": address, "comment": comment},
        target,
        registry=_registry,
    )


@mcp.tool()
def set_disassembly_comment(address: str, comment: str, target: str = "default"):
    return dispatch_tool(
        "set_disassembly_comment",
        {"address": address, "comment": comment},
        target,
        registry=_registry,
    )


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, target: str = "default"):
    return dispatch_tool(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
        target,
        registry=_registry,
    )


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, target: str = "default"):
    return dispatch_tool(
        "set_function_prototype",
        {"function_address": function_address, "prototype": prototype},
        target,
        registry=_registry,
    )


@mcp.tool()
def set_local_variable_type(
    function_address: str,
    variable_name: str,
    new_type: str,
    target: str = "default",
):
    return dispatch_tool(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
        target,
        registry=_registry,
    )


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "get_xrefs_to",
        {"address": address, "offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "get_xrefs_from",
        {"address": address, "offset": offset, "limit": limit},
        target,
        registry=_registry,
    )


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "get_function_xrefs",
        {"name": name, "offset": offset, "limit": limit},
        target,
        registry=_registry,
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
    return dispatch_tool(
        "list_strings",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "create_struct",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "add_struct_members",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def clear_struct(struct_name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return dispatch_tool(
        "clear_struct",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def get_struct(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return dispatch_tool(
        "get_struct",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def get_data_by_label(label: str, target: str = "default"):
    return dispatch_tool(
        "get_data_by_label",
        {"label": label},
        target,
        registry=_registry,
    )


@mcp.tool()
def get_bytes(address: str, size: int = 16, target: str = "default"):
    return dispatch_tool(
        "get_bytes",
        {"address": address, "size": size},
        target,
        registry=_registry,
    )


@mcp.tool()
def search_bytes(pattern: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return dispatch_tool(
        "search_bytes",
        {"bytes": pattern, "offset": offset, "limit": limit},
        target,
        registry=_registry,
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
    return dispatch_tool(
        "create_enum",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "add_enum_values",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def get_enum(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return dispatch_tool(
        "get_enum",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def set_global_data_type(
    address: str,
    data_type: str,
    length: int | None = None,
    clear_mode: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"address": address, "data_type": data_type}
    if length is not None:
        params["length"] = length
    if clear_mode:
        params["clear_mode"] = clear_mode
    return dispatch_tool(
        "set_global_data_type",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def create_class(
    name: str,
    parent_namespace: str | None = None,
    members: list[dict] | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"name": name}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace
    if members:
        params["members"] = members
    return dispatch_tool(
        "create_class",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "add_class_members",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "remove_class_members",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "remove_enum_values",
        params,
        target,
        registry=_registry,
    )


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
    return dispatch_tool(
        "remove_struct_members",
        params,
        target,
        registry=_registry,
    )


@mcp.tool()
def set_bytes(address: str, bytes_hex: str, target: str = "default"):
    return dispatch_tool(
        "set_bytes",
        {"address": address, "bytes": bytes_hex},
        target,
        registry=_registry,
    )


@mcp.tool()
def get_callee(address: str, target: str = "default"):
    return dispatch_tool(
        "get_callee",
        {"address": address},
        target,
        registry=_registry,
    )


@mcp.tool()
def add_bookmark(
    address: str,
    category: str,
    comment: str,
    type: str,
    format: str = "json",
    target: str = "default",
):
    return dispatch_tool(
        "add_bookmark",
        {
            "address": address,
            "category": category,
            "comment": comment,
            "type": type,
            "format": format,
        },
        target,
        registry=_registry,
    )


@mcp.tool(
    description=(
        "List registered targets and their state, including project info and whether a program "
        "is loaded (domain_path). Call this before target-scoped operations."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
)
def list_targets() -> List[Dict[str, Optional[str]]]:
    return dispatch_tool("list_targets", {}, "default", registry=_registry)


@mcp.tool()
def list_project_programs(target: str):
    return dispatch_tool("list_project_programs", {}, target, registry=_registry)


@mcp.tool(
    description=(
        "Register a target with project information only, without loading a program yet. "
        "Use load_project_program later to open a domain path."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        idempotentHint=False,
    ),
)
def register_target(
    target: str,
    project_location: Annotated[str, Field(description="Path to the Ghidra project (.gpr) file or project directory")],
    project_name: Annotated[str | None, Field(description="Project name; required when project_location is a directory")] = None,
):
    return dispatch_tool(
        "register_target",
        {
            "project_location": project_location,
            "project_name": project_name,
        },
        target,
        registry=_registry,
    )


@mcp.tool(
    description=(
        "Load or switch a program for an existing target by domain path. "
        "Use this for targets that already exist (including project-only targets) "
        "instead of create_session."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        idempotentHint=False,
    ),
)
def load_project_program(
    target: str,
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
):
    return dispatch_tool(
        "load_project_program",
        {
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


@mcp.tool(description="Import a binary or Ghidra archive (.gzf) into the current target's project")
def import_program(
    target: str,
    binary_path: Annotated[str, Field(description="Path to the binary or Ghidra archive (.gzf) to import")],
):
    return dispatch_tool(
        "import_program",
        {
            "binary_path": binary_path,
        },
        target,
        registry=_registry,
    )


@mcp.tool(
    description=(
        "Create a new target session by opening a program in a Ghidra project. "
        "This is non-idempotent and fails if the target already exists. "
        "If the target already exists, use load_project_program."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        idempotentHint=False,
    ),
)
def create_session(
    target: str,
    project_location: Annotated[str, Field(description="Path to the Ghidra project (.gpr) file or project directory")],
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
    project_name: Annotated[str | None, Field(description="Project name; required when project_location is a directory")] = None,
):
    return dispatch_tool(
        "create_session",
        {
            "project_location": project_location,
            "project_name": project_name,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


@mcp.tool()
def close_session(target: str):
    return dispatch_tool("close_session", {}, target, registry=_registry)


@mcp.tool()
def close_session_and_remove_program(target: str):
    return dispatch_tool("close_session_and_remove_program", {}, target, registry=_registry)


def get_project_sync_status(
    target: str,
    domain_path: Annotated[str | None, Field(description="同期対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "get_project_sync_status",
        {
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def checkout_project_program(
    target: str,
    exclusive: Annotated[bool, Field(description="Trueの場合は排他的checkoutを試行")] = False,
    domain_path: Annotated[str | None, Field(description="checkout対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "checkout_project_program",
        {
            "exclusive": exclusive,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def add_project_program_to_version_control(
    target: str,
    comment: Annotated[str, Field(description="バージョン管理追加時のコメント")],
    keep_checked_out: Annotated[bool, Field(description="追加後もcheckout状態を維持する")] = False,
    domain_path: Annotated[str | None, Field(description="対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "add_project_program_to_version_control",
        {
            "comment": comment,
            "keep_checked_out": keep_checked_out,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def commit_project_program(
    target: str,
    message: Annotated[str, Field(description="check-in時のコメント")],
    keep_checked_out: Annotated[bool, Field(description="check-in後もcheckout状態を維持する")] = False,
    auto_checkout: Annotated[bool, Field(description="未checkout時に自動checkoutを試行する")] = True,
    domain_path: Annotated[str | None, Field(description="check-in対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "commit_project_program",
        {
            "message": message,
            "keep_checked_out": keep_checked_out,
            "auto_checkout": auto_checkout,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def pull_project_program(
    target: str,
    on_local_changes: Annotated[
        str,
        Field(description="ローカル変更がある場合の挙動: abort または discard"),
    ] = "abort",
    domain_path: Annotated[str | None, Field(description="pull対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "pull_project_program",
        {
            "on_local_changes": on_local_changes,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def undo_checkout_project_program(
    target: str,
    discard_local_changes: Annotated[bool, Field(description="Trueならローカル変更を破棄")] = True,
    domain_path: Annotated[str | None, Field(description="undo対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "undo_checkout_project_program",
        {
            "discard_local_changes": discard_local_changes,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def terminate_project_program_checkout(
    target: str,
    checkout_id: Annotated[int, Field(description="終了したいcheckout id")],
    domain_path: Annotated[str | None, Field(description="終了対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "terminate_project_program_checkout",
        {
            "checkout_id": checkout_id,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def reload_project_program(
    target: str,
    domain_path: Annotated[str | None, Field(description="再読み込み対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "reload_project_program",
        {
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def get_version_history(
    target: str,
    limit: Annotated[int, Field(description="返却する履歴件数の上限")] = 50,
    domain_path: Annotated[str | None, Field(description="履歴取得対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "get_version_history",
        {
            "limit": limit,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def get_version_diff(
    target: str,
    from_version: Annotated[int, Field(description="比較元バージョン")],
    to_version: Annotated[int, Field(description="比較先バージョン")],
    range_limit: Annotated[int, Field(description="返却する差分アドレスレンジ件数の上限")] = 200,
    domain_path: Annotated[str | None, Field(description="差分取得対象のdomain path。未指定時は現在ロード中のprogram")] = None,
):
    return dispatch_tool(
        "get_version_diff",
        {
            "from_version": from_version,
            "to_version": to_version,
            "range_limit": range_limit,
            "domain_path": domain_path,
        },
        target,
        registry=_registry,
    )


def register_shared_project_sync_tools() -> None:
    global _shared_project_sync_tools_registered
    if _shared_project_sync_tools_registered:
        return

    mcp.add_tool(
        get_project_sync_status,
        description="Get shared-project version-control status for the target program",
    )
    mcp.add_tool(
        get_version_history,
        description="Get version history metadata for the target program in a shared project",
    )
    mcp.add_tool(
        get_version_diff,
        description="Get a summary of differences between two shared-project versions of the target program",
    )
    mcp.add_tool(
        checkout_project_program,
        description="Checkout the target program in a shared project",
    )
    mcp.add_tool(
        add_project_program_to_version_control,
        description="Add the target program to shared-project version control",
    )
    mcp.add_tool(
        commit_project_program,
        description="Check-in changes of the target program to the shared project server",
    )
    mcp.add_tool(
        pull_project_program,
        description="Pull/merge latest remote changes for the target program",
    )
    mcp.add_tool(
        undo_checkout_project_program,
        description="Undo checkout for the target program (optionally discard local changes)",
    )
    mcp.add_tool(
        terminate_project_program_checkout,
        description="Terminate a stale checkout by checkout id for the target program",
    )
    mcp.add_tool(
        reload_project_program,
        description="Reload the target program by closing and reopening the current domain path",
    )
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


if __name__ == "__main__":
    sys.exit(main())
