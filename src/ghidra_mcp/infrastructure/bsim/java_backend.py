"""Java API adapter for Ghidra BSim database reads."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit, urlunsplit


def _iter_java_items(items) -> Iterator[Any]:  # noqa: ANN001
    if items is None:
        return
    has_next = getattr(items, "hasNext", None)
    next_item = getattr(items, "next", None)
    if callable(has_next) and callable(next_item):
        while bool(has_next()):
            yield next_item()
        return
    iterator = getattr(items, "iterator", None)
    if callable(iterator):
        yield from _iter_java_items(iterator())
        return
    try:
        yield from items
    except TypeError:
        return


def _category_map(record) -> dict[str, list[str]]:  # noqa: ANN001
    categories: dict[str, list[str]] = {}
    get_all = getattr(record, "getAllCategories", None)
    if get_all is None:
        return categories
    for category in _iter_java_items(get_all()):
        key = str(category.getType())
        categories.setdefault(key, []).append(str(category.getCategory()))
    return categories


def _executable_to_dict(record) -> dict[str, Any]:  # noqa: ANN001
    return {
        "md5": str(record.getMd5()),
        "name": str(record.getNameExec()),
        "architecture": str(record.getArchitecture()),
        "compiler": str(record.getNameCompiler()),
        "repository": None if record.getRepository() is None else str(record.getRepository()),
        "path": None if record.getPath() is None else str(record.getPath()),
        "ghidra_url": None if record.getURLString() is None else str(record.getURLString()),
        "is_library": bool(record.isLibrary()),
        "categories": _category_map(record),
    }


def _text_or_none(value) -> str | None:  # noqa: ANN001
    if value is None:
        return None
    text = str(value)
    return text or None


def _server_info_to_dict(server_info) -> dict[str, Any]:  # noqa: ANN001
    if server_info is None:
        return {}
    return {
        "database_type": _text_or_none(server_info.getDBType()),
        "server_name": _text_or_none(server_info.getServerName()),
        "server_port": int(server_info.getPort()),
        "server_database": _text_or_none(server_info.getDBName()),
        "server_user": _text_or_none(server_info.getUserName()),
    }


def _hostport(parts) -> str:
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return host


def _postgresql_jdbc_url_and_properties(bsim_url: str):
    parts = urlsplit(bsim_url)
    if parts.scheme.lower() != "postgresql":
        return None
    from java.util import Properties

    props = Properties()
    if parts.username:
        props.setProperty("user", unquote(parts.username))
    if parts.password:
        props.setProperty("password", unquote(parts.password))
    jdbc_url = urlunsplit(("jdbc:postgresql", _hostport(parts), parts.path, parts.query, ""))
    return jdbc_url, props


class BsimJavaBackend:
    """Small wrapper around Ghidra's Java BSim query API.

    Imports are intentionally lazy so normal unit tests can import this module without
    requiring PyGhidra to be started.
    """

    @staticmethod
    def _classes():
        from ghidra.features.bsim.query import BSimClientFactory
        from ghidra.features.bsim.query.protocol import QueryExeCount, QueryExeInfo

        return {
            "BSimClientFactory": BSimClientFactory,
            "QueryExeCount": QueryExeCount,
            "QueryExeInfo": QueryExeInfo,
        }

    @contextmanager
    def _database(self, bsim_url: str):
        classes = self._classes()
        url = classes["BSimClientFactory"].deriveBSimURL(bsim_url)
        database = classes["BSimClientFactory"].buildClient(url, False)
        try:
            if not bool(database.initialize()):
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_DATABASE_INIT_FAILED: {message}")
            yield database
        finally:
            database.close()

    @staticmethod
    def get_ghidra_version() -> str | None:
        try:
            from ghidra.framework import Application

            return str(Application.getApplicationVersion())
        except Exception:
            return None

    @staticmethod
    def _postgresql_version(bsim_url: str) -> tuple[str | None, str | None]:
        connection_info = _postgresql_jdbc_url_and_properties(bsim_url)
        if connection_info is None:
            return None, None

        from java.sql import DriverManager

        connection = None
        try:
            connection = DriverManager.getConnection(*connection_info)
            metadata = connection.getMetaData()
            return str(metadata.getDatabaseProductVersion()), None
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        finally:
            if connection is not None:
                connection.close()

    def get_database_status(self, bsim_url: str) -> dict[str, Any]:
        classes = self._classes()
        with self._database(bsim_url) as database:
            info = database.getInfo()
            server_info = _server_info_to_dict(database.getServerInfo())
            postgresql_version, postgresql_version_error = self._postgresql_version(bsim_url)
            query = classes["QueryExeCount"]()
            response = database.query(query)
            if response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_QUERY_FAILED: {message}")
            return {
                "status": "ok",
                "database": str(info.databasename),
                "owner": str(info.owner),
                "description": str(info.description),
                "readonly": bool(info.readonly),
                "track_callgraph": bool(info.trackcallgraph),
                "executable_count": int(response.recordCount),
                "categories": [str(item) for item in _iter_java_items(info.execats)],
                "function_tags": [str(item) for item in _iter_java_items(info.functionTags)],
                "postgresql_version": postgresql_version,
                "postgresql_version_error": postgresql_version_error,
                **server_info,
            }

    def list_categories(self, bsim_url: str) -> dict[str, Any]:
        with self._database(bsim_url) as database:
            info = database.getInfo()
            categories = [str(item) for item in _iter_java_items(info.execats)]
            function_tags = [str(item) for item in _iter_java_items(info.functionTags)]
            return {
                "items": categories,
                "function_tags": function_tags,
                "count": len(categories),
                "function_tag_count": len(function_tags),
            }

    def list_executables(
        self,
        bsim_url: str,
        *,
        name: str | None = None,
        md5: str | None = None,
        arch: str | None = None,
        compiler: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        classes = self._classes()
        with self._database(bsim_url) as database:
            query = classes["QueryExeInfo"]()
            query.limit = int(limit)
            query.filterExeName = name
            query.filterMd5 = md5
            query.filterArch = arch
            query.filterCompilerName = compiler
            query.fillinCategories = True
            response = database.query(query)
            if response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_QUERY_FAILED: {message}")
            items = [_executable_to_dict(record) for record in _iter_java_items(response.records)]
            return {
                "items": items,
                "count": len(items),
                "record_count": int(response.recordCount),
                "truncated": bool(int(response.recordCount) > len(items)),
            }

    def get_executable(
        self,
        bsim_url: str,
        *,
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        if not md5 and not name:
            raise ValueError("md5 or name is required")
        result = self.list_executables(bsim_url, name=name, md5=md5, limit=2)
        items = result["items"]
        if not items:
            raise LookupError("BSIM_EXECUTABLE_NOT_FOUND")
        if len(items) > 1:
            raise RuntimeError("BSIM_EXECUTABLE_AMBIGUOUS: more than one executable matched")
        return items[0]


__all__ = ["BsimJavaBackend"]
