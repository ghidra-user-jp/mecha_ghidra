"""Java API adapter for Ghidra BSim database reads."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit, urlunsplit


_BSIM_UNIQUE_LOOKUP_LIMIT = 100


def _iter_java_items(items) -> Iterator[Any]:  # noqa: ANN001
    if items is None:
        return
    has_next = getattr(items, "hasNext", None)
    next_item = getattr(items, "next", None)
    if callable(has_next) and callable(next_item):
        while bool(has_next()):
            yield next_item()
        return
    java_iterator = getattr(items, "iterator", None)
    if callable(java_iterator):
        yield from _iter_java_items(java_iterator())
        return
    try:
        python_iterator = iter(items)
    except TypeError:
        return
    # Only a failure to obtain an iterator means this is a non-iterable Java object.
    # TypeError raised while consuming it signals a real partial-read failure and must
    # reach the caller rather than silently turning a prefix into a complete result.
    yield from python_iterator


def _category_map(record) -> dict[str, list[str]]:  # noqa: ANN001
    categories: dict[str, list[str]] = {}
    get_all = getattr(record, "getAllCategories", None)
    if get_all is None:
        return categories
    for category in _iter_java_items(get_all()):
        key = str(category.getType())
        categories.setdefault(key, []).append(str(category.getCategory()))
    return categories


def _categories_to_java_list(categories: dict[str, list[str]]):  # noqa: ANN001
    from ghidra.features.bsim.query.description import CategoryRecord
    from java.util import ArrayList

    records = ArrayList()
    for category_type in sorted(categories):
        for category in categories[category_type]:
            records.add(CategoryRecord(category_type, category))
    return records


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


def _format_address(value) -> str:  # noqa: ANN001
    # Ghidra's FunctionDescription.getAddress() returns a signed Java long; mask to
    # unsigned 64-bit so high addresses do not render as "0x-..." strings.
    return "0x%x" % (int(value) & 0xFFFFFFFFFFFFFFFF)


def _name_matches_exactly(record_name, *, name) -> bool:  # noqa: ANN001
    # BSim's QueryExeInfo name filter is a case-insensitive substring (ILIKE) match, so
    # re-check the name exactly to avoid acting on an unintended record. md5 is filtered
    # exactly server-side for full 32-char values (and as a prefix otherwise), so it
    # needs no re-check here -- re-checking would break legitimate md5-prefix lookups.
    return name is None or str(record_name) == name


def _select_unique_executable_record(records, *, name):  # noqa: ANN001
    candidates = list(records)
    exact_matches = [
        record
        for record in candidates
        if _name_matches_exactly(record.getNameExec(), name=name)
    ]
    if len(exact_matches) > 1:
        raise RuntimeError("BSIM_EXECUTABLE_AMBIGUOUS: more than one executable matched")
    if len(candidates) > _BSIM_UNIQUE_LOOKUP_LIMIT:
        # The extra record is a truncation sentinel. Even if the visible page has one
        # exact match, another exact match may be beyond it, so mutating would be unsafe.
        raise RuntimeError(
            "BSIM_EXECUTABLE_LOOKUP_TRUNCATED: more than 100 candidates matched; use md5"
        )
    if not exact_matches:
        raise LookupError("BSIM_EXECUTABLE_NOT_FOUND")
    return exact_matches[0]


def _load_executable_update_manager(database, query_name_class, source_record):  # noqa: ANN001
    """Load one real function alongside an executable before issuing QueryUpdate.

    Ghidra 12.1.2's SQL backend calls ``DescriptionManager.listFunctions()`` for
    every executable in a ``QueryUpdate``.  That method raises
    ``NoSuchElementException`` when the manager's function set is empty, so merely
    transferring the ``QueryExeInfo`` executable record is not sufficient.  A
    lightweight ``QueryName`` supplies the executable plus one unchanged function.
    """

    query = query_name_class()
    query.spec.transfer(source_record)
    query.funcname = ""
    query.maxfunc = 1
    query.printselfsig = False
    query.printjustexe = False
    query.fillinSigs = False
    query.fillinCallgraph = False
    query.fillinCategories = True
    response = database.query(query)
    if response is None:
        last_error = database.getLastError()
        message = "unknown error" if last_error is None else str(last_error.message)
        raise RuntimeError(f"BSIM_GET_EXECUTABLE_FAILED: {message}")
    if not bool(response.uniqueexecutable):
        raise LookupError("BSIM_EXECUTABLE_NOT_FOUND")

    manager = response.manage
    if int(manager.numFunctions()) == 0:
        # Avoid propagating Ghidra's opaque NoSuchElementException.  BSim records
        # normally contain functions, but an empty/corrupt record cannot safely use
        # QueryUpdate on Ghidra 12.1.2.
        raise RuntimeError(
            "BSIM_EXECUTABLE_UPDATE_UNSUPPORTED: executable has no function records"
        )
    record = manager.findExecutable(str(source_record.getMd5()))
    return manager, record


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
        from ghidra.features.bsim.query.protocol import (
            InstallCategoryRequest,
            QueryExeCount,
            QueryExeInfo,
            QueryName,
            QueryUpdate,
        )

        return {
            "BSimClientFactory": BSimClientFactory,
            "InstallCategoryRequest": InstallCategoryRequest,
            "QueryExeCount": QueryExeCount,
            "QueryExeInfo": QueryExeInfo,
            "QueryName": QueryName,
            "QueryUpdate": QueryUpdate,
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

    def add_executable_category(self, bsim_url: str, *, category: str) -> dict[str, Any]:
        classes = self._classes()
        with self._database(bsim_url) as database:
            info = database.getInfo()
            existing = [str(item) for item in _iter_java_items(info.execats)]
            if category in existing:
                return {
                    "status": "already_exists",
                    "category": category,
                    "items": existing,
                    "count": len(existing),
                }

            query = classes["InstallCategoryRequest"]()
            query.type_name = category
            response = database.query(query)
            if response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_ADD_EXECUTABLE_CATEGORY_FAILED: {message}")
            updated_info = response.info or database.getInfo()
            categories = [str(item) for item in _iter_java_items(updated_info.execats)]
            return {
                "status": "created",
                "category": category,
                "items": categories,
                "count": len(categories),
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
            query.filterMd5 = md5.lower() if md5 else md5
            query.filterArch = arch
            query.filterCompilerName = compiler
            query.fillinCategories = True
            response = database.query(query)
            if response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_QUERY_FAILED: {message}")
            items = [_executable_to_dict(record) for record in _iter_java_items(response.records)]
            # recordCount reflects the returned page size, not a true total, so a full page
            # means more rows may exist; report that rather than claiming completeness.
            return {
                "items": items,
                "count": len(items),
                "record_count": len(items),
                "truncated": len(items) >= int(limit),
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
        # Fetch a sentinel record beyond the scan budget. A unique match within a full
        # page is not necessarily unique in the database, and "not found" is likewise
        # unsafe when an exact match may exist beyond that page.
        result = self.list_executables(
            bsim_url,
            name=name,
            md5=md5,
            limit=_BSIM_UNIQUE_LOOKUP_LIMIT + 1,
        )
        candidates = list(result["items"])
        items = [
            item
            for item in candidates
            if _name_matches_exactly(item.get("name"), name=name)
        ]
        if len(items) > 1:
            raise RuntimeError("BSIM_EXECUTABLE_AMBIGUOUS: more than one executable matched")
        if len(candidates) > _BSIM_UNIQUE_LOOKUP_LIMIT or bool(result.get("truncated")):
            raise RuntimeError(
                "BSIM_EXECUTABLE_LOOKUP_TRUNCATED: more than 100 candidates matched; use md5"
            )
        if not items:
            raise LookupError("BSIM_EXECUTABLE_NOT_FOUND")
        return items[0]

    def update_executable_metadata(
        self,
        bsim_url: str,
        *,
        categories: dict[str, list[str]],
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        classes = self._classes()
        with self._database(bsim_url) as database:
            info = database.getInfo()
            configured_categories = {str(item) for item in _iter_java_items(info.execats)}
            unknown = sorted(set(categories) - configured_categories)
            if unknown:
                raise ValueError(
                    "BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED: "
                    + ", ".join(unknown)
                    + "; call bsim_add_executable_category first"
                )

            query = classes["QueryExeInfo"]()
            # Fetch one record beyond the scan budget so a full result page cannot be
            # mistaken for a complete, unique lookup.
            query.limit = _BSIM_UNIQUE_LOOKUP_LIMIT + 1
            query.filterMd5 = md5.lower() if md5 else md5
            query.filterExeName = name
            query.fillinCategories = True
            response = database.query(query)
            if response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_GET_EXECUTABLE_FAILED: {message}")

            # The name filter is a case-insensitive substring (ILIKE) match server-side, so
            # narrow to records whose identity matches exactly before mutating anything.
            source_record = _select_unique_executable_record(
                _iter_java_items(response.records),
                name=name,
            )
            manager, updated_record = _load_executable_update_manager(
                database,
                classes["QueryName"],
                source_record,
            )
            # QueryName is a second, exact-MD5 read.  Merge from that fresher record
            # so a category change between the uniqueness scan and this query is not
            # overwritten merely because the first snapshot was stale.
            merged_categories = _category_map(updated_record)
            for category_type, values in categories.items():
                if values:
                    merged_categories[category_type] = list(values)
                else:
                    merged_categories.pop(category_type, None)

            manager.setExeCategories(updated_record, _categories_to_java_list(merged_categories))

            update = classes["QueryUpdate"]()
            update.manage = manager
            update_response = database.query(update)
            if update_response is None:
                last_error = database.getLastError()
                message = "unknown error" if last_error is None else str(last_error.message)
                raise RuntimeError(f"BSIM_UPDATE_EXECUTABLE_METADATA_FAILED: {message}")

            bad_executables = [
                _executable_to_dict(record)
                for record in _iter_java_items(update_response.badexe)
            ]
            bad_functions = [
                {
                    "executable_md5": str(func.getExecutableRecord().getMd5()),
                    "name": str(func.getFunctionName()),
                    "address": _format_address(func.getAddress()),
                }
                for func in _iter_java_items(update_response.badfunc)
            ]
            return {
                "status": "updated" if int(update_response.exeupdate) else "unchanged",
                "executable": _executable_to_dict(updated_record),
                "categories": merged_categories,
                "updated_executables": int(update_response.exeupdate),
                "updated_functions": int(update_response.funcupdate),
                "bad_executables": bad_executables,
                "bad_functions": bad_functions,
            }


__all__ = ["BsimJavaBackend"]
