"""Mutating BSim commands for loaded programs."""

from __future__ import absolute_import, print_function

import re

from ghidra_headless.errors import HeadlessError

from .read_only_bsim import (
    _all_function_symbols,
    _collect_matches,
    _domain_path,
    _format_address,
    _function_symbols_for_query,
    _iter_items,
    _program_md5,
    _requested_functions,
    _run_query,
)

_CATEGORY_NAME_RE = re.compile(r"^[A-Za-z0-9 ._:/()]+$")
# Names Ghidra itself assigns; a match carrying one of these teaches nothing.
_DEFAULT_NAME_RE = re.compile(r"^(thunk_)?(FUN|LAB|SUB|DAT|EXT|PTR|UNK|switchD)_[0-9a-fA-F]+$")
MAX_APPLY_FUNCTIONS = 10_000


def _metadata_value_text(value):
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        raise ValueError(
            "BSIM_TARGET_METADATA_INVALID: category values must be scalar; register the "
            "target first, then use bsim_update_executable_metadata for multiple values"
        )
    return str(value).strip()


def _ghidra_url_class():
    from ghidra.framework.protocol.ghidra import GhidraURL

    return GhidraURL


def _program_class():
    from ghidra.program.model.listing import Program

    return Program


def _bsim_registration_classes():
    from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
    from ghidra.features.bsim.query.protocol import InsertRequest, QueryExeCount, QueryUpdate

    return BSimClientFactory, GenSignatures, InsertRequest, QueryExeCount, QueryUpdate


def _repository_url_from_locator(locator):
    """Return the BSim repository URL for the project that holds ``locator``.

    A shared project's ``project.prp`` names the Ghidra Server and repository, so
    the URL is ``ghidra://host:port/repository``; a private project maps to the
    local ``ghidra:/dir/name`` form.  This avoids ``DomainFile.getSharedProjectURL``,
    which Ghidra routes through a ``DomainFileProxy`` for a versioned file that is
    not checked out and which then fails with "A blank Path element is not allowed".
    """
    import pathlib

    from ghidra_headless.session import path_utils

    GhidraURL = _ghidra_url_class()
    project_dir = pathlib.Path(str(locator.getProjectDir()))
    info = path_utils._read_prp_basic_info(project_dir / "project.prp") or {}
    server = str(info.get("SERVER") or "").strip()
    repository = str(info.get("REPOSITORY_NAME") or "").strip()
    if server and repository:
        port = str(info.get("PORT") or info.get("PORT_NUMBER") or "").strip()
        authority = "%s:%s" % (server, port) if port else server
        return "ghidra://%s/%s" % (authority, repository)
    return str(GhidraURL.makeURL(locator).toExternalForm())


def _program_repository_and_path(program):
    """Return (repository URL, folder path) the way Ghidra's own ingest does.

    ``GenSignatures.getPathFromDomainFile`` yields ``None`` for a root-level file
    and ``"/folder/"`` otherwise; ``ExecutableRecord`` normalises the slashes.
    """
    from ghidra.features.bsim.query import GenSignatures

    domain_file = program.getDomainFile()
    if domain_file is None:
        raise HeadlessError("BSIM_UNSAVED_PROGRAM: current program has no DomainFile")
    locator = domain_file.getProjectLocator()
    if locator is None:
        raise HeadlessError("BSIM_UNSAVED_PROGRAM: current program has never been saved")
    path = GenSignatures.getPathFromDomainFile(program)
    return _repository_url_from_locator(locator), (None if path is None else str(path))


def _sort_callgraph(manager):
    iterator = manager.listAllFunctions()
    while iterator.hasNext():
        iterator.next().sortCallgraph()


def _last_error_message(database):
    last_error = database.getLastError()
    return "unknown error" if last_error is None else str(last_error.message)


def _apply_program_categories(ctx, categories, *, txn):
    """Store executable-category values in Program Information (inside a transaction)."""
    Program = _program_class()
    if not isinstance(categories, dict) or not categories:
        raise ValueError("categories must be a non-empty object")

    def _apply():
        options = ctx.program.getOptions(Program.PROGRAM_INFO)
        applied = {}
        for key, value in categories.items():
            text_key = str(key).strip()
            if not text_key:
                raise ValueError("BSIM_TARGET_METADATA_INVALID: metadata category names must not be empty")
            if _CATEGORY_NAME_RE.match(text_key) is None:
                raise ValueError(
                    "BSIM_TARGET_METADATA_INVALID: category name contains unsupported characters: %s" % text_key
                )
            if value is None:
                continue
            text_value = _metadata_value_text(value)
            if not text_value:
                continue
            options.setString(text_key, text_value)
            applied[text_key] = text_value
        if not applied:
            raise ValueError("categories did not contain any non-empty values")
        return applied

    return txn(ctx, "Set BSim executable metadata", _apply)


class _SignatureSession(object):
    """Open the BSim database and a GenSignatures bound to the loaded program."""

    def __init__(self, ctx, bsim_url):
        BSimClientFactory, GenSignatures, _, _, _ = _bsim_registration_classes()
        if not bsim_url:
            raise ValueError("bsim_url is required")
        self.ctx = ctx
        url = BSimClientFactory.deriveBSimURL(bsim_url)
        self.database = BSimClientFactory.buildClient(url, False)
        self.gensig = None
        try:
            if not bool(self.database.initialize()):
                raise HeadlessError("BSIM_DATABASE_INIT_FAILED: %s" % _last_error_message(self.database))
            db_info = self.database.getInfo()
            self.gensig = GenSignatures(bool(db_info.trackcallgraph))
            self.gensig.setVectorFactory(self.database.getLSHVectorFactory())
            self.gensig.addExecutableCategories(db_info.execats)
            self.gensig.addFunctionTags(db_info.functionTags)
            self.gensig.addDateColumnName(db_info.dateColumnName)
            self.repository, self.path = _program_repository_and_path(ctx.program)
            self.gensig.openProgram(ctx.program, None, None, None, self.repository, self.path)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.gensig is not None:
            self.gensig.dispose()
            self.gensig = None
        self.database.close()


def bsim_register_target(params, *, ensure_context, txn):
    _, _, InsertRequest, QueryExeCount, _ = _bsim_registration_classes()
    ctx = ensure_context()
    categories = params.get("categories")
    applied_categories = None
    if categories:
        # GenSignatures reads category values from Program Information, so they
        # must be stored before the executable record is generated.
        applied_categories = _apply_program_categories(ctx, categories, txn=txn)
    session = _SignatureSession(ctx, params.get("bsim_url"))
    try:
        function_manager = ctx.program.getFunctionManager()
        iterator = function_manager.getFunctions(True)
        session.gensig.scanFunctions(iterator, function_manager.getFunctionCount(), ctx.monitor())
        manager = session.gensig.getDescriptionManager()
        if manager.numFunctions() == 0:
            raise HeadlessError("BSIM_NO_FUNCTIONS: program contains no functions with bodies")
        _sort_callgraph(manager)
        insert_request = InsertRequest()
        insert_request.manage = manager
        response = insert_request.execute(session.database)
        if response is None:
            raise HeadlessError("BSIM_INSERT_FAILED: %s" % _last_error_message(session.database))
        count_query = QueryExeCount()
        count_response = count_query.execute(session.database)
        executable_count = None if count_response is None else int(count_response.recordCount)
        inserted_executables = int(response.numexe)
        return {
            "status": "ok",
            "program": _domain_path(ctx.program),
            "repository": session.repository,
            "path": session.path,
            "categories": applied_categories,
            # numexe counts the program plus one stub record per library its call
            # graph references; executable_count is the database total and counts
            # only non-library executables, so the two are reported separately.
            "inserted_executables": inserted_executables,
            "inserted_library_executables": max(0, inserted_executables - 1),
            "inserted_functions": int(response.numfunc),
            "executable_count": executable_count,
        }
    finally:
        session.close()


def _bad_executables(response):
    return [
        {"executable_md5": str(record.getMd5()), "executable_name": str(record.getNameExec())}
        for record in _iter_items(response.badexe)
    ]


def _bad_functions(response):
    return [
        {
            "executable_md5": str(func.getExecutableRecord().getMd5()),
            "name": str(func.getFunctionName()),
            "address": _format_address(func.getAddress()),
        }
        for func in _iter_items(response.badfunc)
    ]


def _category_records(categories):
    from ghidra.features.bsim.query.description import CategoryRecord
    from java.util import ArrayList

    records = ArrayList()
    for category_type in sorted(categories):
        for value in categories[category_type]:
            records.add(CategoryRecord(category_type, value))
    return records


def _record_categories(record):
    result = {}
    get_all = getattr(record, "getAllCategories", None)
    if get_all is None:
        return result
    for category in _iter_items(get_all()):
        result.setdefault(str(category.getType()), []).append(str(category.getCategory()))
    return result


def _stored_executable_categories(database, md5):
    """Return the categories the database currently holds for ``md5`` (None if absent)."""
    from ghidra.features.bsim.query.protocol import QueryExeInfo

    query = QueryExeInfo()
    query.limit = 2
    query.filterMd5 = md5
    query.fillinCategories = True
    response = database.query(query)
    if response is None:
        raise HeadlessError("BSIM_GET_EXECUTABLE_FAILED: %s" % _last_error_message(database))
    for record in _iter_items(response.records):
        if str(record.getMd5()).lower() == md5:
            return _record_categories(record)
    return None


def _preserve_stored_categories(manager, database, md5):
    """Keep database-only categories across an update.

    ``QueryUpdate`` replaces the executable record's categories with whatever the
    program's Program Information holds, so categories that were only ever set
    through ``bsim_update_executable_metadata`` would silently vanish.  Merge them
    back: a category type the program defines wins, every other stored type stays.
    Returns (preserved category map, found_in_database).
    """
    stored = _stored_executable_categories(database, md5)
    if stored is None:
        return {}, False
    exerec = manager.findExecutable(md5)
    from_program = _record_categories(exerec)
    merged = dict(from_program)
    preserved = {}
    for category_type, values in stored.items():
        if category_type not in merged:
            merged[category_type] = list(values)
            preserved[category_type] = list(values)
    if preserved:
        manager.setExeCategories(exerec, _category_records(merged))
    return preserved, True


def bsim_update_target_signatures(params, *, ensure_context):
    """Push the loaded program's current function names back to its BSim records.

    Equivalent to Ghidra's ``bsim generateupdates`` + ``commitupdates`` done in one
    step: only metadata (names, flags, categories) changes, the feature vectors
    stay as ingested.  Categories stored only in the database are preserved.
    """
    _, _, _, _, QueryUpdate = _bsim_registration_classes()
    ctx = ensure_context()
    session = _SignatureSession(ctx, params.get("bsim_url"))
    try:
        session.gensig.scanFunctionsMetadata(None, ctx.monitor())
        manager = session.gensig.getDescriptionManager()
        scanned = int(manager.numFunctions())
        if scanned == 0:
            raise HeadlessError("BSIM_NO_FUNCTIONS: program contains no functions with bodies")
        program_md5 = _program_md5(ctx.program)
        preserved_categories = {}
        if program_md5 is not None:
            preserved_categories, registered = _preserve_stored_categories(manager, session.database, program_md5)
            if not registered:
                raise LookupError(
                    "BSIM_EXECUTABLE_NOT_FOUND: program is not registered in the BSim database; "
                    "call bsim_register_target first"
                )
        update = QueryUpdate()
        update.manage = manager
        response = update.execute(session.database)
        if response is None:
            raise HeadlessError("BSIM_UPDATE_FAILED: %s" % _last_error_message(session.database))
        bad_executables = _bad_executables(response)
        if program_md5 is not None and any(item["executable_md5"].lower() == program_md5 for item in bad_executables):
            raise LookupError(
                "BSIM_EXECUTABLE_NOT_FOUND: program is not registered in the BSim database; "
                "call bsim_register_target first"
            )
        updated_executables = int(response.exeupdate)
        updated_functions = int(response.funcupdate)
        return {
            "status": "updated" if (updated_executables or updated_functions) else "unchanged",
            "program": _domain_path(ctx.program),
            "executable_md5": program_md5,
            "scanned_functions": scanned,
            "updated_executables": updated_executables,
            "updated_functions": updated_functions,
            "preserved_categories": preserved_categories,
            "bad_executables": bad_executables,
            "bad_functions": bad_functions_or_empty(response),
        }
    finally:
        session.close()


def bad_functions_or_empty(response):
    try:
        return _bad_functions(response)
    except Exception:
        return []


def _is_default_name(name):
    return not name or _DEFAULT_NAME_RE.match(str(name)) is not None


def _select_best_match(candidates):
    """Pick the best foreign match for one query function.

    Returns (match, reason) where reason is None on success or the skip reason.
    Candidates are already sorted best-first.  The pick is ambiguous when the
    runner-up has the same similarity but proposes a different name.
    """
    usable = [item for item in candidates if not _is_default_name(item["matched_ref"].get("name"))]
    if not usable:
        return None, "default_match_name" if candidates else "no_match"
    best = usable[0]
    best_name = best["matched_ref"]["name"]
    for other in usable[1:]:
        if float(other["similarity"]) < float(best["similarity"]):
            break
        if other["matched_ref"]["name"] != best_name:
            return None, "ambiguous"
    return best, None


def bsim_apply_matches(params, *, ensure_context, get_address, find_function_by_name, txn, source_type):
    """Rename functions after their best BSim match, in one transaction.

    Only functions that still carry a Ghidra default name are renamed unless
    ``only_default_names`` is false.  ``dry_run`` reports the plan without renaming.
    """
    ctx = ensure_context()
    dry_run = bool(params.get("dry_run", False))
    only_default_names = params.get("only_default_names", True)
    only_default_names = True if only_default_names is None else bool(only_default_names)
    max_functions = int(params.get("max_functions", 500) or 500)
    if max_functions < 1 or max_functions > MAX_APPLY_FUNCTIONS:
        raise ValueError("max_functions must be between 1 and %d" % MAX_APPLY_FUNCTIONS)

    addresses, names = _requested_functions(params)
    skipped_small = 0
    if addresses or names:
        symbols = _function_symbols_for_query(
            ctx,
            params,
            get_address=get_address,
            find_function_by_name=find_function_by_name,
        )
    else:
        symbols, skipped_small = _all_function_symbols(
            ctx,
            min_function_size=int(params.get("min_function_size", 0) or 0),
        )
    exclude_self = params.get("exclude_self", True)
    exclude_md5 = _program_md5(ctx.program) if (exclude_self is None or bool(exclude_self)) else None
    rows = _run_query(ctx, params, symbols, extra_matches_per_function=1 if exclude_md5 else 0)
    matches, excluded = _collect_matches(
        ctx,
        params.get("query_target") or "default",
        rows,
        exclude_md5=exclude_md5,
        matches_per_function=params.get("matches_per_function", 5),
    )

    by_function = {}
    order = []
    for item in matches:
        key = item["query_ref"]["address"]
        if key not in by_function:
            by_function[key] = []
            order.append(key)
        by_function[key].append(item)

    skipped = {"no_match": 0, "default_match_name": 0, "ambiguous": 0, "not_default_name": 0, "same_name": 0}
    plan = []
    truncated = False
    for key in order:
        if len(plan) >= max_functions:
            truncated = True
            break
        candidates = by_function[key]
        best, reason = _select_best_match(candidates)
        if best is None:
            skipped[reason] += 1
            continue
        address = ctx.address_factory.getAddress(key)
        function = None if address is None else ctx.function_manager.getFunctionAt(address)
        if function is None:
            skipped["no_match"] += 1
            continue
        current_name = str(function.getName())
        new_name = str(best["matched_ref"]["name"])
        if current_name == new_name:
            skipped["same_name"] += 1
            continue
        if only_default_names and function.getSymbol().getSource() != source_type.DEFAULT:
            skipped["not_default_name"] += 1
            continue
        plan.append(
            {
                "address": key,
                "old_name": current_name,
                "new_name": new_name,
                "similarity": float(best["similarity"]),
                "significance": float(best["significance"]),
                "matched_executable_name": best["matched_ref"].get("executable_name"),
                "matched_executable_md5": best["matched_ref"].get("executable_md5"),
                "function": function,
            }
        )

    applied = []
    failed = []
    if plan and not dry_run:

        def _rename_all():
            for entry in plan:
                function = entry["function"]
                try:
                    function.setName(entry["new_name"], source_type.USER_DEFINED)
                except Exception as exc:
                    failed.append(
                        {
                            "address": entry["address"],
                            "old_name": entry["old_name"],
                            "new_name": entry["new_name"],
                            "error": str(exc),
                        }
                    )
                    continue
                applied.append(entry)
            return True

        txn(ctx, "Apply BSim matched function names", _rename_all)
    else:
        applied = list(plan)

    def _public(entry):
        return {key: value for key, value in entry.items() if key != "function"}

    return {
        "status": "dry_run" if dry_run else "ok",
        "program": _domain_path(ctx.program),
        "dry_run": dry_run,
        "queried_functions": int(symbols.size()),
        "matched_functions": len(order),
        "skipped_small_functions": skipped_small,
        "excluded_self_matches": excluded,
        "applied": [_public(entry) for entry in applied],
        "applied_count": len(applied),
        "skipped": skipped,
        "skipped_count": sum(skipped.values()),
        "failed": failed,
        "failed_count": len(failed),
        "truncated": truncated,
    }


__all__ = ["MAX_APPLY_FUNCTIONS", "bsim_apply_matches", "bsim_register_target", "bsim_update_target_signatures"]
