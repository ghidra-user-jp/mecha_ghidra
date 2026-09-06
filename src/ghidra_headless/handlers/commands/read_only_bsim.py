"""Read-only BSim commands for loaded programs."""

from __future__ import absolute_import, print_function

import pathlib

from ghidra_headless.errors import HeadlessError

BSIM_MATCHED_REF_VERSION = 1
# One query may name at most this many functions explicitly (addresses plus names).
MAX_QUERY_FUNCTIONS = 1000


def _bsim_classes():
    from ghidra.features.bsim.gui.search.results import BSimMatchResult
    from ghidra.features.bsim.query.facade import SFQueryInfo, SimilarFunctionQueryService
    from java.util import HashSet

    return HashSet, SimilarFunctionQueryService, SFQueryInfo, BSimMatchResult


def _iter_items(items):
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
        for item in _iter_items(iterator()):
            yield item
        return
    try:
        python_iter = iter(items)
    except TypeError:
        python_iter = None
    if python_iter is not None:
        # Only the iter() acquisition may fail for a non-iterable; do not wrap the
        # consumption loop, otherwise a mid-iteration error silently truncates the
        # result and the caller reports a partial list as complete.
        for item in python_iter:
            yield item
        return
    if callable(next_item):
        while True:
            try:
                yield next_item()
            except StopIteration:
                break


def _domain_path(program):
    domain_file = program.getDomainFile()
    if domain_file is None:
        return None
    return domain_file.getPathname()


def _program_md5(program):
    """Return the lower-case MD5 BSim uses to identify this program, or None."""
    get_md5 = getattr(program, "getExecutableMD5", None)
    if get_md5 is None:
        return None
    value = get_md5()
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _category_map(record):
    result = {}
    get_all = getattr(record, "getAllCategories", None)
    if get_all is None:
        return result
    for category in _iter_items(get_all()):
        key = str(category.getType())
        result.setdefault(key, []).append(str(category.getCategory()))
    return result


def _format_address(value):
    # FunctionDescription.getAddress() is a signed Java long; mask to unsigned 64-bit
    # so high addresses do not render as "0x-..." strings.
    return "0x%x" % (int(value) & 0xFFFFFFFFFFFFFFFF)


def _matched_domain_path(record):
    # ExecutableRecord.getPath() is always the containing folder and never includes the
    # program name, so always append it. (A folder whose basename happens to equal the
    # program name must not collapse to the folder path.)
    raw_path = record.getPath()
    name = str(record.getNameExec())
    if raw_path is None or not str(raw_path).strip():
        return "/" + name
    path = pathlib.PurePosixPath(str(raw_path))
    if not path.is_absolute():
        path = pathlib.PurePosixPath("/") / path
    return (path / name).as_posix()


def _matched_ref(function_description):
    record = function_description.getExecutableRecord()
    repository = record.getRepository()
    ghidra_url = record.getURLString()
    return {
        "matched_ref_version": BSIM_MATCHED_REF_VERSION,
        "executable_md5": str(record.getMd5()),
        "executable_name": str(record.getNameExec()),
        "ghidra_url": None if ghidra_url is None else str(ghidra_url),
        "repository": None if repository is None else str(repository),
        "domain_path": _matched_domain_path(record),
        "address": _format_address(function_description.getAddress()),
        "name": str(function_description.getFunctionName()),
        "is_library": bool(record.isLibrary()),
        "categories": _category_map(record),
    }


def _query_ref(ctx, target, function_description):
    return {
        "target": target,
        "domain_path": _domain_path(ctx.program),
        "address": _format_address(function_description.getAddress()),
        "name": str(function_description.getFunctionName()),
    }


def _text_list(value, *, name):
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        raise ValueError("%s must be a list" % name)
    items = []
    for item in value:
        text = str(item).strip() if item is not None else ""
        if text:
            items.append(text)
    return items


def _requested_functions(params):
    """Merge the single and batch function selectors into (addresses, names)."""
    addresses = _text_list(params.get("addresses"), name="addresses")
    names = _text_list(params.get("function_names"), name="function_names")
    single_address = params.get("address")
    single_name = params.get("function_name")
    if single_address:
        addresses.insert(0, str(single_address).strip())
    if single_name:
        names.insert(0, str(single_name).strip())
    if len(addresses) + len(names) > MAX_QUERY_FUNCTIONS:
        raise ValueError("at most %d functions may be queried per call" % MAX_QUERY_FUNCTIONS)
    return addresses, names


def _resolve_functions(ctx, addresses, names, *, get_address, find_function_by_name):
    """Resolve every selector to a Function; report all misses at once."""
    functions = []
    seen_entries = set()
    missing = []
    for address_text in addresses:
        function = ctx.function_manager.getFunctionContaining(get_address(ctx, address_text))
        if function is None:
            missing.append(address_text)
            continue
        entry = str(function.getEntryPoint())
        if entry not in seen_entries:
            seen_entries.add(entry)
            functions.append(function)
    for name in names:
        function = find_function_by_name(ctx, name)
        if function is None:
            missing.append(name)
            continue
        entry = str(function.getEntryPoint())
        if entry not in seen_entries:
            seen_entries.add(entry)
            functions.append(function)
    if missing:
        raise LookupError("Function not found: %s" % ", ".join(missing))
    return functions


def _function_symbols_for_query(ctx, params, *, get_address, find_function_by_name):
    HashSet, _, _, _ = _bsim_classes()
    addresses, names = _requested_functions(params)
    if not addresses and not names:
        raise ValueError("address, function_name, addresses, or function_names is required")
    symbols = HashSet()
    for function in _resolve_functions(
        ctx,
        addresses,
        names,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    ):
        symbols.add(function.getSymbol())
    return symbols


def _function_body_size(function):
    body = function.getBody()
    if body is None:
        return 0
    return int(body.getNumAddresses())


def _all_function_symbols(ctx, *, min_function_size=0):
    """Collect every function symbol; return (symbols, skipped_small_functions)."""
    HashSet, _, _, _ = _bsim_classes()
    symbols = HashSet()
    skipped = 0
    threshold = max(0, int(min_function_size or 0))
    iterator = ctx.function_manager.getFunctions(True)
    for function in _iter_items(iterator):
        if threshold and _function_body_size(function) < threshold:
            skipped += 1
            continue
        symbols.add(function.getSymbol())
    return symbols, skipped


def _run_query(ctx, params, function_symbols, *, extra_matches_per_function=0):
    _, SimilarFunctionQueryService, SFQueryInfo, BSimMatchResult = _bsim_classes()
    bsim_url = params.get("bsim_url")
    if not bsim_url:
        raise ValueError("bsim_url is required")
    if int(function_symbols.size()) == 0:
        return []
    service = SimilarFunctionQueryService(ctx.program)
    try:
        service.initializeDatabase(bsim_url)
        query_info = SFQueryInfo(function_symbols)
        query_info.setSimilarityThreshold(float(params.get("similarity_threshold", 0.7)))
        query_info.setSignificanceThreshold(float(params.get("significance_threshold", 0.0)))
        # When self matches are filtered out afterwards, ask for one more row per
        # function so the caller still sees matches_per_function foreign matches.
        query_info.setMaximumResults(int(params.get("matches_per_function", 10)) + int(extra_matches_per_function))
        query = service.generateQueryNearest(query_info, ctx.monitor())
        query.fillinCategories = True
        raw_result = service.queryRaw(query, None, None, ctx.monitor())
        if raw_result is None:
            error = service.getLastError()
            message = "unknown error" if error is None else str(error.message)
            raise HeadlessError("BSIM_QUERY_FAILED: %s" % message)
        rows = BSimMatchResult.generate(raw_result.result, ctx.program)
        return rows
    finally:
        service.dispose()


def _collect_matches(ctx, target, rows, *, exclude_md5=None, matches_per_function=None):
    """Turn BSim rows into sorted match dicts.

    ``exclude_md5`` drops matches against that executable (the query program itself);
    ``matches_per_function`` then re-applies the per-function cap after the drop.
    Returns (matches, excluded_self_matches).
    """
    raw_matches = []
    excluded = 0
    for row in _iter_items(rows):
        original = row.getOriginalFunctionDescription()
        matched = row.getMatchFunctionDescription()
        matched_ref = _matched_ref(matched)
        if exclude_md5 is not None and str(matched_ref.get("executable_md5") or "").lower() == exclude_md5:
            excluded += 1
            continue
        raw_matches.append(
            {
                "query_ref": _query_ref(ctx, target, original),
                "matched_ref": matched_ref,
                "similarity": float(row.getSimilarity()),
                "significance": float(row.getSignificance()),
            }
        )
    raw_matches.sort(
        key=lambda item: (
            -float(item.get("similarity", 0.0)),
            -float(item.get("significance", 0.0)),
            str(item["matched_ref"].get("executable_md5") or ""),
            str(item["matched_ref"].get("address") or ""),
        )
    )
    if matches_per_function is not None and excluded:
        per_function = {}
        capped = []
        cap = max(1, int(matches_per_function))
        for item in raw_matches:
            key = item["query_ref"]["address"]
            count = per_function.get(key, 0)
            if count >= cap:
                continue
            per_function[key] = count + 1
            capped.append(item)
        raw_matches = capped
    return raw_matches, excluded


def _rows_to_result(ctx, params, rows, *, exclude_md5=None, extra=None):
    target = params.get("query_target") or "default"
    limit = max(0, int(params.get("max_results", 500)))
    raw_matches, excluded = _collect_matches(
        ctx,
        target,
        rows,
        exclude_md5=exclude_md5,
        matches_per_function=params.get("matches_per_function", 10),
    )
    matches = raw_matches[:limit]
    result = {
        "target": target,
        "program": _domain_path(ctx.program),
        "matches": matches,
        "count": len(matches),
        "truncated": len(matches) < len(raw_matches),
        "excluded_self_matches": excluded,
    }
    if extra:
        result.update(extra)
    return result


def _self_md5_to_exclude(ctx, params):
    exclude_self = params.get("exclude_self", True)
    if exclude_self is None or not bool(exclude_self):
        return None
    return _program_md5(ctx.program)


def bsim_query_target(params, *, ensure_context):
    ctx = ensure_context()
    min_function_size = int(params.get("min_function_size", 0) or 0)
    symbols, skipped_small = _all_function_symbols(ctx, min_function_size=min_function_size)
    exclude_md5 = _self_md5_to_exclude(ctx, params)
    rows = _run_query(ctx, params, symbols, extra_matches_per_function=1 if exclude_md5 else 0)
    return _rows_to_result(
        ctx,
        params,
        rows,
        exclude_md5=exclude_md5,
        extra={"queried_functions": int(symbols.size()), "skipped_small_functions": skipped_small},
    )


def bsim_query_function(params, *, ensure_context, get_address, find_function_by_name):
    ctx = ensure_context()
    symbols = _function_symbols_for_query(
        ctx,
        params,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    )
    exclude_md5 = _self_md5_to_exclude(ctx, params)
    rows = _run_query(ctx, params, symbols, extra_matches_per_function=1 if exclude_md5 else 0)
    return _rows_to_result(
        ctx,
        params,
        rows,
        exclude_md5=exclude_md5,
        extra={"queried_functions": int(symbols.size()), "skipped_small_functions": 0},
    )


__all__ = ["BSIM_MATCHED_REF_VERSION", "MAX_QUERY_FUNCTIONS", "bsim_query_function", "bsim_query_target"]
