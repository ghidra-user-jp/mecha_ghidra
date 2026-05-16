"""Read-only BSim commands for loaded programs."""

from __future__ import absolute_import, print_function

import pathlib


BSIM_MATCHED_REF_VERSION = 1


def _bsim_classes():
    from java.util import HashSet

    from ghidra.features.bsim.gui.search.results import BSimMatchResult
    from ghidra.features.bsim.query.facade import SFQueryInfo, SimilarFunctionQueryService

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
        for item in items:
            yield item
    except Exception:
        return


def _domain_path(program):
    domain_file = program.getDomainFile()
    if domain_file is None:
        return None
    return domain_file.getPathname()


def _category_map(record):
    result = {}
    get_all = getattr(record, "getAllCategories", None)
    if get_all is None:
        return result
    for category in _iter_items(get_all()):
        key = str(category.getType())
        result.setdefault(key, []).append(str(category.getCategory()))
    return result


def _matched_domain_path(record):
    raw_path = record.getPath()
    name = str(record.getNameExec())
    if raw_path is None or not str(raw_path).strip():
        return "/" + name
    path = pathlib.PurePosixPath(str(raw_path))
    if not path.is_absolute():
        path = pathlib.PurePosixPath("/") / path
    if path.name == name:
        return path.as_posix()
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
        "address": "0x%x" % int(function_description.getAddress()),
        "name": str(function_description.getFunctionName()),
        "is_library": bool(record.isLibrary()),
        "categories": _category_map(record),
    }


def _query_ref(ctx, target, function_description):
    return {
        "target": target,
        "domain_path": _domain_path(ctx.program),
        "address": "0x%x" % int(function_description.getAddress()),
        "name": str(function_description.getFunctionName()),
    }


def _function_symbols_for_query(ctx, params, *, get_address, find_function_by_name):
    HashSet, _, _, _ = _bsim_classes()
    address_text = params.get("address")
    function_name = params.get("function_name")
    if address_text:
        address = get_address(ctx, address_text)
        function = ctx.function_manager.getFunctionContaining(address)
        if function is None:
            raise LookupError("Function not found: %s" % address_text)
        symbols = HashSet()
        symbols.add(function.getSymbol())
        return symbols
    if function_name:
        function = find_function_by_name(ctx, function_name)
        if function is None:
            raise LookupError("Function not found: %s" % function_name)
        symbols = HashSet()
        symbols.add(function.getSymbol())
        return symbols
    raise ValueError("address or function_name is required")


def _all_function_symbols(ctx):
    HashSet, _, _, _ = _bsim_classes()
    symbols = HashSet()
    iterator = ctx.function_manager.getFunctions(True)
    for function in _iter_items(iterator):
        symbols.add(function.getSymbol())
    return symbols


def _run_query(ctx, params, function_symbols):
    _, SimilarFunctionQueryService, SFQueryInfo, BSimMatchResult = _bsim_classes()
    bsim_url = params.get("bsim_url")
    if not bsim_url:
        raise ValueError("bsim_url is required")
    service = SimilarFunctionQueryService(ctx.program)
    try:
        service.initializeDatabase(bsim_url)
        query_info = SFQueryInfo(function_symbols)
        query_info.setSimilarityThreshold(float(params.get("similarity_threshold", 0.7)))
        query_info.setSignificanceThreshold(float(params.get("significance_threshold", 0.0)))
        query_info.setMaximumResults(int(params.get("matches_per_function", 10)))
        query = service.generateQueryNearest(query_info, ctx.monitor())
        query.fillinCategories = True
        raw_result = service.queryRaw(query, None, None, ctx.monitor())
        if raw_result is None:
            error = service.getLastError()
            message = "unknown error" if error is None else str(error.message)
            raise RuntimeError("BSIM_QUERY_FAILED: %s" % message)
        rows = BSimMatchResult.generate(raw_result.result, ctx.program)
        return rows
    finally:
        service.dispose()


def _rows_to_result(ctx, params, rows):
    target = params.get("query_target") or "default"
    limit = max(0, int(params.get("max_results", 500)))
    raw_matches = []
    for row in _iter_items(rows):
        original = row.getOriginalFunctionDescription()
        matched = row.getMatchFunctionDescription()
        raw_matches.append(
            {
                "query_ref": _query_ref(ctx, target, original),
                "matched_ref": _matched_ref(matched),
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
    matches = raw_matches[:limit]
    return {
        "target": target,
        "program": _domain_path(ctx.program),
        "matches": matches,
        "count": len(matches),
        "truncated": len(matches) < len(raw_matches),
    }


def bsim_query_target(params, *, ensure_context):
    ctx = ensure_context()
    symbols = _all_function_symbols(ctx)
    rows = _run_query(ctx, params, symbols)
    return _rows_to_result(ctx, params, rows)


def bsim_query_function(params, *, ensure_context, get_address, find_function_by_name):
    ctx = ensure_context()
    symbols = _function_symbols_for_query(
        ctx,
        params,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    )
    rows = _run_query(ctx, params, symbols)
    return _rows_to_result(ctx, params, rows)


__all__ = ["BSIM_MATCHED_REF_VERSION", "bsim_query_function", "bsim_query_target"]
