"""Mutating BSim commands for loaded programs."""

from __future__ import absolute_import, print_function


def _ghidra_url_class():
    from ghidra.framework.protocol.ghidra import GhidraURL

    return GhidraURL


def _program_class():
    from ghidra.program.model.listing import Program

    return Program


def _bsim_registration_classes():
    from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
    from ghidra.features.bsim.query.protocol import InsertRequest, QueryExeCount

    return BSimClientFactory, GenSignatures, InsertRequest, QueryExeCount


def _domain_path(program):
    domain_file = program.getDomainFile()
    if domain_file is None:
        return None
    return domain_file.getPathname()


def _program_repository_and_path(program):
    GhidraURL = _ghidra_url_class()
    domain_file = program.getDomainFile()
    if domain_file is None:
        raise RuntimeError("BSIM_UNSAVED_PROGRAM: current program has no DomainFile")
    file_url = domain_file.getSharedProjectURL(None)
    if file_url is None:
        file_url = domain_file.getLocalProjectURL(None)
    if file_url is None:
        raise RuntimeError("BSIM_UNSAVED_PROGRAM: current program has never been saved")
    path = str(GhidraURL.getProjectPathname(file_url))
    last_slash = path.rfind("/")
    path = "/" if last_slash == 0 else path[:last_slash]
    project_url = GhidraURL.getProjectURL(file_url)
    return str(project_url.toExternalForm()), path


def _sort_callgraph(manager):
    iterator = manager.listAllFunctions()
    while iterator.hasNext():
        iterator.next().sortCallgraph()


def bsim_set_target_metadata(params, *, ensure_context, txn):
    Program = _program_class()
    ctx = ensure_context()
    categories = params.get("categories") or {}
    if not isinstance(categories, dict) or not categories:
        raise ValueError("categories must be a non-empty object")

    def _apply():
        options = ctx.program.getOptions(Program.PROGRAM_INFO)
        applied = {}
        for key, value in categories.items():
            text_key = str(key).strip()
            if not text_key:
                raise ValueError("metadata category names must not be empty")
            if value is None:
                continue
            text_value = str(value).strip()
            if not text_value:
                continue
            options.setString(text_key, text_value)
            applied[text_key] = text_value
        if not applied:
            raise ValueError("categories did not contain any non-empty values")
        return applied

    applied_categories = txn(ctx, "Set BSim executable metadata", _apply)
    return {
        "status": "ok",
        "program": _domain_path(ctx.program),
        "categories": applied_categories,
    }


def bsim_register_target(params, *, ensure_context):
    BSimClientFactory, GenSignatures, InsertRequest, QueryExeCount = _bsim_registration_classes()
    ctx = ensure_context()
    bsim_url = params.get("bsim_url")
    if not bsim_url:
        raise ValueError("bsim_url is required")

    url = BSimClientFactory.deriveBSimURL(bsim_url)
    database = BSimClientFactory.buildClient(url, False)
    gensig = None
    try:
        if not bool(database.initialize()):
            last_error = database.getLastError()
            message = "unknown error" if last_error is None else str(last_error.message)
            raise RuntimeError("BSIM_DATABASE_INIT_FAILED: %s" % message)
        db_info = database.getInfo()
        gensig = GenSignatures(bool(db_info.trackcallgraph))
        gensig.setVectorFactory(database.getLSHVectorFactory())
        gensig.addExecutableCategories(db_info.execats)
        gensig.addFunctionTags(db_info.functionTags)
        gensig.addDateColumnName(db_info.dateColumnName)
        repo, path = _program_repository_and_path(ctx.program)
        gensig.openProgram(ctx.program, None, None, None, repo, path)
        function_manager = ctx.program.getFunctionManager()
        iterator = function_manager.getFunctions(True)
        gensig.scanFunctions(iterator, function_manager.getFunctionCount(), ctx.monitor())
        manager = gensig.getDescriptionManager()
        if manager.numFunctions() == 0:
            raise RuntimeError("BSIM_NO_FUNCTIONS: program contains no functions with bodies")
        _sort_callgraph(manager)
        insert_request = InsertRequest()
        insert_request.manage = manager
        response = insert_request.execute(database)
        if response is None:
            last_error = database.getLastError()
            message = "unknown error" if last_error is None else str(last_error.message)
            raise RuntimeError("BSIM_INSERT_FAILED: %s" % message)
        count_query = QueryExeCount()
        count_response = count_query.execute(database)
        executable_count = None if count_response is None else int(count_response.recordCount)
        return {
            "status": "ok",
            "program": _domain_path(ctx.program),
            "repository": repo,
            "path": path,
            "inserted_executables": int(response.numexe),
            "inserted_functions": int(response.numfunc),
            "executable_count": executable_count,
        }
    finally:
        if gensig is not None:
            gensig.dispose()
        database.close()


__all__ = ["bsim_register_target", "bsim_set_target_metadata"]
