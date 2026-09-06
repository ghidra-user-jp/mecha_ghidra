"""Program-level commands: metadata, comments, symbol search, labels, undo/redo, export."""

from __future__ import absolute_import, print_function

import pathlib

from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.commands.pagination import normalize_pagination

MAX_UNDO_STEPS = 100
MAX_ENTRY_POINTS = 50
EXPORT_FORMATS = ("gzf", "binary")
_COMMENT_KINDS = (
    ("pre", "PRE_COMMENT"),
    ("eol", "EOL_COMMENT"),
    ("post", "POST_COMMENT"),
    ("plate", "PLATE_COMMENT"),
    ("repeatable", "REPEATABLE_COMMENT"),
)


def _text(value):
    return None if value is None else str(value)


def get_program_info(params, *, ensure_context, safe_call, iter_items):
    """Describe the loaded program: identity, language, layout, analysis and undo state."""
    ctx = ensure_context()
    program = ctx.program
    language = program.getLanguage()
    description = safe_call(language, "getLanguageDescription")
    memory = program.getMemory()
    domain_file = safe_call(program, "getDomainFile")
    options = program.getOptions("Program Information")
    entry_points = []
    for address in iter_items(ctx.symbol_table.getExternalEntryPointIterator()):
        if len(entry_points) >= MAX_ENTRY_POINTS:
            break
        symbol = ctx.symbol_table.getPrimarySymbol(address)
        entry_points.append({"address": str(address), "name": None if symbol is None else str(symbol.getName(True))})
    blocks = list(iter_items(memory.getBlocks()))
    return {
        "name": str(program.getName()),
        "domain_path": None if domain_file is None else _text(safe_call(domain_file, "getPathname")),
        "executable_path": _text(safe_call(program, "getExecutablePath")),
        "executable_format": _text(safe_call(program, "getExecutableFormat")),
        "executable_md5": _text(safe_call(program, "getExecutableMD5")),
        "executable_sha256": _text(safe_call(program, "getExecutableSHA256")),
        "language_id": str(language.getLanguageID()),
        "processor": _text(safe_call(language, "getProcessor")),
        "address_size": None if description is None else safe_call(description, "getSize"),
        "is_big_endian": bool(safe_call(language, "isBigEndian")),
        "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": _text(safe_call(program, "getImageBase")),
        "min_address": _text(safe_call(program, "getMinAddress")),
        "max_address": _text(safe_call(program, "getMaxAddress")),
        "memory_size": int(memory.getSize()),
        "memory_block_count": len(blocks),
        "function_count": int(ctx.function_manager.getFunctionCount()),
        "symbol_count": safe_call(ctx.symbol_table, "getNumSymbols"),
        "entry_points": entry_points,
        # Read only options that exist: getBoolean/getString on a missing option would
        # register it, which is a write and needs a transaction.
        "is_analyzed": bool(options.contains("Analyzed") and options.getBoolean("Analyzed", False)),
        "created_with_ghidra_version": (
            _text(options.getString("Created With Ghidra Version", None))
            if options.contains("Created With Ghidra Version")
            else None
        ),
        "creation_date": _text(safe_call(program, "getCreationDate")),
        "has_unsaved_changes": bool(safe_call(program, "isChanged")),
        "can_undo": bool(safe_call(program, "canUndo")),
        "can_redo": bool(safe_call(program, "canRedo")),
    }


def get_comments(params, *, ensure_context, get_address, code_unit):
    """Return every comment slot at an address (None when a slot is empty)."""
    ctx = ensure_context()
    address_text = params.get("address")
    address = get_address(ctx, address_text)
    result = {"address": address_text}
    for kind, attribute in _COMMENT_KINDS:
        comment = ctx.listing.getComment(getattr(code_unit, attribute), address)
        result[kind] = None if comment is None else str(comment)
    return result


def _symbol_entry(symbol, safe_call):
    namespace = safe_call(symbol, "getParentNamespace")
    return {
        "name": str(symbol.getName()),
        "full_name": str(symbol.getName(True)),
        "address": str(symbol.getAddress()),
        "type": _text(safe_call(symbol, "getSymbolType")),
        "namespace": None if namespace is None else str(namespace.getName(True)),
        "source": _text(safe_call(symbol, "getSource")),
        "is_primary": bool(safe_call(symbol, "isPrimary")),
    }


def search_symbols(params, *, ensure_context, to_int, iter_items, safe_call):
    """Case-insensitive symbol search; ``*`` and ``?`` in query are Ghidra globs."""
    ctx = ensure_context()
    query = str(params.get("query") or "").strip()
    if not query:
        raise ValueError("query is required")
    offset, limit = normalize_pagination(params, to_int, 100)
    symbol_type = str(params.get("type") or "").strip().lower() or None
    pattern = query if any(marker in query for marker in "*?") else "*%s*" % query
    iterator = ctx.symbol_table.getSymbolIterator(pattern, False)
    items = []
    idx = 0
    for symbol in iter_items(iterator):
        if symbol_type is not None:
            kind = _text(safe_call(symbol, "getSymbolType"))
            if kind is None or kind.lower() != symbol_type:
                continue
        if idx >= offset:
            items.append(_symbol_entry(symbol, safe_call))
            if len(items) >= limit:
                break
        idx += 1
    return items


def create_label(params, *, ensure_context, get_address, txn, source_type):
    """Create a user label at an address; an existing label of that name is reused."""
    ctx = ensure_context()
    address_text = params.get("address")
    name = str(params.get("name") or "").strip()
    if not address_text or not name:
        raise ValueError("address and name are required")
    make_primary = params.get("make_primary", True)
    make_primary = True if make_primary is None else bool(make_primary)
    address = get_address(ctx, address_text)

    def _create():
        symbol = ctx.symbol_table.createLabel(address, name, source_type.USER_DEFINED)
        if symbol is None:
            raise RuntimeError("Failed to create label %s at %s" % (name, address_text))
        if make_primary and not bool(symbol.isPrimary()):
            symbol.setPrimary()
        return symbol

    symbol = txn(ctx, "Create label", _create)
    return {
        "name": str(symbol.getName()),
        "address": str(symbol.getAddress()),
        "is_primary": bool(symbol.isPrimary()),
    }


def _undo_count(params):
    raw = params.get("count")
    count = 1 if raw is None else int(raw)
    if count < 1 or count > MAX_UNDO_STEPS:
        raise ValueError("count must be between 1 and %d" % MAX_UNDO_STEPS)
    return count


def _names(program, method, safe_call, iter_items):
    values = safe_call(program, method)
    if values is None:
        return []
    return [str(item) for item in iter_items(values)]


def _undo_state(program, safe_call, iter_items):
    return {
        "can_undo": bool(safe_call(program, "canUndo")),
        "can_redo": bool(safe_call(program, "canRedo")),
        "remaining_undo": _names(program, "getAllUndoNames", safe_call, iter_items)[:20],
        "remaining_redo": _names(program, "getAllRedoNames", safe_call, iter_items)[:20],
    }


def undo_program_change(params, *, ensure_context, safe_call, iter_items):
    """Undo the most recent ``count`` transactions on the loaded program."""
    ctx = ensure_context()
    program = ctx.program
    count = _undo_count(params)
    undone = []
    for _ in range(count):
        if not bool(program.canUndo()):
            break
        name = safe_call(program, "getUndoName")
        program.undo()
        undone.append(_text(name))
    result = {"status": "ok" if undone else "noop", "undone": undone, "undone_count": len(undone)}
    result.update(_undo_state(program, safe_call, iter_items))
    return result


def redo_program_change(params, *, ensure_context, safe_call, iter_items):
    """Redo up to ``count`` previously undone transactions."""
    ctx = ensure_context()
    program = ctx.program
    count = _undo_count(params)
    redone = []
    for _ in range(count):
        if not bool(program.canRedo()):
            break
        name = safe_call(program, "getRedoName")
        program.redo()
        redone.append(_text(name))
    result = {"status": "ok" if redone else "noop", "redone": redone, "redone_count": len(redone)}
    result.update(_undo_state(program, safe_call, iter_items))
    return result


def _exporter_for(export_format):
    if export_format == "gzf":
        from ghidra.app.util.exporter import GzfExporter

        return GzfExporter()
    if export_format == "binary":
        from ghidra.app.util.exporter import BinaryExporter

        return BinaryExporter()
    raise ValueError("format must be one of: %s" % ", ".join(EXPORT_FORMATS))


def export_program(params, *, ensure_context, safe_call):
    """Write the loaded program to ``output_path`` as a .gzf archive or raw bytes.

    The path policy check happens in the application layer before this runs.
    A .gzf packs the program's saved state, so unsaved edits are reported but
    not included; call save_project_program first when they matter.
    """
    ctx = ensure_context()
    output_path = str(params.get("output_path") or "").strip()
    if not output_path:
        raise ValueError("output_path is required")
    export_format = str(params.get("format") or "gzf").strip().lower()
    if export_format not in EXPORT_FORMATS:
        raise ValueError("format must be one of: %s" % ", ".join(EXPORT_FORMATS))
    overwrite = bool(params.get("overwrite", False))
    path = pathlib.Path(output_path).expanduser()
    if path.exists():
        if path.is_dir():
            raise ValueError("EXPORT_TARGET_IS_DIRECTORY: output_path must name a file")
        if not overwrite:
            raise HeadlessError("EXPORT_TARGET_EXISTS: %s exists; pass overwrite=true to replace it" % path)
    elif not path.parent.is_dir():
        raise HeadlessError("EXPORT_DIRECTORY_MISSING: %s does not exist" % path.parent)

    from java.io import File

    exporter = _exporter_for(export_format)
    ok = bool(exporter.export(File(str(path)), ctx.program, None, ctx.monitor()))
    log = safe_call(exporter, "getMessageLog")
    messages = None if log is None else str(log).strip() or None
    if not ok:
        raise HeadlessError("EXPORT_FAILED: %s" % (messages or "exporter returned false"))
    return {
        "status": "ok",
        "output_path": str(path),
        "format": export_format,
        "bytes_written": path.stat().st_size if path.exists() else None,
        "has_unsaved_changes": bool(safe_call(ctx.program, "isChanged")),
        "messages": messages,
    }


__all__ = [
    "EXPORT_FORMATS",
    "MAX_UNDO_STEPS",
    "create_label",
    "export_program",
    "get_comments",
    "get_program_info",
    "redo_program_change",
    "search_symbols",
    "undo_program_change",
]
