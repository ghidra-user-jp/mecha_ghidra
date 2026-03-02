"""Helpers for managing Ghidra projects/programs via PyGhidra."""

from __future__ import annotations

from . import java_bindings, path_utils, project_handle, sync_utils
from .java_bindings import (
    _console_monitor,
    _default_checkin_handler_class,
    _flat_program_api_class,
    _java_object,
    _program_diff_class,
    _program_diff_filter_class,
)
from .models import ProgramSession
from .path_utils import (
    _collect_program_files,
    _collect_program_files_from_idata,
    _domain_path,
    _find_first_program_path,
    _parse_domain_path,
    _read_prp_basic_info,
    _to_iso8601_utc,
)
from .project_handle import ProjectHandle
from .sync_utils import (
    _collect_diff_ranges,
    _collect_diff_type_counts,
    _get_version_history_entries,
    _release_domain_object,
    _required_call,
    _safe_call,
    _sync_status_from_domain_file,
    _to_checkout_status_dict,
)

__all__ = ["ProgramSession", "ProjectHandle"]
