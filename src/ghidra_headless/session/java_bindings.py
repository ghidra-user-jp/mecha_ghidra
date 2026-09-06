"""Lazy JVM class bindings for session helpers."""

from __future__ import annotations

import pyghidra.core as pycore

_FLAT_API_CLASS = None
_CONSOLE_MONITOR_CLASS = None
_DEFAULT_CHECKIN_HANDLER_CLASS = None
_PROGRAM_DIFF_CLASS = None
_PROGRAM_DIFF_FILTER_CLASS = None
_PROGRAM_DIFF_DETAILS_CLASS = None
_JAVA_OBJECT_CLASS = None
_GHIDRA_PROGRAM_UTILITIES_CLASS = None
_GHIDRA_SCRIPT_UTIL_CLASS = None
_TIMEOUT_TASK_MONITOR_CLASS = None
_TIME_UNIT_CLASS = None


def _flat_program_api_class():
    global _FLAT_API_CLASS
    if _FLAT_API_CLASS is None:
        _FLAT_API_CLASS = pycore.JClass("ghidra.program.flatapi.FlatProgramAPI")
    return _FLAT_API_CLASS


def _console_monitor():
    """Return a silent task monitor.

    The name is historical: the previous ``ConsoleTaskMonitor`` printed progress
    to Java's ``System.out``, which is the same descriptor the MCP stdio
    transport uses for JSON-RPC framing.
    """
    global _CONSOLE_MONITOR_CLASS
    if _CONSOLE_MONITOR_CLASS is None:
        _CONSOLE_MONITOR_CLASS = pycore.JClass("ghidra.util.task.TaskMonitor")
    return _CONSOLE_MONITOR_CLASS.DUMMY


def _timeout_task_monitor(*, timeout_seconds: int = 60):
    global _TIMEOUT_TASK_MONITOR_CLASS
    global _TIME_UNIT_CLASS
    normalized_timeout = int(timeout_seconds)
    if normalized_timeout < 1:
        raise ValueError("timeout_seconds must be >= 1")
    if _TIMEOUT_TASK_MONITOR_CLASS is None:
        _TIMEOUT_TASK_MONITOR_CLASS = pycore.JClass("ghidra.util.task.TimeoutTaskMonitor")
    if _TIME_UNIT_CLASS is None:
        _TIME_UNIT_CLASS = pycore.JClass("java.util.concurrent.TimeUnit")
    return _TIMEOUT_TASK_MONITOR_CLASS.timeoutIn(
        normalized_timeout,
        _TIME_UNIT_CLASS.SECONDS,
        _console_monitor(),
    )


def _default_checkin_handler_class():
    global _DEFAULT_CHECKIN_HANDLER_CLASS
    if _DEFAULT_CHECKIN_HANDLER_CLASS is None:
        _DEFAULT_CHECKIN_HANDLER_CLASS = pycore.JClass("ghidra.framework.data.DefaultCheckinHandler")
    return _DEFAULT_CHECKIN_HANDLER_CLASS


def _program_diff_class():
    global _PROGRAM_DIFF_CLASS
    if _PROGRAM_DIFF_CLASS is None:
        _PROGRAM_DIFF_CLASS = pycore.JClass("ghidra.program.util.ProgramDiff")
    return _PROGRAM_DIFF_CLASS


def _program_diff_details_class():
    global _PROGRAM_DIFF_DETAILS_CLASS
    if _PROGRAM_DIFF_DETAILS_CLASS is None:
        _PROGRAM_DIFF_DETAILS_CLASS = pycore.JClass("ghidra.program.util.ProgramDiffDetails")
    return _PROGRAM_DIFF_DETAILS_CLASS


def _program_diff_filter_class():
    global _PROGRAM_DIFF_FILTER_CLASS
    if _PROGRAM_DIFF_FILTER_CLASS is None:
        _PROGRAM_DIFF_FILTER_CLASS = pycore.JClass("ghidra.program.util.ProgramDiffFilter")
    return _PROGRAM_DIFF_FILTER_CLASS


def _java_object():
    global _JAVA_OBJECT_CLASS
    if _JAVA_OBJECT_CLASS is None:
        _JAVA_OBJECT_CLASS = pycore.JClass("java.lang.Object")
    return _JAVA_OBJECT_CLASS()


def _ghidra_program_utilities():
    global _GHIDRA_PROGRAM_UTILITIES_CLASS
    if _GHIDRA_PROGRAM_UTILITIES_CLASS is None:
        _GHIDRA_PROGRAM_UTILITIES_CLASS = pycore.JClass("ghidra.program.util.GhidraProgramUtilities")
    return _GHIDRA_PROGRAM_UTILITIES_CLASS


def _ghidra_script_util():
    global _GHIDRA_SCRIPT_UTIL_CLASS
    if _GHIDRA_SCRIPT_UTIL_CLASS is None:
        _GHIDRA_SCRIPT_UTIL_CLASS = pycore.JClass("ghidra.app.script.GhidraScriptUtil")
    return _GHIDRA_SCRIPT_UTIL_CLASS
