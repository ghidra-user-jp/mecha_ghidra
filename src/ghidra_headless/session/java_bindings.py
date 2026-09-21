"""Lazy JVM class bindings for session helpers.

Each binding is a cached zero-argument function: the ``JClass`` lookup runs on
first use (after the JVM is up) and never again.  ``functools.cache`` replaces
the former module-level ``global`` caches so that no module carries mutable
state.
"""

from __future__ import annotations

from functools import cache

import jpype


@cache
def _flat_program_api_class():
    return jpype.JClass("ghidra.program.flatapi.FlatProgramAPI")


@cache
def _task_monitor_class():
    return jpype.JClass("ghidra.util.task.TaskMonitor")


def _console_monitor():
    """Return a silent task monitor.

    The name is historical: the previous ``ConsoleTaskMonitor`` printed progress
    to Java's ``System.out``, which is the same descriptor the MCP stdio
    transport uses for JSON-RPC framing.
    """
    return _task_monitor_class().DUMMY


@cache
def _timeout_task_monitor_class():
    return jpype.JClass("ghidra.util.task.TimeoutTaskMonitor")


@cache
def _time_unit_class():
    return jpype.JClass("java.util.concurrent.TimeUnit")


def _timeout_task_monitor(*, timeout_seconds: int = 60):
    normalized_timeout = int(timeout_seconds)
    if normalized_timeout < 1:
        raise ValueError("timeout_seconds must be >= 1")
    return _timeout_task_monitor_class().timeoutIn(
        normalized_timeout,
        _time_unit_class().SECONDS,
        _console_monitor(),
    )


@cache
def _default_checkin_handler_class():
    return jpype.JClass("ghidra.framework.data.DefaultCheckinHandler")


@cache
def _program_diff_class():
    return jpype.JClass("ghidra.program.util.ProgramDiff")


@cache
def _program_diff_details_class():
    return jpype.JClass("ghidra.program.util.ProgramDiffDetails")


@cache
def _program_diff_filter_class():
    return jpype.JClass("ghidra.program.util.ProgramDiffFilter")


@cache
def _java_object_class():
    return jpype.JClass("java.lang.Object")


def _java_object():
    return _java_object_class()()


@cache
def _ghidra_program_utilities():
    return jpype.JClass("ghidra.program.util.GhidraProgramUtilities")


@cache
def _ghidra_script_util():
    return jpype.JClass("ghidra.app.script.GhidraScriptUtil")
