"""Lazy JVM class bindings for session helpers."""

from __future__ import annotations

import pyghidra.core as pycore

_FLAT_API_CLASS = None
_CONSOLE_MONITOR_CLASS = None
_DEFAULT_CHECKIN_HANDLER_CLASS = None
_PROGRAM_DIFF_CLASS = None
_PROGRAM_DIFF_FILTER_CLASS = None
_JAVA_OBJECT_CLASS = None


def _flat_program_api_class():
    global _FLAT_API_CLASS
    if _FLAT_API_CLASS is None:
        _FLAT_API_CLASS = pycore.JClass("ghidra.program.flatapi.FlatProgramAPI")
    return _FLAT_API_CLASS


def _console_monitor():
    global _CONSOLE_MONITOR_CLASS
    if _CONSOLE_MONITOR_CLASS is None:
        _CONSOLE_MONITOR_CLASS = pycore.JClass("ghidra.util.task.ConsoleTaskMonitor")
    return _CONSOLE_MONITOR_CLASS()


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

