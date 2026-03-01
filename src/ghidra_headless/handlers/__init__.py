"""Ghidra操作用ハンドラのエントリーポイント。"""

from __future__ import absolute_import, print_function


def __getattr__(name):
    if name == "HANDLERS":
        from .core import HANDLERS

        return HANDLERS
    raise AttributeError(name)

__all__ = ["HANDLERS"]
