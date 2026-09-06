"""Fakes shared by the runtime test modules (session store, lifecycle, sync)."""

from __future__ import annotations


class FakeDomainFile:
    def __init__(self, path: str) -> None:
        self._path = path

    def getPathname(self) -> str:
        return self._path


class FakeProgram:
    def __init__(self, path: str, *, changed: bool = False) -> None:
        self._path = path
        self._changed = changed

    def getDomainFile(self) -> FakeDomainFile:
        return FakeDomainFile(self._path)

    def isChanged(self) -> bool:
        return self._changed

    def startTransaction(self, _description: str) -> int:
        return 1

    def endTransaction(self, _transaction_id: int, _commit: bool) -> None:
        return None
