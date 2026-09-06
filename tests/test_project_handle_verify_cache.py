from __future__ import annotations

import pytest

from ghidra_headless.session import project_handle as module


class _Repository:
    def __init__(self, *, verified: bool = True) -> None:
        self.verified = verified
        self.verify_calls = 0
        self.connected_calls = 0

    def isConnected(self) -> bool:
        self.connected_calls += 1
        return True

    def verifyConnection(self) -> bool:
        self.verify_calls += 1
        return self.verified


def _handle(repository: _Repository, monkeypatch: pytest.MonkeyPatch) -> module.ProjectHandle:
    handle = module.ProjectHandle.__new__(module.ProjectHandle)
    handle.project_location = "/tmp/prj"
    handle.project_name = "sample"
    handle._closed = False
    handle._repository_verified_at = None
    monkeypatch.setattr(module.ProjectHandle, "is_repository_project_from_metadata", staticmethod(lambda *_a: True))
    monkeypatch.setattr(handle, "_get_repository_adapter_locked", lambda: repository)
    return handle


def test_verification_is_reused_within_the_interval(monkeypatch):
    repository = _Repository()
    handle = _handle(repository, monkeypatch)
    monkeypatch.setattr(module.ProjectHandle, "repository_verify_interval_seconds", 60.0)

    for _ in range(5):
        assert handle._ensure_repository_connected_locked(required=True) is True

    assert repository.verify_calls == 1
    assert repository.connected_calls == 5


def test_interval_zero_verifies_every_call(monkeypatch):
    repository = _Repository()
    handle = _handle(repository, monkeypatch)
    monkeypatch.setattr(module.ProjectHandle, "repository_verify_interval_seconds", 0.0)

    for _ in range(3):
        handle._ensure_repository_connected_locked(required=True)

    assert repository.verify_calls == 3


def test_failed_verification_is_not_cached(monkeypatch):
    repository = _Repository(verified=False)
    handle = _handle(repository, monkeypatch)
    monkeypatch.setattr(module.ProjectHandle, "repository_verify_interval_seconds", 60.0)

    with pytest.raises(RuntimeError, match="REPOSITORY_CONNECT_FAILED"):
        handle._ensure_repository_connected_locked(required=True)
    repository.verified = True
    assert handle._ensure_repository_connected_locked(required=True) is True
    assert repository.verify_calls == 2


def test_cache_expires_after_the_interval(monkeypatch):
    repository = _Repository()
    handle = _handle(repository, monkeypatch)
    monkeypatch.setattr(module.ProjectHandle, "repository_verify_interval_seconds", 10.0)
    clock = {"now": 1000.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])

    handle._ensure_repository_connected_locked(required=True)
    clock["now"] += 5.0
    handle._ensure_repository_connected_locked(required=True)
    clock["now"] += 6.0
    handle._ensure_repository_connected_locked(required=True)

    assert repository.verify_calls == 2
