from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from ghidra_mcp.application.locks import KeyedLockPool, LockManager
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.session_store import RuntimeSessionStore


def test_keyed_lock_pool_evicts_every_entry_after_heavy_contention():
    pool = KeyedLockPool()
    counter = {"value": 0}

    def work(index: int) -> None:
        key = f"key-{index % 4}"
        for _ in range(200):
            with pool.acquire(key, timeout=5.0):
                counter["value"] += 1

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(work, range(16)))

    assert counter["value"] == 16 * 200
    assert pool.active_count == 0


def test_lock_manager_serializes_same_target_across_threads():
    manager = LockManager()
    inside = {"count": 0, "max": 0}
    guard = threading.Lock()

    def work(_: int) -> None:
        for _ in range(50):
            with manager.acquire(target="fw", project_key="p", timeout=5.0):
                with guard:
                    inside["count"] += 1
                    inside["max"] = max(inside["max"], inside["count"])
                with guard:
                    inside["count"] -= 1

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(work, range(8)))

    assert inside["max"] == 1
    assert manager.cached_lock_counts == {"target": 0, "project": 0}


class _CountingHandle:
    instances = 0
    lock = threading.Lock()

    def __init__(self, location: str, name: str) -> None:
        with _CountingHandle.lock:
            _CountingHandle.instances += 1
        self.key = (location, name)
        self.closed = False

    def get_key(self):
        return self.key

    def is_closed(self):
        return self.closed

    def close(self):
        self.closed = True


def test_get_or_create_project_handle_converges_on_one_live_handle(monkeypatch):
    from ghidra_mcp.infrastructure.ghidra_adapter.runtime import session_store as module

    monkeypatch.setattr(module, "ProjectHandle", _CountingHandle)
    _CountingHandle.instances = 0
    state = RuntimeState(
        core_accessor=lambda: None, checkout_required_commands=set(), normalize_result=lambda value: value
    )
    store = RuntimeSessionStore(state=state, core_accessor=lambda: None)
    key = ("/tmp/prj", "sample")
    barrier = threading.Barrier(8)
    results: list[object] = []
    results_lock = threading.Lock()

    def work() -> None:
        barrier.wait(timeout=5.0)
        handle = store.get_or_create_project_handle(key)
        with results_lock:
            results.append(handle)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)

    assert len(results) == 8
    assert len({id(handle) for handle in results}) == 1
    assert store.project_handles[key] is results[0]
    # Losing racers must close their duplicate handle instead of leaking it.
    assert _CountingHandle.instances >= 1
    assert all(handle.closed for handle in [store.project_handles[key]]) is False
