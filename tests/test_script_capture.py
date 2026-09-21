"""Bounded output behavior without a JVM; allocation checks prevent copying discarded output."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from ghidra_headless.scripts import capture


class _Buffer:
    def __init__(self, data, start=0, end=None):
        self.data = data
        self.offset = start
        self.end = len(data) if end is None else end

    def remaining(self):
        return self.end - self.offset

    def get(self, array):
        size = len(array)
        assert size <= self.remaining()
        array[:] = self.data[self.offset : self.offset + size]
        self.offset += size

    def limit(self):
        return self.end

    def position(self, value):
        assert self.offset <= value <= self.end
        self.offset = value


@pytest.fixture
def channel_factory(monkeypatch):
    allocations = []

    def array(size):
        allocations.append(size)
        return bytearray(size)

    capture._bounded_channel_class.cache_clear()
    monkeypatch.setattr(capture.jpype, "JImplements", lambda _name: lambda cls: cls)
    monkeypatch.setattr(capture.jpype, "JOverride", lambda method: method)
    monkeypatch.setattr(capture.jpype, "JArray", lambda _type: array)
    return capture._bounded_channel_class(), allocations


def test_capture_copies_only_retained_bytes_and_consumes_the_buffer_slice(channel_factory):
    factory, allocations = channel_factory
    channel = factory(5)
    first = _Buffer(b"--abcd--", 2, 6)
    assert channel.write(first) == 4
    second = _Buffer(b"-efgh-", 1, 5)
    assert channel.write(second) == 4
    full = _Buffer(b"discarded")
    assert channel.write(full) == 9
    assert [first.offset, second.offset, full.offset] == [6, 5, 9]
    assert channel.snapshot() == (b"abcde", 12)
    assert allocations == [4, 1]


def test_zero_capacity_and_empty_buffers_do_not_allocate(channel_factory):
    factory, allocations = channel_factory
    channel = factory(0)
    full = _Buffer(b"abcd")
    assert channel.write(full) == 4
    assert full.remaining() == 0
    assert channel.write(_Buffer(b"")) == 0
    assert channel.snapshot() == (b"", 4)
    assert allocations == []


def test_concurrent_capture_keeps_limit_and_exact_dropped_count(channel_factory):
    factory, allocations = channel_factory
    channel = factory(31)

    def write(index):
        buffer = _Buffer(bytes([index]) * 8)
        assert channel.write(buffer) == 8
        assert buffer.remaining() == 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(32)))
    kept, dropped = channel.snapshot()
    assert len(kept) == 31
    assert dropped == 32 * 8 - 31
    assert sum(allocations) == 31
