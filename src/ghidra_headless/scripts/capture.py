"""Bounded capture of a script's console output.

``ScriptControls`` takes ``java.io.PrintWriter`` instances.  A ``StringWriter``
would grow without bound while the script runs, so the writers here sit on a
``WritableByteChannel`` implemented in Python: every write is truncated at the
configured limit while it happens and the number of dropped bytes is counted.

The proxy class is created lazily because ``@JImplements`` needs a running
JVM; importing this module must stay JVM-free for the unit tests.
"""

from __future__ import annotations

import contextlib
import functools
import threading

import jpype


@functools.cache
def _bounded_channel_class():
    from jpype import JImplements, JOverride

    @JImplements("java.nio.channels.WritableByteChannel")
    class _BoundedChannel:
        def __init__(self, limit: int) -> None:
            self._limit = max(0, int(limit))
            self._buffer = bytearray()
            self._dropped = 0
            self._open = True
            self._lock = threading.Lock()

        @JOverride
        def write(self, src):
            remaining = int(src.remaining())
            if remaining <= 0:
                return 0
            with self._lock:
                room = self._limit - len(self._buffer)
                kept = min(room, remaining)
                if kept:
                    array = jpype.JArray(jpype.JByte)(kept)
                    src.get(array)
                    try:
                        data = bytes(array)
                    except Exception:
                        data = bytes(int(value) & 0xFF for value in array)
                    self._buffer += data
                if kept < remaining:
                    src.position(src.limit())
                self._dropped += remaining - kept
            return remaining

        @JOverride
        def isOpen(self):
            return self._open

        @JOverride
        def close(self):
            self._open = False

        def snapshot(self) -> tuple[bytes, int]:
            with self._lock:
                return bytes(self._buffer), self._dropped

    return _BoundedChannel


class BoundedCapture:
    """A bounded UTF-8 text sink exposed as a Java ``PrintWriter``."""

    def __init__(self, limit_bytes: int) -> None:
        self.limit_bytes = int(limit_bytes)
        self._channel = _bounded_channel_class()(self.limit_bytes)
        channels = jpype.JClass("java.nio.channels.Channels")
        output_stream_writer = jpype.JClass("java.io.OutputStreamWriter")
        print_writer = jpype.JClass("java.io.PrintWriter")
        charsets = jpype.JClass("java.nio.charset.StandardCharsets")
        self._stream = channels.newOutputStream(self._channel)
        self.writer = print_writer(output_stream_writer(self._stream, charsets.UTF_8), True)

    def flush(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.flush()

    def text(self) -> str:
        self.flush()
        data, _ = self._channel.snapshot()
        return data.decode("utf-8", errors="replace")

    def dropped_bytes(self) -> int:
        self.flush()
        _, dropped = self._channel.snapshot()
        return dropped

    def describe(self) -> dict:
        self.flush()
        data, dropped = self._channel.snapshot()
        return {
            "text": data.decode("utf-8", errors="replace"),
            "truncated": dropped > 0,
            "dropped_bytes": dropped,
            "limit_bytes": self.limit_bytes,
        }


__all__ = ["BoundedCapture"]
