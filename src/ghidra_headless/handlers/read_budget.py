"""Per-read deadlines; never abandon a running Ghidra call or release its lock."""

import math
import threading
import time
from contextlib import contextmanager

from ghidra_headless.errors import HeadlessError


class ReadBudget:
    def __init__(self, deadline, *, clock=time.monotonic):
        self.deadline = deadline
        self.clock = clock

    def remaining(self):
        return max(0.0, self.deadline - self.clock())

    def check(self, code="READ_TIMEOUT"):
        if not self.remaining():
            raise HeadlessError("%s: read deadline exceeded" % code)

    def native_timeout(self):
        self.check("DECOMPILE_TIMEOUT")
        # Zero means unlimited to the native decompiler. A monitor handles
        # fractional seconds; this integer timeout is a second line of defense.
        return max(1, math.ceil(self.remaining()))

    @contextmanager
    def monitor(self, factory=None):
        if factory is None:
            import jpype

            def factory():
                return jpype.JClass("ghidra.util.task.TaskMonitorAdapter")(True)

        self.check("DECOMPILE_TIMEOUT")
        monitor = factory()
        timer = threading.Timer(self.remaining(), monitor.cancel)
        timer.daemon = True
        timer.start()
        try:
            yield monitor
        finally:
            timer.cancel()
            timer.join()
