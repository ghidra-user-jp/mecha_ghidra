"""Per-read deadlines; never abandon a running Ghidra call or release its lock."""

import math
import threading
import time
from contextlib import contextmanager

from ghidra_headless.errors import HeadlessError

# How often a read's watcher looks at the call's monitor (the one its request can cancel).
PARENT_POLL_SECONDS = 0.05


class ReadBudget:
    def __init__(self, deadline, *, clock=time.monotonic, parent=None):
        self.deadline = deadline
        self.clock = clock
        # The monitor of the whole call, if its request can cancel it: a read that has its own deadline monitor
        # stops when either runs out.
        self.parent = parent

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
        if self.parent is None:
            timer = threading.Timer(self.remaining(), monitor.cancel)
        else:
            stopped = threading.Event()
            timer = _Watcher(self, monitor, stopped)
        timer.daemon = True
        timer.start()
        try:
            yield monitor
        finally:
            timer.cancel()
            timer.join()


class _Watcher(threading.Thread):
    """Cancels a read's monitor at the read's deadline, or at once when the call's monitor is cancelled."""

    def __init__(self, budget, monitor, stopped):
        super().__init__(name="read-budget", daemon=True)
        self._budget = budget
        self._monitor = monitor
        self._stopped = stopped

    def cancel(self):
        self._stopped.set()

    def run(self):
        budget = self._budget
        while not self._stopped.is_set():
            remaining = budget.remaining()
            if remaining <= 0 or budget.parent.isCancelled():
                self._monitor.cancel()
                return
            self._stopped.wait(min(remaining, PARENT_POLL_SECONDS))
