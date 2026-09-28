"""Work on Swing's event dispatch thread (EDT) from the server's threads.

Two ways, chosen by whether Ghidra may open a modal dialog while the work runs:

``run_on_edt`` waits for the result.  ``Swing.runNow`` bounds only the wait
for the EDT to *start* the work; once started, it waits for the end without a
limit.  It is for short work that shows no dialog: reading GUI state, or a
transaction section that only changes the program.

``post_to_edt`` returns at once.  It is for work that can show a dialog, such
as opening a program (the auto-analysis prompt) or changing the current
program: waiting for it would hold the calling thread, and every lock it
holds, until a human answers.  The caller then checks the outcome it expects
with a bounded poll.
"""

from __future__ import annotations

import html
import logging
import re
import threading
from collections.abc import Callable
from typing import TypeVar

from ghidra_headless.errors import HeadlessError

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# How long a caller waits for the EDT to start its work: Ghidra's own bound
# for it (ghidra.util.Swing, 20 s).  A GUI that does not start it this soon is
# busy with something long; the caller reports that instead of queueing behind
# it.  A slow machine keeps the EDT busy for seconds at a time while Ghidra
# opens a program or a tool (up to 34 s on an emulated Windows VM).
EDT_START_TIMEOUT_SECONDS = 20.0

_HTML_TAG = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")

# The runnables posted with post_to_edt, until they have run: the event queue
# holds the Java proxy, and this keeps its Python side alive.
_pending: set[object] = set()
_pending_lock = threading.Lock()

_thread_state = threading.local()


def use_ghidra_class_loader() -> None:
    """Give the calling Python thread Ghidra's class loader before it touches AWT.

    JPype attaches a Python thread with no context class loader.  The first
    thread to use AWT creates the event queue, and the EDT takes that thread's
    context class loader; Swing loads the look and feel's UI classes through
    it.  With none, a FlatLaf theme (Linux's default) finds no UI class and
    Ghidra's windows fail to build ("no ComponentUI class").
    """
    if getattr(_thread_state, "class_loader_set", False):
        return
    from java.lang import ClassLoader, Thread

    thread = Thread.currentThread()
    if thread.getContextClassLoader() is None:
        thread.setContextClassLoader(ClassLoader.getSystemClassLoader())
    _thread_state.class_loader_set = True


def is_edt() -> bool:
    use_ghidra_class_loader()
    from javax.swing import SwingUtilities

    return bool(SwingUtilities.isEventDispatchThread())


def run_on_edt(function: Callable[[], _T], *, start_timeout: float = EDT_START_TIMEOUT_SECONDS) -> _T:
    """Run ``function`` on the EDT and return its value, re-raising what it raised.

    Only for work that cannot open a modal dialog (see the module docstring).
    """
    if is_edt():
        return function()
    import jpype
    from ghidra.util import Swing
    from java.lang import Runnable
    from java.util.concurrent import TimeUnit

    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["value"] = function()
        except BaseException as exc:  # handed back to the calling thread
            outcome["error"] = exc

    try:
        Swing.runNow(jpype.JProxy(Runnable, dict={"run": run}), int(start_timeout * 1000), TimeUnit.MILLISECONDS)
    except Exception as exc:
        if "error" in outcome or "value" in outcome:
            raise
        raise HeadlessError(
            f"LOCK_TIMEOUT: the Ghidra GUI did not start the request within {start_timeout:g} s; "
            f"it is busy (modal dialogs: {', '.join(modal_dialog_titles()) or 'none'})",
            details={"lock": "gui_event_thread", "modal_dialogs": modal_dialog_titles()},
        ) from exc
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome.get("value")  # type: ignore[return-value]


def is_edt_busy(exc: BaseException) -> bool:
    """Whether ``exc`` is ``run_on_edt``'s: the EDT did not start the request in time."""
    return (
        isinstance(exc, HeadlessError)
        and exc.code == "LOCK_TIMEOUT"
        and (exc.details or {}).get("lock") == "gui_event_thread"
    )


def post_to_edt(function: Callable[[], object], *, label: str = "GUI request") -> None:
    """Queue ``function`` on the EDT and return at once; a failure is logged, not raised."""
    use_ghidra_class_loader()
    import jpype
    from ghidra.util import Swing
    from java.lang import Runnable

    proxy_box: list[object] = []

    def run() -> None:
        try:
            function()
        except BaseException:
            logger.exception("%s failed on the Swing thread", label)
        finally:
            with _pending_lock:
                for proxy in proxy_box:
                    _pending.discard(proxy)

    proxy = jpype.JProxy(Runnable, dict={"run": run})
    proxy_box.append(proxy)
    with _pending_lock:
        _pending.add(proxy)
    Swing.runLater(proxy)


def modal_dialog_titles() -> list[str]:
    """The titles of the visible modal dialogs, such as Ghidra's auto-analysis prompt.

    Reads window state from any thread without waiting for the EDT, so it
    still answers while a dialog is up.
    """
    try:
        use_ghidra_class_loader()
        from java.awt import Dialog, Window
    except Exception:  # no JVM yet
        return []
    titles: list[str] = []
    try:
        for window in Window.getWindows():
            if isinstance(window, Dialog) and window.isVisible() and window.isModal():
                title = window.getTitle()
                titles.append(plain_text(str(title)) if title is not None else "")
    except Exception as exc:  # a window disposed while being read
        logger.debug("could not list modal dialogs: %s", exc)
    return titles


def plain_text(text: str) -> str:
    """``text`` without HTML tags, character references or repeated whitespace (Ghidra's messages are often HTML).

    The references are read after the tags are gone, so an escaped ``<`` stays in the text.
    """
    return _WHITESPACE.sub(" ", html.unescape(_HTML_TAG.sub(" ", text))).strip()
