"""Run one Ghidra script (Java, Jython or PyGhidra) against an open program.

The execution sequence mirrors ``pyghidra.api.ghidra_script``:

    provider.getScriptInstance -> GhidraState -> ScriptControls -> setScriptArgs
    -> GhidraScript.execute

with three runtime-specific additions that make failures observable:

* Java: the snapshot root is registered as a source bundle up front and
  compile errors are attributed through ``GhidraSourceBundle.getErrors``.
* PyGhidra: the upstream runner must pass an exception propagation check.
* Jython: the interpreter is handed over through the ``ghidra.jython.interpreter``
  state variable so ``execFile`` runs synchronously in this thread instead of
  in a helper thread that swallows ``PyException``.

``run_script_with_transaction`` wraps the run in an outer transaction and
classifies the outcome *after* ``endTransaction`` from the retained
``TransactionInfo`` (see ``classify_transaction``).
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import threading
import time
import uuid
import weakref
from typing import Any

import jpype

from ghidra_headless.errors import HeadlessError
from ghidra_headless.scripts import providers, runtime_check
from ghidra_headless.scripts.capture import BoundedCapture

logger = logging.getLogger(__name__)

JYTHON_INTERPRETER_VAR = "ghidra.jython.interpreter"
DEFAULT_OUTPUT_LIMIT = 64 * 1024

# ``GhidraJythonInterpreter.get()`` builds a complete interpreter (Jython
# runtime, Ghidra builtins, script paths) and takes seconds; the Script Manager
# shares one across runs the same way.  Runs are serialized by the exclusive
# script barrier, so a single instance is reused until a run leaves it in
# doubt (setup failure, threads still running) or the runtimes shut down.


class _SharedInterpreter:
    __slots__ = ("instance",)

    def __init__(self) -> None:
        self.instance: Any = None


_jython = _SharedInterpreter()

OUTCOME_COMMITTED = "committed"
OUTCOME_UNCHANGED = "unchanged"
OUTCOME_ROLLED_BACK = "rolled_back"
OUTCOME_UNKNOWN = "unknown"


def _jclass(name: str):
    return jpype.JClass(name)


def _java_class_name(exc: BaseException) -> str:
    try:
        return str(exc.getClass().getName())  # type: ignore[attr-defined]
    except Exception:
        return type(exc).__name__


def _is_java_exception(exc: BaseException) -> bool:
    return isinstance(exc, jpype.JException)


def _short(text: Any, limit: int = 4000) -> str:
    value = "" if text is None else str(text)
    return value if len(value) <= limit else value[:limit] + "...[truncated]"


def shared_jython_interpreter():
    """The process-wide ``GhidraJythonInterpreter``, created on first use."""

    if _jython.instance is None:
        _jython.instance = _jclass("ghidra.jython.GhidraJythonInterpreter").get()
    return _jython.instance


def discard_shared_jython_interpreter() -> None:
    """Dispose the shared interpreter; the next run builds a fresh one."""

    interpreter, _jython.instance = _jython.instance, None
    if interpreter is None:
        return
    try:
        interpreter.cleanup()
    except Exception as exc:
        logger.debug("jython cleanup failed: %s", exc)


providers.add_shutdown_hook(discard_shared_jython_interpreter)


# ---- thread observation ----------------------------------------------------


def _thread_mxbean():
    return _jclass("java.lang.management.ManagementFactory").getThreadMXBean()


def snapshot_threads() -> dict[str, set]:
    """Java thread ids alive now.  Python threads are not diffed: see ``ThreadStartRecorder``.

    The ``python`` key is kept (empty) so callers holding an older snapshot shape keep working.
    """

    java_ids: set[int] = set()
    try:
        java_ids = {int(identity) for identity in _thread_mxbean().getAllThreadIds()}
    except Exception as exc:
        logger.debug("java thread snapshot failed: %s", exc)
    return {"java": java_ids, "python": set()}


# Threads the JVM, Ghidra and its OSGi framework start on their own during a
# run (bundle activation, compilation, logging).  They are not script work.
_HOUSEKEEPING_THREAD_RE = re.compile(
    r"^(Felix|OSGi|Bundle File Closer|Timer-\d+|ForkJoinPool|Common-Cleaner|Attach Listener|process reaper|"
    r"Reference Handler|Finalizer|Signal Dispatcher|Notification Thread|C\d CompilerThread|Sweeper thread|"
    r"Service Thread|Log4j|Ghidra Analysis|Swing-Shutdown|DestroyJavaVM|JPype|jpype|Python-JVM|"
    r"AsyncFileHandler|asyncio|pydevd|Thread-Watcher)"
)
# Python threads the MCP server itself starts while a script runs: anyio spawns a
# worker for every message that arrives mid-run (``anyio.to_thread.run_sync``),
# uvicorn and the stdlib executor name theirs likewise.  Never script work.
_SERVER_THREAD_RE = re.compile(r"^(AnyIO worker thread|asyncio_\d+|uvicorn|ThreadPoolExecutor-)")
THREAD_GRACE_SECONDS = 1.0

_ORIGINAL_THREAD_START = threading.Thread.start
# Stable token -> Thread for every Python thread a script started, so liveness is
# checked on the object itself: idents are recycled by the OS and ``_DummyThread``
# (a Java thread that called into Python) always reports alive.
_RECORDED_THREADS: dict[str, weakref.ref[threading.Thread]] = {}
_RECORDED_TOKENS: weakref.WeakKeyDictionary[threading.Thread, str] = weakref.WeakKeyDictionary()
_registry_lock = threading.Lock()


def _prune_recorded_threads() -> None:
    dead = [token for token, ref in _RECORDED_THREADS.items() if ref() is None]
    for token in dead:
        _RECORDED_THREADS.pop(token, None)


class ThreadStartRecorder:
    """Record the Python threads started while the block runs.

    Installed right before the script executes, under the exclusive script
    barrier the caller holds, by temporarily wrapping ``threading.Thread.start``.
    Only threads that go through ``start()`` in the window are script-started:
    ``_DummyThread`` instances never are, and server worker threads
    (``_SERVER_THREAD_RE``) are excluded by name so a worker spawned by the MCP
    server during the run is never reported as a stray.
    """

    def __init__(self) -> None:
        self.started: list[threading.Thread] = []
        self._previous_start = None
        self._lock = threading.Lock()

    def record(self, thread: threading.Thread) -> None:
        if isinstance(thread, threading._DummyThread):  # the stdlib type for foreign (Java) threads
            return
        try:
            name = thread.name
        except Exception:
            name = ""
        if _SERVER_THREAD_RE.match(name or ""):
            return
        with _registry_lock:
            token = _RECORDED_TOKENS.get(thread)
            if token is None:
                token = uuid.uuid4().hex
                _RECORDED_TOKENS[thread] = token
                _RECORDED_THREADS[token] = weakref.ref(thread)
            _prune_recorded_threads()
        with self._lock:
            if thread not in self.started:
                self.started.append(thread)

    def __enter__(self) -> "ThreadStartRecorder":
        recorder = self
        previous = threading.Thread.start

        def start(thread_self, *args, **kwargs):
            result = previous(thread_self, *args, **kwargs)
            recorder.record(thread_self)
            return result

        self._previous_start = previous
        threading.Thread.start = start  # type: ignore[method-assign]
        return self

    def __exit__(self, *_exc_info) -> None:
        if self._previous_start is not None:
            threading.Thread.start = self._previous_start  # type: ignore[method-assign]
            self._previous_start = None


def token_for_thread(thread: threading.Thread) -> str | None:
    with _registry_lock:
        return _RECORDED_TOKENS.get(thread)


def _python_entry(thread: threading.Thread) -> dict[str, Any]:
    return {
        "kind": "python",
        "id": thread.ident,
        "name": thread.name,
        "daemon": thread.daemon,
        "token": token_for_thread(thread),
    }


def _live_threads_not_in(before: dict[str, set], recorder: ThreadStartRecorder | None = None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    try:
        bean = _thread_mxbean()
        new_ids = [int(identity) for identity in bean.getAllThreadIds() if int(identity) not in before["java"]]
        # Depth zero obtains names/daemon flags without collecting any stacks.
        infos = bean.getThreadInfo(jpype.JArray(jpype.JLong)(new_ids), 0) if new_ids else []
        for thread_id, info in zip(new_ids, infos):
            if info is not None:  # A thread may have exited since ID enumeration.
                found.append(
                    {
                        "kind": "java",
                        "id": thread_id,
                        "name": str(info.getThreadName()),
                        "daemon": bool(info.isDaemon()),
                    }
                )
    except Exception as exc:
        logger.debug("java thread diff failed: %s", exc)
    for thread in list(recorder.started) if recorder is not None else []:
        if thread.is_alive():
            found.append(_python_entry(thread))
    return found


def describe_new_threads(
    before: dict[str, set],
    *,
    grace_seconds: float = THREAD_GRACE_SECONDS,
    recorder: ThreadStartRecorder | None = None,
) -> dict[str, Any]:
    """Best-effort detector: Java threads alive now that were not at ``before``, plus
    the Python threads ``recorder`` saw started, that are still alive.

    Waits up to ``grace_seconds`` for transient threads to finish and separates
    known housekeeping threads (``ignored``) from candidates a script may have
    left running (``stray``).  Detection only: an empty ``stray`` list does not
    prove quiescence (pools, virtual threads and unattached CPython threads are
    invisible here).
    """

    deadline = time.monotonic() + max(0.0, grace_seconds)
    while True:
        found = _live_threads_not_in(before, recorder)
        stray = [item for item in found if not _HOUSEKEEPING_THREAD_RE.match(item["name"])]
        if not stray or time.monotonic() >= deadline:
            ignored = [item for item in found if item not in stray]
            return {"stray": stray, "ignored": ignored}
        time.sleep(0.05)


def alive_threads(entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Which of the recorded stray threads (from ``describe_new_threads``) are still alive.

    Python entries are resolved through their ``token`` to the recorded Thread
    object; an unknown token (server restarted, thread collected) counts as gone.
    Java entries are checked by thread id against the live thread table.
    """

    if not entries:
        return []
    java_alive = snapshot_threads()["java"] if any(entry.get("kind") == "java" for entry in entries) else set()
    alive = []
    for entry in entries:
        kind = entry.get("kind")
        if kind == "java":
            if entry.get("id") in java_alive:
                alive.append(entry)
            continue
        if kind != "python":
            continue
        token = entry.get("token")
        with _registry_lock:
            ref = _RECORDED_THREADS.get(token) if token else None
        thread = ref() if ref is not None else None
        if thread is not None and thread.is_alive():
            alive.append(entry)
    return alive


# ---- failure classification -------------------------------------------------


def _jython_exception_details(exc: BaseException) -> dict[str, Any] | None:
    """Normalize ``org.python.core.PyException`` (Jython)."""

    if _java_class_name(exc) != "org.python.core.PyException":
        return None
    type_name = ""
    exit_code: Any = None
    with contextlib.suppress(Exception):
        type_name = str(exc.type)  # type: ignore[attr-defined]
    is_system_exit = "SystemExit" in type_name
    if is_system_exit:
        exit_code = "unknown"
        try:
            exc.normalize()  # type: ignore[attr-defined]
            value = exc.value  # type: ignore[attr-defined]
            # JPype does not expose Jython's __findattr__/__getattr__ methods.
            # Use the public Python-object invocation API to read SystemExit.code.
            code_obj = value.invoke("__getattribute__", _jclass("org.python.core.PyString")("code"))
            if isinstance(code_obj, _jclass("org.python.core.PyNone")):
                exit_code = None
            elif isinstance(code_obj, (_jclass("org.python.core.PyInteger"), _jclass("org.python.core.PyLong"))):
                # PyBoolean extends PyInteger; PyLong.getValue() is BigInteger.
                # Avoid asInt(), which overflows for arbitrary-sized Python ints.
                exit_code = int(str(code_obj.getValue()))
            else:
                # Strings (and anything else) are failures in CPython semantics too.
                exit_code = str(code_obj)
        except Exception:
            exit_code = "unknown"
    return {
        "kind": "jython",
        "python_type": type_name,
        "system_exit": is_system_exit,
        "exit_code": exit_code,
        "message": _short(exc),
    }


def _python_exception_details(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, SystemExit):
        code = exc.code
        if code is None or isinstance(code, bool | int):
            exit_code: Any = None if code is None else int(code)
        else:
            exit_code = str(code)
        return {
            "kind": "python",
            "python_type": "SystemExit",
            "system_exit": True,
            "exit_code": exit_code,
            "message": _short(exc),
        }
    return {"kind": "python", "python_type": type(exc).__name__, "system_exit": False, "message": _short(exc)}


def _java_exception_details(exc: BaseException) -> dict[str, Any]:
    cause_chain = []
    try:
        cause = exc.getCause()  # type: ignore[attr-defined]
        depth = 0
        while cause is not None and depth < 5:
            cause_chain.append({"type": str(cause.getClass().getName()), "message": _short(cause.getMessage())})
            cause = cause.getCause()
            depth += 1
    except Exception:
        pass
    return {"kind": "java", "java_type": _java_class_name(exc), "message": _short(exc), "causes": cause_chain}


def _exit_code_is_success(exit_code: Any) -> bool:
    """CPython semantics: only ``None`` and integer zero are successful exits (strings never are)."""
    if exit_code is None:
        return True
    return isinstance(exit_code, bool | int) and int(exit_code) == 0


def bundle_root_for(script_path: str, snapshot_roots: list[str] | None) -> str:
    """The source bundle directory a script belongs to: its snapshot root, else its own directory.

    Ghidra's Script Manager registers each script directory as one bundle and
    compiles every ``.java`` in it together; a nested ``root/sub/Foo.java`` is
    part of the root's bundle, never a bundle of its own.
    """

    directory = os.path.dirname(os.path.abspath(script_path))
    best: str | None = None
    for root in snapshot_roots or ():
        root_abs = os.path.abspath(str(root))
        if directory == root_abs or directory.startswith(root_abs + os.sep):
            if best is None or len(root_abs) > len(best):
                best = root_abs
    return best if best is not None else directory


def source_roots_for(script_path: str, snapshot_roots: list[str] | None) -> list[str]:
    """Directories to register as source bundles for a run: the roots, plus the script's
    own directory only when it lies under none of them (e.g. a probe script)."""

    roots = [str(root) for root in (snapshot_roots or ())]
    directory = os.path.dirname(os.path.abspath(script_path))
    if bundle_root_for(script_path, roots) == directory and not any(
        os.path.abspath(root) == directory for root in roots
    ):
        roots.append(directory)
    return roots


def _bundle_diagnostics(script_path: str, snapshot_roots: list[str] | None = None) -> dict[str, Any]:
    """Collect compile diagnostics for ``script_path`` from its source bundle."""

    directory = bundle_root_for(script_path, snapshot_roots)
    result: dict[str, Any] = {"script_errors": None, "bundle_errors": {}}
    try:
        bundle = providers.source_bundle_for(directory)
        if bundle is None:
            return result
        resource_file = _jclass("generic.jar.ResourceFile")
        java_file = _jclass("java.io.File")
        get_errors = getattr(bundle, "getErrors", None)
        if get_errors is not None:
            error = get_errors(resource_file(java_file(script_path)))
            if error is not None:
                result["script_errors"] = _short(error, 8000)
        get_all = getattr(bundle, "getAllErrors", None)
        if get_all is not None:
            for entry in get_all().entrySet():
                key = str(entry.getKey().getName())
                if str(entry.getKey().getAbsolutePath()) == script_path:
                    continue
                result["bundle_errors"][key] = _short(entry.getValue(), 2000)
    except Exception as exc:
        logger.debug("bundle diagnostics unavailable: %s", exc)
    return result


def _classify_load_failure(
    exc: BaseException, script_path: str, snapshot_roots: list[str] | None = None
) -> HeadlessError:
    diagnostics = _bundle_diagnostics(script_path, snapshot_roots)
    details = {
        "script_path": script_path,
        "exception": _java_exception_details(exc) if _is_java_exception(exc) else _python_exception_details(exc),
    }
    details.update(diagnostics)
    if diagnostics.get("script_errors"):
        return HeadlessError(f"SCRIPT_COMPILE_FAILED: {script_path} did not compile", details=details)
    return HeadlessError(f"SCRIPT_LOAD_FAILED: {script_path} could not be loaded: {_short(exc, 500)}", details=details)


# ---- execution --------------------------------------------------------------


def execute_script(
    *,
    program,
    project,
    script_path: str,
    runtime: str,
    args: list[str] | None = None,
    timeout_seconds: int = 300,
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT,
    snapshot_roots: list[str] | None = None,
) -> dict[str, Any]:
    """Run the script and return an outcome dict.  Never raises for script failures.

    ``status`` is ``ok``, ``error`` or ``timeout``; ``error`` carries the
    normalized failure. Load/compile failures raise ``HeadlessError`` with
    thread observations: Java initializers/constructors can already have run.
    """

    runtime_check.require_script_runtime_ready()
    providers.ensure_bundle_host()
    provider = providers.provider_for(runtime)
    # Every runtime uses these paths for runScript(), including Python-only
    # catalogs. Registration does not compile Java sources until they are used.
    # Only whole roots are bundles (the inline staging dir is passed as one):
    # registering a nested directory too would create two overlapping bundles.
    roots = source_roots_for(script_path, snapshot_roots)
    for root in roots:
        providers.register_source_root(root)

    resource_file = _jclass("generic.jar.ResourceFile")
    java_file = _jclass("java.io.File")
    state_cls = _jclass("ghidra.app.script.GhidraState")
    controls_cls = _jclass("ghidra.app.script.ScriptControls")
    task_monitor = _jclass("ghidra.util.task.TaskMonitor")
    timeout_monitor_cls = _jclass("ghidra.util.task.TimeoutTaskMonitor")
    time_unit = _jclass("java.util.concurrent.TimeUnit")

    diag = BoundedCapture(output_limit_bytes)
    source = resource_file(java_file(script_path))
    if not bool(source.exists()):
        raise HeadlessError(f"SCRIPT_NOT_FOUND: {script_path} does not exist")
    stdout = BoundedCapture(output_limit_bytes)
    stderr = BoundedCapture(output_limit_bytes)
    state = state_cls(None, project, program, None, None, None)

    jython_interpreter = None
    # Java and PyGhidra parents can run Jython children too. Hand the shared
    # interpreter over so child output and exceptions return to this transaction.
    # runScript() can resolve nested files or sources registered during the
    # run, beyond the catalog's top-level entries. A file scan cannot prove
    # that no Jython child will run, so always share when Jython is available.
    if providers.runtime_availability().get(providers.RUNTIME_JYTHON, False):
        try:
            jython_interpreter = shared_jython_interpreter()
        except BaseException as exc:
            raise HeadlessError(
                f"SCRIPT_RUNTIME_UNAVAILABLE: Jython interpreter could not be created: {_short(exc, 500)}"
            ) from exc
        if jython_interpreter is None:
            raise HeadlessError("SCRIPT_RUNTIME_UNAVAILABLE: GhidraJythonInterpreter.get() returned null")
        jython_interpreter.setOut(stdout.writer)
        jython_interpreter.setErr(stderr.writer)
        state.addEnvironmentVar(JYTHON_INTERPRETER_VAR, jython_interpreter)

    error: dict[str, Any] | None = None
    setup_error: BaseException | None = None
    monitor = None
    load_ms = duration_ms = 0
    # Runtime initialization is complete, but user constructors/static initializers
    # run inside getScriptInstance. Observe them as well as the script body;
    # describe_new_threads filters the known OSGi/compiler housekeeping threads.
    before_threads = snapshot_threads()
    recorder = ThreadStartRecorder()
    try:
        with recorder:
            load_started = time.monotonic()
            try:
                script = provider.getScriptInstance(source, diag.writer)
            except BaseException as exc:
                raise _classify_load_failure(exc, script_path, snapshot_roots) from exc
            finally:
                load_ms = int((time.monotonic() - load_started) * 1000)
            if script is None:
                raise HeadlessError(f"SCRIPT_LOAD_FAILED: provider returned no instance for {script_path}")
            monitor = timeout_monitor_cls.timeoutIn(int(timeout_seconds), time_unit.SECONDS, task_monitor.DUMMY)
            controls = controls_cls(stdout.writer, stderr.writer, monitor)
            script.setScriptArgs(jpype.JArray(jpype.JString)([str(item) for item in (args or [])]))
            started = time.monotonic()
            try:
                script.execute(state, controls)
            except BaseException as exc:
                if _is_java_exception(exc):
                    error = _jython_exception_details(exc) or _java_exception_details(exc)
                else:
                    error = _python_exception_details(exc)
            finally:
                duration_ms = int((time.monotonic() - started) * 1000)
    except BaseException as exc:
        setup_error = exc
    finally:
        if monitor is not None:
            with contextlib.suppress(Exception):
                monitor.finished()
        if jython_interpreter is not None:
            with contextlib.suppress(Exception):
                state.removeEnvironmentVar(JYTHON_INTERPRETER_VAR)
        stdout.flush()
        stderr.flush()
        diag.flush()

    threads = describe_new_threads(before_threads, recorder=recorder)
    if jython_interpreter is not None and (setup_error is not None or threads["stray"]):
        # A failed setup or work still running may hold the interpreter: do not
        # hand that instance to the next run.
        discard_shared_jython_interpreter()
    if setup_error is not None:
        details = dict(setup_error.details or {}) if isinstance(setup_error, HeadlessError) else {}
        details.update(
            stray_threads=threads["stray"],
            ignored_threads=threads["ignored"],
            load_ms=load_ms,
            duration_ms=duration_ms,
            stdout=stdout.describe(),
            stderr=stderr.describe(),
            diagnostics=diag.describe(),
        )
        if isinstance(setup_error, HeadlessError):
            raise HeadlessError(str(setup_error), code=setup_error.code, details=details) from setup_error
        raise HeadlessError(f"SCRIPT_FAILED: {_short(setup_error, 500)}", details=details) from setup_error

    # The startup probe verifies that PyGhidra exceptions propagate. Only an
    # exception escaping this execute() is a failure: a parent script may have
    # caught a child's exception and legitimately completed its work.
    timed_out = False
    with contextlib.suppress(Exception):
        timed_out = bool(monitor.didTimeout())
    cancelled = False
    with contextlib.suppress(Exception):
        cancelled = bool(monitor.isCancelled()) and not timed_out

    if error is not None and error.get("system_exit") and _exit_code_is_success(error.get("exit_code")):
        error = None
    status = "ok"
    if timed_out:
        status = "timeout"
    elif error is not None:
        status = "error"
    elif cancelled:
        status = "cancelled"
    return {
        "status": status,
        "runtime": runtime,
        "error": error,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "load_ms": load_ms,
        "duration_ms": duration_ms,
        "stdout": stdout.describe(),
        "stderr": stderr.describe(),
        "diagnostics": diag.describe(),
        "stray_threads": threads["stray"],
        "ignored_threads": threads["ignored"],
    }


# ---- transaction wrapper ---------------------------------------------------


def classify_transaction(
    *,
    commit_requested: bool,
    ended: bool | None,
    status: str | None,
    committed_db: bool | None,
    leaked: bool,
) -> tuple[str, str]:
    """Return ``(outcome, execution_state)`` for an ended outer transaction.

    ``status`` and ``committed_db`` must be read *after* ``endTransaction``:
    before it the status is always ``NOT_DONE``.
    """

    if leaked:
        return OUTCOME_UNKNOWN, "invalid"
    if status == "COMMITTED" and committed_db is True and commit_requested:
        return OUTCOME_COMMITTED, "valid"
    if status == "COMMITTED" and committed_db is False and commit_requested:
        return OUTCOME_UNCHANGED, "valid"
    if status == "ABORTED" and not committed_db:
        return OUTCOME_ROLLED_BACK, "valid"
    return OUTCOME_UNKNOWN, "invalid"


def run_script_with_transaction(
    *,
    program,
    project,
    description: str,
    request: dict[str, Any],
    observe_threads: bool = True,
) -> dict[str, Any]:
    """Execute ``request`` inside an outer transaction and classify the result.

    Returns the result dict on success (``committed``/``unchanged``) and raises
    ``HeadlessError`` (``SCRIPT_FAILED``/``SCRIPT_TIMEOUT``/``SCRIPT_CANCELLED``)
    with the full execution summary in ``details`` otherwise.  The caller
    quarantines the target when ``details["execution_state"] == "invalid"``.
    """

    runtime_check.require_script_runtime_ready()
    if program.getCurrentTransactionInfo() is not None:
        raise HeadlessError("OPERATION_FAILED: a transaction is already open on the program")
    analysis_manager = None
    try:
        analysis_cls = _jclass("ghidra.app.plugin.core.analysis.AutoAnalysisManager")
        analysis_manager = analysis_cls.getAnalysisManager(program)
        if bool(analysis_manager.isAnalyzing()):
            raise HeadlessError("OPERATION_FAILED: auto-analysis is running; retry after it finishes")
    except HeadlessError:
        raise
    except Exception as exc:
        logger.debug("analysis manager unavailable: %s", exc)

    revision_before = _revision(program)
    tx_id = program.startTransaction(description)
    info = program.getCurrentTransactionInfo()
    outcome: dict[str, Any] | None = None
    run_error: BaseException | None = None
    try:
        outcome = execute_script(
            program=program,
            project=project,
            script_path=request["script_path"],
            runtime=request["runtime"],
            args=request.get("args") or [],
            timeout_seconds=int(request.get("timeout_seconds") or 300),
            output_limit_bytes=int(request.get("output_limit_bytes") or DEFAULT_OUTPUT_LIMIT),
            snapshot_roots=request.get("snapshot_roots") or [],
        )
    except BaseException as exc:
        run_error = exc
    commit = run_error is None and outcome is not None and outcome["status"] == "ok"
    ended: bool | None
    end_error = None
    try:
        ended = bool(program.endTransaction(tx_id, commit))
    except BaseException as exc:
        ended = None
        end_error = _short(exc, 500)
    status = None
    committed_db = None
    open_sub = []
    try:
        status = str(info.getStatus())
        committed_db = bool(info.hasCommittedDBTransaction())
        open_sub = [str(item) for item in info.getOpenSubTransactions()]
    except Exception as exc:
        logger.debug("transaction info unavailable: %s", exc)
    leaked_info = program.getCurrentTransactionInfo()
    leaked = leaked_info is not None
    tx_outcome, execution_state = classify_transaction(
        commit_requested=commit, ended=ended, status=status, committed_db=committed_db, leaked=leaked
    )
    if end_error is not None:
        tx_outcome, execution_state = OUTCOME_UNKNOWN, "invalid"

    execution_details = outcome or (run_error.details if isinstance(run_error, HeadlessError) else None) or {}
    stray_threads = (execution_details.get("stray_threads") or []) if observe_threads else []
    analyzing_after = False
    if analysis_manager is not None:
        with contextlib.suppress(Exception):
            analyzing_after = bool(analysis_manager.isAnalyzing())
    if stray_threads or analyzing_after:
        execution_state = "invalid"

    summary: dict[str, Any] = {
        "script_id": request.get("script_id"),
        "runtime": request.get("runtime"),
        "transaction_outcome": tx_outcome,
        "execution_state": execution_state,
        "transaction_status": status,
        "committed_db_transaction": committed_db,
        "commit_requested": commit,
        "end_transaction_result": ended,
        "end_transaction_error": end_error,
        "open_sub_transactions": open_sub if leaked else [],
        "revision_before": revision_before,
        "revision_after": _revision(program),
        "can_undo": _safe_bool(program, "canUndo"),
        "program_dirty": _safe_bool(program, "isChanged"),
        "stray_threads": stray_threads,
        "ignored_threads": execution_details.get("ignored_threads") or [],
        "analysis_pending": "unknown",
    }
    if outcome is not None:
        summary.update(
            {
                "status": outcome["status"],
                "error": outcome["error"],
                "timed_out": outcome["timed_out"],
                "load_ms": outcome["load_ms"],
                "duration_ms": outcome["duration_ms"],
                "stdout": outcome["stdout"],
                "stderr": outcome["stderr"],
                "diagnostics": outcome["diagnostics"],
            }
        )

    if run_error is not None:
        if isinstance(run_error, HeadlessError):
            details = dict(run_error.details or {})
            details.update(summary)
            raise HeadlessError(str(run_error), code=run_error.code, details=details) from run_error
        raise HeadlessError(f"SCRIPT_FAILED: {_short(run_error, 500)}", details=summary) from run_error
    assert outcome is not None
    if outcome["status"] == "timeout":
        raise HeadlessError(
            f"SCRIPT_TIMEOUT: {request.get('script_id')} exceeded {request.get('timeout_seconds')} seconds",
            details=summary,
        )
    if outcome["status"] == "cancelled":
        raise HeadlessError(f"SCRIPT_CANCELLED: {request.get('script_id')} was cancelled", details=summary)
    if outcome["status"] == "error":
        message = (outcome["error"] or {}).get("message") or "script raised an error"
        raise HeadlessError(f"SCRIPT_FAILED: {_short(message, 500)}", details=summary)
    if tx_outcome == OUTCOME_ROLLED_BACK:
        # The script returned normally but aborted its own nested transaction.
        raise HeadlessError(
            "SCRIPT_FAILED: the script aborted its own transaction; no changes were kept", details=summary
        )
    if execution_state == "invalid":
        raise HeadlessError(
            "SCRIPT_FAILED: the script left the program in an unverifiable state; the target is quarantined",
            details=summary,
        )
    return summary


def _revision(program) -> str | None:
    try:
        return str(program.getModificationNumber())
    except Exception:
        return None


def _safe_bool(obj, name: str) -> bool | None:
    try:
        return bool(getattr(obj, name)())
    except Exception:
        return None


__all__ = [
    "DEFAULT_OUTPUT_LIMIT",
    "JYTHON_INTERPRETER_VAR",
    "OUTCOME_COMMITTED",
    "OUTCOME_ROLLED_BACK",
    "OUTCOME_UNCHANGED",
    "OUTCOME_UNKNOWN",
    "ThreadStartRecorder",
    "alive_threads",
    "bundle_root_for",
    "classify_transaction",
    "describe_new_threads",
    "discard_shared_jython_interpreter",
    "execute_script",
    "run_script_with_transaction",
    "shared_jython_interpreter",
    "snapshot_threads",
    "source_roots_for",
]
