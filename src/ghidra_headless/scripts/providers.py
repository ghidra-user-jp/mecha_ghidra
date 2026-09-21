"""Script provider lookup by runtime name.

``GhidraScriptUtil.getProvider(file)`` picks a provider by extension and
priority (PyGhidra carries priority 1000), which would silently decide the
language of a ``.py`` script.  The catalog therefore decides the runtime from
the ``@runtime`` header and this module hands out the matching provider.
"""

from __future__ import annotations

import logging
import threading

import jpype

from ghidra_headless.errors import HeadlessError

logger = logging.getLogger(__name__)

RUNTIME_JAVA = "Java"
RUNTIME_JYTHON = "Jython"
RUNTIME_PYGHIDRA = "PyGhidra"
SUPPORTED_RUNTIMES = (RUNTIME_JAVA, RUNTIME_JYTHON, RUNTIME_PYGHIDRA)

_lock = threading.RLock()


class _RuntimeState:
    """Process-wide script runtime state, released by ``shutdown()``."""

    __slots__ = ("bundle_host", "providers", "registered_roots", "shutdown_hooks")

    def __init__(self) -> None:
        self.bundle_host = None
        self.providers: dict[str, object] | None = None
        self.registered_roots: set[str] = set()
        # State owned by other modules (e.g. the shared Jython interpreter)
        # that must be released before the bundle host goes away.
        self.shutdown_hooks: list = []


_state = _RuntimeState()


def add_shutdown_hook(hook) -> None:
    with _lock:
        if hook not in _state.shutdown_hooks:
            _state.shutdown_hooks.append(hook)


def _script_util():
    return jpype.JClass("ghidra.app.script.GhidraScriptUtil")


def ensure_bundle_host():
    """Acquire the bundle host once for the life of the process.

    Releasing the last reference disposes the host and every registered source
    bundle, so the reference taken here is only released by ``shutdown()``.
    """

    with _lock:
        if _state.bundle_host is None:
            _state.bundle_host = _script_util().acquireBundleHostReference()
        return _state.bundle_host


def shutdown() -> None:
    with _lock:
        for hook in list(_state.shutdown_hooks):
            try:
                hook()
            except Exception as exc:
                logger.debug("script runtime shutdown hook %r failed: %s", hook, exc)
        if _state.bundle_host is not None:
            try:
                _script_util().releaseBundleHostReference()
            except Exception as exc:
                logger.debug("releaseBundleHostReference failed: %s", exc)
            _state.bundle_host = None
        _state.providers = None
        _state.registered_roots.clear()


def _jython_stub_class():
    """``ghidra.app.script.JythonStubScriptProvider`` when the running Ghidra has it, else ``None``."""

    try:
        return jpype.JClass("ghidra.app.script.JythonStubScriptProvider")
    except Exception as exc:
        logger.debug("JythonStubScriptProvider not on the classpath: %s", exc)
        return None


def _is_jython_stub(provider, stub_cls) -> bool:
    if stub_cls is None:
        return False
    try:
        return isinstance(provider, stub_cls)
    except Exception:
        return False


def index_providers(*, refresh: bool = False) -> dict[str, object]:
    """Map runtime environment name -> provider instance."""

    with _lock:
        if _state.providers is not None and not refresh:
            return dict(_state.providers)
        found: dict[str, object] = {}
        stub_cls = _jython_stub_class()
        for provider in _script_util().getProviders():
            try:
                name = str(provider.getRuntimeEnvironmentName())
                # Ghidra advertises this placeholder as "Jython" even when
                # the extension is absent; it can only throw a load error.
                if _is_jython_stub(provider, stub_cls):
                    continue
            except Exception as exc:
                logger.debug("provider without runtime name skipped: %s", exc)
                continue
            found.setdefault(name, provider)
        _state.providers = found
        return dict(found)


def runtime_availability() -> dict[str, bool]:
    providers = index_providers()
    return {name: name in providers for name in SUPPORTED_RUNTIMES}


def provider_for(runtime: str):
    providers = index_providers()
    provider = providers.get(runtime)
    if provider is None:
        hint = ""
        if runtime == RUNTIME_JYTHON:
            hint = (
                "; Jython ships as a Ghidra Extension: unzip Extensions/Ghidra/*_Jython.zip into "
                "Ghidra/Extensions and restart"
            )
        raise HeadlessError(
            f"SCRIPT_RUNTIME_UNAVAILABLE: no script provider for runtime {runtime!r}{hint}",
            details={"runtime": runtime, "available": sorted(providers)},
        )
    return provider


def register_source_root(directory: str):
    """Register a snapshot root as a (non-system) source bundle.

    ``JavaScriptProvider.loadClass`` requires the script's directory to be a
    known bundle and does not add it itself.  Registration is idempotent; the
    provider activates (compiles) the bundle on first use.
    """

    host = ensure_bundle_host()
    resource_file = jpype.JClass("generic.jar.ResourceFile")
    java_file = jpype.JClass("java.io.File")
    with _lock:
        root = resource_file(java_file(str(directory)))
        # getGhidraBundle returns null quietly; getExistingGhidraBundle would log Msg.showError for a new root.
        existing = host.getGhidraBundle(root)
        if existing is not None:
            _state.registered_roots.add(str(directory))
            return existing
        bundle = host.add(root, True, False)
        _state.registered_roots.add(str(directory))
        return bundle


def unregister_source_root(directory: str) -> bool:
    """Deactivate a source bundle, wipe its compiled output and forget it (inline scripts are one-shot)."""

    host = ensure_bundle_host()
    resource_file = jpype.JClass("generic.jar.ResourceFile")
    java_file = jpype.JClass("java.io.File")
    with _lock:
        _state.registered_roots.discard(str(directory))
        bundle = host.getGhidraBundle(resource_file(java_file(str(directory))))
        if bundle is None:
            return False
        try:
            bundle.clean()  # deactivates the OSGi bundle and removes osgi/compiled-bundles/<hash>
        except Exception as exc:
            logger.warning("failed to clean script bundle %s: %s", directory, exc)
        host.remove(bundle)
        return True


def source_bundle_for(directory: str):
    host = ensure_bundle_host()
    resource_file = jpype.JClass("generic.jar.ResourceFile")
    java_file = jpype.JClass("java.io.File")
    return host.getGhidraBundle(resource_file(java_file(str(directory))))


__all__ = [
    "RUNTIME_JAVA",
    "RUNTIME_JYTHON",
    "RUNTIME_PYGHIDRA",
    "SUPPORTED_RUNTIMES",
    "add_shutdown_hook",
    "ensure_bundle_host",
    "index_providers",
    "provider_for",
    "register_source_root",
    "runtime_availability",
    "shutdown",
    "source_bundle_for",
]
