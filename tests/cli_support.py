"""Test-side stand-in for the CLI's former module-level default registry.

``ghidra_mcp.presentation.cli`` no longer keeps a process-wide registry or
tool functions: ``main()`` builds one :class:`CLIApplication` and passes it
around.  Tests that call tools directly get the same thing from a harness:
``cli_tools.list_functions(...)`` dispatches to ``cli_tools.registry``, which a
test may swap (``monkeypatch.setattr(cli_tools, "registry", Dummy())``) exactly
where it used to swap ``cli._registry``.  Runtime tests call ``configure(...)``
where they used to call ``cli._get_registry(...)``.
"""

from __future__ import annotations

from typing import Any

from ghidra_mcp.presentation import cli


class ToolHarness:
    def __init__(self) -> None:
        self._app: cli.CLIApplication | None = None
        self._registry: Any = None
        self._tools = cli.bind_tools(lambda: self.registry)

    def configure(self, *args: Any, **kwargs: Any):
        """Build the application the way ``main()`` does; returns its registry (as ``_get_registry`` did)."""
        self._app = cli.build_application(*args, **kwargs)
        self._registry = self._app.registry
        return self._registry

    @property
    def app(self) -> cli.CLIApplication:
        if self._app is None:
            self.configure()
        assert self._app is not None
        return self._app

    @property
    def registry(self) -> Any:
        if self._registry is None:
            self.configure()
        return self._registry

    @registry.setter
    def registry(self, value: Any) -> None:
        self._registry = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._tools, name)


__all__ = ["ToolHarness"]
