[English](development.md) | [日本語](development.ja.md)

# Development Guide

## Development and Testing

- Dependency updates: `uv add <package>` / `uv remove <package>`
- Add formatting/type-check tools as needed and run them with `uv run <tool>`.
- Test run: first install test dependencies (`pytest`, `pytest-mock`) with `uv sync --extra test`, then run unit tests with `uv run pytest`.
