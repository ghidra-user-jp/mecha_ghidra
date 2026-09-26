"""The OperationControl a job hands over, for tests that call a job's service or runtime entry directly."""

from __future__ import annotations

from typing import Callable


class JobControl:
    def __init__(self, project_key: str | None = None, generation: int | None = None) -> None:
        self.expected_project_key = project_key
        self.expected_generation = generation
        self.checked = 0
        self.begun = False
        self.cancel: Callable[[], None] | None = None

    def check_active(self) -> None:
        self.checked += 1

    def begin(self) -> None:
        self.begun = True

    def bind_cancel(self, cancel: Callable[[], None] | None) -> None:
        self.cancel = cancel
