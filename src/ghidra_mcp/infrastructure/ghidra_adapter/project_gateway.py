"""Gateway for target/project lifecycle operations."""

from __future__ import annotations

from typing import Any


class ProjectGateway:
    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def list_targets(self):
        return self._registry.list_targets()

    def list_project_programs(self, target: str):
        return self._registry.list_programs(target)

    def register_target(self, target: str, *, project_location: str, project_name: str | None = None):
        return self._registry.register_target(target, project_location, project_name=project_name)

    def load_project_program(self, target: str, *, domain_path: str):
        return self._registry.load_program(target, domain_path)

    def import_program(self, target: str, *, binary_path: str):
        return self._registry.import_program(target, binary_path)

    def create_session(
        self,
        target: str,
        *,
        project_location: str,
        domain_path: str,
        project_name: str | None = None,
    ):
        return self._registry.create_session(
            target,
            project_location,
            project_name=project_name,
            domain_path=domain_path,
        )

    def close_session(self, target: str, *, remove_program: bool = False):
        return self._registry.close_session(target, remove_program=remove_program)


__all__ = ["ProjectGateway"]
