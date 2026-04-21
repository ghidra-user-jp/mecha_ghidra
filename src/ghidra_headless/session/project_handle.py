"""Project-level operations for Ghidra sessions."""

from __future__ import annotations

import logging
import pathlib
import threading
from typing import Any, Dict, Optional

import pyghidra
import pyghidra.core as pycore

from .models import ProgramSession
from . import java_bindings, path_utils, sync_utils

logger = logging.getLogger(__name__)


class ProjectHandle:
    """Shared handle for a Ghidra project, allowing multiple program sessions."""

    def __init__(self, project_location: str, project_name: Optional[str]) -> None:
        self._lock = threading.RLock()
        self.project_location, self.project_name = self.resolve_project_location_and_file(project_location, project_name)
        self.key = self.make_key(project_location, project_name)
        self._open_programs: set[tuple[str, str]] = set()

        from ghidra.base.project import GhidraProject

        self.project = GhidraProject.openProject(self.project_location, self.project_name, True)
        self._refcount = 0
        self._closed = False

    @staticmethod
    def resolve_project_location_and_file(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        path = pathlib.Path(project_location).expanduser().resolve()
        if project_name is None and path.suffix.lower() != ".gpr":
            raise ValueError("project_location must point to a .gpr Ghidra project file")
        if project_name is None and not path.is_file():
            raise ValueError(f"Specified .gpr file not found: {path}")
        if project_name is None and path.is_dir():
            raise ValueError("project_name is required")
        effective = project_name or path.stem
        return (str(path.parent if path.is_file() else path), effective)

    @staticmethod
    def make_key(project_location: str, project_name: Optional[str]) -> tuple[str, str]:
        return ProjectHandle.resolve_project_location_and_file(project_location, project_name)

    @staticmethod
    def list_programs_from_metadata(project_location: str, project_name: Optional[str]) -> Optional[list[Dict[str, str]]]:
        rep_dir = ProjectHandle._project_rep_dir(project_location, project_name)
        idata_dir = rep_dir / "idata"
        if not idata_dir.is_dir():
            return None
        return path_utils._collect_program_files_from_idata(idata_dir)

    @staticmethod
    def is_repository_project_from_metadata(project_location: str, project_name: Optional[str]) -> bool:
        info = path_utils._read_prp_basic_info(ProjectHandle._project_rep_dir(project_location, project_name) / "project.prp")
        if not info:
            return False
        return bool(str(info.get("SERVER") or "").strip())

    @staticmethod
    def _project_rep_dir(project_location: str, project_name: Optional[str]) -> pathlib.Path:
        resolved_location, resolved_name = ProjectHandle.resolve_project_location_and_file(project_location, project_name)
        return pathlib.Path(resolved_location) / f"{resolved_name}.rep"

    def get_project_location(self) -> str:
        return self.project_location

    def get_project_name(self) -> str:
        return self.project_name

    def get_key(self) -> tuple[str, str]:
        return self.key

    def open_program(self, domain_path: Optional[str] = None) -> ProgramSession:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is already closed")
            monitor = java_bindings._console_monitor()
            domain_dir, domain_name = path_utils._parse_domain_path(self.project, domain_path)
            domain_path_key = (domain_dir, domain_name)
            if domain_path_key in self._open_programs:
                raise RuntimeError(f"Program already has an active session: {domain_path_key}")
            program = self.project.openProgram(domain_dir, domain_name, False)
            if program is None:
                raise RuntimeError(f"Failed to open program: {domain_path}")
            flat_api = java_bindings._flat_program_api_class()(program, monitor)
            self._refcount += 1
            self._open_programs.add(domain_path_key)
            return ProgramSession(flat_api, program, project_handle=self)

    def import_program(
        self,
        binary_path: str,
        *,
        import_mode: str = "auto",
        language_id: str | None = None,
        compiler_spec_id: str | None = None,
        base_address: str | None = None,
        file_offset: int | None = None,
        length: int | None = None,
        block_name: str | None = None,
        overlay: bool = False,
        entry_address: str | None = None,
        entry_offset: int | None = None,
        analyze_imported: bool | None = None,
    ):
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is already closed")
            path = pathlib.Path(binary_path)
            if not path.exists():
                raise ValueError(f"Binary does not exist: {binary_path}")
            program_dir = "/"
            program_name = path.name
            data = self.project.getProjectData()
            domain_file = data.getFile(program_dir + program_name)
            if domain_file is not None:
                raise RuntimeError(f"Program already exists: {domain_file.getPathname()}")
            if import_mode == "auto":
                domain_file = self._import_program_auto_locked(path, program_dir, program_name)
            elif import_mode == "raw_binary":
                if language_id is None:
                    raise ValueError("language_id is required when import_mode='raw_binary'")
                domain_file = self._import_program_raw_locked(
                    path,
                    program_dir=program_dir,
                    program_name=program_name,
                    language_id=language_id,
                    compiler_spec_id=compiler_spec_id,
                    base_address=base_address,
                    file_offset=file_offset,
                    length=length,
                    block_name=block_name,
                    overlay=overlay,
                )
            else:
                raise ValueError(f"Unsupported import_mode: {import_mode}")
            if domain_file is None:
                raise RuntimeError(f"Failed to add program: {binary_path}")
            should_analyze = analyze_imported if analyze_imported is not None else (import_mode == "raw_binary")
            if should_analyze or entry_address is not None or entry_offset is not None:
                self._post_process_imported_program_locked(
                    domain_file.getPathname(),
                    entry_address=entry_address,
                    entry_offset=entry_offset,
                    analyze_imported=bool(should_analyze),
                )

            return domain_file

    def get_sync_status(self, domain_path: str) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            return sync_utils._sync_status_from_domain_file(domain_file)

    def get_version_history(self, domain_path: str, *, limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            normalized_limit = int(limit)
            if normalized_limit < 1:
                raise ValueError("limit must be >= 1")
            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(sync_utils._required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")
            versions = sync_utils._get_version_history_entries(domain_file)
            versions.sort(key=lambda item: item["version"], reverse=True)
            current_version = int(sync_utils._required_call(domain_file, "getVersion"))
            latest_version = int(sync_utils._required_call(domain_file, "getLatestVersion"))
            return {
                "program": domain_path,
                "current_version": current_version,
                "latest_version": latest_version,
                "total_versions": len(versions),
                "versions": versions[:normalized_limit],
            }

    def get_version_diff(
        self,
        domain_path: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
    ) -> Dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            source_version = int(from_version)
            target_version = int(to_version)
            if source_version < 1 or target_version < 1:
                raise ValueError("from_version and to_version must be >= 1")
            normalized_range_limit = int(range_limit)
            if normalized_range_limit < 0:
                raise ValueError("range_limit must be >= 0")

            domain_file = self._get_domain_file_locked(domain_path)
            if not bool(sync_utils._required_call(domain_file, "isVersioned")):
                raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")

            versions = sync_utils._get_version_history_entries(domain_file)
            known_versions = {item["version"] for item in versions}
            if source_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: from_version={source_version} not found in history"
                )
            if target_version not in known_versions:
                raise RuntimeError(
                    f"VERSION_NOT_FOUND: to_version={target_version} not found in history"
                )

            result = {
                "program": domain_path,
                "from_version": source_version,
                "to_version": target_version,
                "total_diff_addresses": 0,
                "total_diff_ranges": 0,
                "diff_types": [],
                "ranges": [],
                "ranges_truncated": False,
                "warnings": None,
            }
            if source_version == target_version:
                return result

            monitor = java_bindings._console_monitor()
            from_consumer = java_bindings._java_object()
            to_consumer = java_bindings._java_object()
            from_program = None
            to_program = None
            try:
                from_program = domain_file.getReadOnlyDomainObject(from_consumer, source_version, monitor)
                to_program = domain_file.getReadOnlyDomainObject(to_consumer, target_version, monitor)
                if from_program is None or to_program is None:
                    raise RuntimeError(
                        f"VERSION_LOAD_FAILED: failed to open version {source_version} or {target_version}"
                    )
                program_diff = java_bindings._program_diff_class()(from_program, to_program)
                differences = program_diff.getDifferences(monitor)

                type_counts = sync_utils._collect_diff_type_counts(program_diff, differences, monitor)
                ranges, truncated = sync_utils._collect_diff_ranges(differences, limit=normalized_range_limit)
                warnings = program_diff.getWarnings()
                result.update(
                    {
                        "total_diff_addresses": int(differences.getNumAddresses()) if differences is not None else 0,
                        "total_diff_ranges": int(differences.getNumAddressRanges()) if differences is not None else 0,
                        "diff_types": type_counts,
                        "ranges": ranges,
                        "ranges_truncated": truncated,
                        "warnings": None if warnings is None else str(warnings),
                    }
                )
                return result
            finally:
                sync_utils._release_domain_object(from_program, from_consumer)
                sync_utils._release_domain_object(to_program, to_consumer)

    def checkout_program(self, domain_path: str, *, exclusive: bool = False) -> bool:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            return bool(domain_file.checkout(bool(exclusive), monitor))

    def add_program_to_version_control(
        self,
        domain_path: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            text = (comment or "").strip()
            if not text:
                raise ValueError("comment is required")
            domain_file = self._get_domain_file_locked(domain_path)
            can_add = sync_utils._safe_call(domain_file, "canAddToRepository")
            if can_add is False:
                raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed")
            monitor = java_bindings._console_monitor()
            domain_file.addToVersionControl(text, bool(keep_checked_out), monitor)

    def commit_program(
        self,
        domain_path: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        create_keep_file: bool = False,
    ) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            text = (message or "").strip()
            if not text:
                raise ValueError("message is required")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            handler = java_bindings._default_checkin_handler_class()(text, bool(keep_checked_out), bool(create_keep_file))
            domain_file.checkin(handler, monitor)

    def merge_program(self, domain_path: str, *, ok_to_upgrade: bool = True) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            monitor = java_bindings._console_monitor()
            domain_file.merge(bool(ok_to_upgrade), monitor)

    def undo_checkout_program(self, domain_path: str, *, keep: bool = False) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.undoCheckout(bool(keep))

    def terminate_checkout_program(self, domain_path: str, checkout_id: int) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            domain_file = self._get_domain_file_locked(domain_path)
            domain_file.terminateCheckout(int(checkout_id))

    def release_program(self, program, *, save: bool = True, remove_program: bool = False) -> None:
        with self._lock:
            if self._closed:
                return
            domain_path = path_utils._domain_path(program)
            if domain_path is None:
                raise RuntimeError("Failed to resolve path of program to remove")
            domain_key = path_utils._parse_domain_path(self.project, domain_path)
            save_error = None
            close_error = None
            remove_error = None
            try:
                if save and program is not None and self._program_needs_save(program):
                    self.project.save(program)
            except Exception as exc:
                save_error = exc
                logger.warning("program save failed before close: %s", exc)
            try:
                if program is not None:
                    self.project.close(program)
            except Exception as exc:
                close_error = exc
                logger.warning("program close failed: %s", exc)
            if remove_program:
                try:
                    self._delete_program_locked(domain_path)
                except Exception as exc:
                    remove_error = exc
            self._open_programs.discard(domain_key)
            self._refcount = max(0, self._refcount - 1)
            if self._refcount == 0:
                self._close_project_locked()
            if close_error is not None:
                messages = []
                if save_error is not None:
                    messages.append(f"failed to save program before close: {save_error}")
                messages.append(f"failed to close program: {close_error}")
                if remove_error is not None:
                    messages.append(f"failed to remove program: {remove_error}")
                raise RuntimeError(f"SESSION_CLOSE_FAILED: {'; '.join(messages)}")
            if save_error is not None:
                messages = [f"failed to save program before close: {save_error}"]
                if remove_error is not None:
                    messages.append(f"failed to remove program: {remove_error}")
                raise RuntimeError(f"SAVE_FAILED: {'; '.join(messages)}")
            if remove_error is not None:
                raise RuntimeError(f"REMOVE_PROGRAM_FAILED: {remove_error}")

    def list_programs(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("Project is closed")
            results = []
            root = self.project.getProjectData().getRootFolder()
            path_utils._collect_program_files(root, results)
            return results

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        with self._lock:
            self._close_project_locked()

    # ------------------------------------------------------------------

    def _close_project_locked(self) -> None:
        if self._closed:
            return
        try:
            self.project.close()
        except Exception as exc:
            logger.warning("project close failed: %s", exc)
        self._open_programs.clear()
        self._closed = True

    def _delete_program_locked(self, domain_path: str) -> None:
        if self._closed:
            return
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Program to remove not found: {domain_path}")
        try:
            domain_file.delete()
        except Exception as exc:
            raise RuntimeError(f"Failed to remove program: {domain_path}: {exc}")

    @staticmethod
    def _program_needs_save(program) -> bool:
        is_changed = getattr(program, "isChanged", None)
        if is_changed is None:
            return True
        try:
            return bool(is_changed())
        except Exception:
            return True

    def _get_domain_file_locked(self, domain_path: str):
        if not domain_path:
            raise ValueError("domain_path is required")
        data = self.project.getProjectData()
        domain_file = data.getFile(domain_path)
        if domain_file is None:
            raise RuntimeError(f"Program not found: {domain_path}")
        return domain_file

    def _import_program_auto_locked(self, path: pathlib.Path, program_dir: str, program_name: str):
        program = None
        try:
            java_file = pycore.JClass("java.io.File")(str(path))
            program = self.project.importProgram(java_file)
            self.project.saveAs(program, program_dir, program_name, True)
            return program.getDomainFile()
        finally:
            if program is not None:
                self.project.close(program)

    def _import_program_raw_locked(
        self,
        path: pathlib.Path,
        *,
        program_dir: str,
        program_name: str,
        language_id: str,
        compiler_spec_id: str | None,
        base_address: str | None,
        file_offset: int | None,
        length: int | None,
        block_name: str | None,
        overlay: bool,
    ):
        monitor = java_bindings._console_monitor()
        loader_factory = getattr(pyghidra, "program_loader", None)
        builder_factory = loader_factory or (lambda: pycore.JClass("ghidra.app.util.importer.ProgramLoader").builder())
        loader_value = "ghidra.app.util.opinion.BinaryLoader"
        try:
            loader_value = pycore.JClass(loader_value)
        except Exception:
            pass
        builder = (
            builder_factory()
            .project(self.project.getProject())
            .projectFolderPath(program_dir)
            .source(str(path))
            .name(program_name)
            .loaders(loader_value)
            .language(language_id)
        )
        if compiler_spec_id is not None:
            builder = builder.compiler(compiler_spec_id)

        loader_option_args = self._resolve_binary_loader_args_locked(builder)
        loader_args = {
            "Base Address": base_address,
            "File Offset": file_offset,
            "Length": length,
            "Block Name": block_name,
        }
        for option_name, value in loader_args.items():
            if value is None:
                continue
            option_arg = loader_option_args.get(option_name)
            if option_arg is None:
                logger.debug("binary loader option is unavailable in this environment: %s", option_name)
                continue
            builder = builder.addLoaderArg(option_arg, str(value))
        if overlay:
            option_arg = loader_option_args.get("Overlay")
            if option_arg is not None:
                builder = builder.addLoaderArg(option_arg, "true")

        load_results = builder.load()
        try:
            loaded_program = load_results.getPrimary()
            if loaded_program is None:
                raise RuntimeError(f"Failed to add program: {path}")
            return loaded_program.save(monitor)
        finally:
            load_results.close()

    def _post_process_imported_program_locked(
        self,
        domain_path: str,
        *,
        entry_address: str | None,
        entry_offset: int | None,
        analyze_imported: bool,
    ) -> None:
        monitor = java_bindings._console_monitor()
        domain_dir, domain_name = path_utils._parse_domain_path(self.project, domain_path)
        program = self.project.openProgram(domain_dir, domain_name, False)
        if program is None:
            raise RuntimeError(f"Failed to reopen imported program: {domain_path}")
        flat_api = java_bindings._flat_program_api_class()(program, monitor)
        try:
            entry = self._resolve_entry_address_locked(
                program,
                entry_address=entry_address,
                entry_offset=entry_offset,
            )
            if entry is not None:
                self._bootstrap_entry_locked(program, flat_api, entry)
            if analyze_imported:
                self._analyze_program_locked(program, flat_api)
            self.project.save(program)
        finally:
            self.project.close(program)

    def _resolve_entry_address_locked(
        self,
        program,
        *,
        entry_address: str | None,
        entry_offset: int | None,
    ):
        if entry_address is not None:
            return self._address_from_int_locked(program, int(entry_address, 0))
        if entry_offset is None:
            return None
        min_address = self._get_imported_min_address_locked(program)
        return self._address_from_int_locked(program, int(min_address.getOffset()) + int(entry_offset))

    def _bootstrap_entry_locked(self, program, flat_api, entry) -> None:
        tx = program.startTransaction("Bootstrap imported entry")
        committed = False
        try:
            listing = program.getListing()
            function_manager = program.getFunctionManager()
            symbol_table = program.getSymbolTable()
            if listing.getInstructionAt(entry) is None:
                flat_api.disassemble(entry)
            if function_manager.getFunctionAt(entry) is None:
                flat_api.createFunction(entry, None)
            if not bool(symbol_table.isExternalEntryPoint(entry)):
                flat_api.addEntryPoint(entry)
            committed = True
        finally:
            program.endTransaction(tx, committed)

    def _analyze_program_locked(self, program, flat_api) -> None:
        utilities = java_bindings._ghidra_program_utilities()
        if not bool(utilities.shouldAskToAnalyze(program)):
            return
        script_util = java_bindings._ghidra_script_util()
        script_util.acquireBundleHostReference()
        try:
            flat_api.analyzeAll(program)
            utilities.markProgramAnalyzed(program)
        finally:
            script_util.releaseBundleHostReference()

    def _get_imported_min_address_locked(self, program):
        memory = program.getMemory()
        for getter_name in ("getLoadedAndInitializedAddressSet", "getLoadedAddressSet"):
            getter = getattr(memory, getter_name, None)
            if getter is None:
                continue
            address_set = getter()
            if address_set is None:
                continue
            min_address = address_set.getMinAddress()
            if min_address is not None:
                return min_address
        for getter_name in ("getImageBase", "getMinAddress"):
            getter = getattr(program, getter_name, None)
            if getter is None:
                continue
            address = getter()
            if address is not None:
                return address
        raise RuntimeError("Failed to resolve imported program base address")

    def _address_from_int_locked(self, program, value: int):
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        if address_space is None:
            raise RuntimeError("Program has no default address space")
        return address_space.getAddress(int(value))

    def _resolve_binary_loader_args_locked(self, builder) -> dict[str, str]:
        fallback = {
            "Base Address": "Base Address",
            "File Offset": "File Offset",
            "Length": "Length",
            "Block Name": "Block Name",
            "Overlay": "Overlay",
        }
        try:
            builder_class = builder.getClass()
            byte_provider_class = pycore.JClass("ghidra.app.util.bin.ByteProvider")
            load_spec_class = pycore.JClass("ghidra.app.util.opinion.LoadSpec")
            get_source = builder_class.getDeclaredMethod("getSourceAsProvider")
            get_source.setAccessible(True)
            provider = get_source.invoke(builder)
            try:
                get_load_spec = builder_class.getDeclaredMethod("getLoadSpec", byte_provider_class.class_)
                get_load_spec.setAccessible(True)
                load_spec = get_load_spec.invoke(builder, provider)
                get_loader_options = builder_class.getDeclaredMethod(
                    "getLoaderOptions",
                    byte_provider_class.class_,
                    load_spec_class.class_,
                )
                get_loader_options.setAccessible(True)
                options = get_loader_options.invoke(builder, provider, load_spec)
            finally:
                close = getattr(provider, "close", None)
                if close is not None:
                    close()
            resolved = dict(fallback)
            if options is None:
                return resolved
            for option in options:
                option_name = option.getName()
                option_arg = option.getArg()
                if option_name is None or option_arg is None:
                    continue
                resolved[str(option_name)] = str(option_arg)
            return resolved
        except Exception as exc:
            logger.debug("failed to resolve binary loader option args; using fallback names: %s", exc)
            return fallback


__all__ = ["ProjectHandle"]
