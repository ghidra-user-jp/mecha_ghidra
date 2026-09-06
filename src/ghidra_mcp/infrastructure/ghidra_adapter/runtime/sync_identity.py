"""Domain-path resolution and project/file identity checks."""

from __future__ import annotations

import ipaddress
import logging
import pathlib
import urllib.parse

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import ProjectHandle, path_utils

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class SyncIdentityMixin:
    """Mixin for :class:`RuntimeSyncOperations`; expects ``self._store``."""

    _store: RuntimeSessionStore

    def _resolve_sync_target_locked(
        self,
        name: str,
        domain_path: str | None,
    ) -> tuple[ProjectHandle, str]:
        resolved_domain_path = (domain_path or "").strip()
        if resolved_domain_path:
            handle = self._store.get_target_handle(name)
            return handle, self._normalize_domain_path_locked(handle, resolved_domain_path)

        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        return handle, self._store.session_domain_path(session)

    @staticmethod
    def _normalize_domain_path_locked(handle: ProjectHandle, domain_path: str | None) -> str:
        domain_dir, domain_name = path_utils._parse_domain_path(handle.project, domain_path)
        normalized_path = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        return normalized_path

    @staticmethod
    def _session_is_read_only(session) -> bool:
        """A past version opened read-only is pinned; sync operations never reopen it."""
        return getattr(session, "read_only_version", None) is not None

    def _is_active_domain_path_locked(self, name: str, domain_path: str) -> bool:
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None or self._session_is_read_only(session):
            return False
        return self._store.session_domain_path(session) == domain_path

    def _find_loaded_target_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        include_read_only: bool = False,
    ) -> str | None:
        requested_key = handle.get_key()
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            if not include_read_only and self._session_is_read_only(session):
                continue
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise HeadlessError(
                    f"SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target '{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if session_handle.get_key() == requested_key:
                return target_name
        return None

    def _find_loaded_target_across_shared_project_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
    ) -> str | None:
        # Destructive guards count read-only version sessions too: the versioned
        # copy keeps the repository file busy until it is released.
        local_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path, include_read_only=True)
        if local_target is not None:
            return local_target
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise HeadlessError(
                    f"SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target '{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if self._handles_share_destructive_file_identity(
                handle,
                session_handle,
                domain_path=domain_path,
            ):
                return target_name
        return None

    def _find_loaded_checkout_owner_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        checkout_id: int,
    ) -> str | None:
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            if self._session_is_read_only(session):
                continue
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise HeadlessError(
                    f"SYNC_STATUS_UNAVAILABLE: failed to inspect loaded checkout owner '{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if not self._handles_share_destructive_file_identity(
                handle,
                session_handle,
                domain_path=domain_path,
            ):
                continue
            try:
                self._refresh_project_sync_state_locked(session_handle, required=True)
                loaded_status = session_handle.get_sync_status(domain_path)
                self._ensure_checkout_status_consistent(
                    loaded_status,
                    context=f"loaded target '{target_name}'",
                )
                checkout_status = loaded_status.get("checkout_status") or {}
            except Exception as exc:
                raise HeadlessError(
                    f"SYNC_STATUS_UNAVAILABLE: failed to inspect loaded checkout state for '{target_name}': {exc}"
                ) from exc
            local_checkout_id = checkout_status.get("checkout_id")
            if local_checkout_id is not None and int(local_checkout_id) == int(checkout_id):
                return target_name
        return None

    @staticmethod
    def _handles_share_project_identity(first: ProjectHandle, second: ProjectHandle) -> bool:
        first_shared = SyncIdentityMixin._shared_project_identity(first)
        if first_shared is None:
            return first.get_key() == second.get_key()
        second_shared = SyncIdentityMixin._shared_project_identity(second)
        return second_shared is not None and first_shared == second_shared

    @staticmethod
    def _handles_share_destructive_file_identity(
        first: ProjectHandle,
        second: ProjectHandle,
        *,
        domain_path: str,
    ) -> bool:
        """Identify one repository file across caches, including DNS URL aliases.

        Project URLs are sufficient for the normal case.  When two local caches
        reached the same Ghidra Server through different DNS aliases, however,
        URL comparison cannot prove identity.  Version-controlled Ghidra files
        retain the same file ID across checkouts/caches, so destructive guards
        use it as a second, path-scoped identity and otherwise fail closed.
        """
        if first.get_key() == second.get_key():
            return True

        first_shared = SyncIdentityMixin._shared_project_identity(first)
        second_shared = SyncIdentityMixin._shared_project_identity(second)
        if first_shared is None or second_shared is None:
            return False
        if first_shared == second_shared:
            return True

        first_file_id = SyncIdentityMixin._domain_file_identity(first, domain_path)
        second_file_id = SyncIdentityMixin._domain_file_identity(second, domain_path)
        return first_file_id == second_file_id

    @staticmethod
    def _domain_file_identity(handle: ProjectHandle, domain_path: str) -> str:
        get_file_id = getattr(handle, "get_domain_file_id", None)
        if get_file_id is None:
            raise HeadlessError("SYNC_STATUS_UNAVAILABLE: project handle does not support domain file ID lookup")
        try:
            file_id = get_file_id(domain_path)
        except Exception as exc:
            raise HeadlessError(f"SYNC_STATUS_UNAVAILABLE: failed to inspect domain file ID: {exc}") from exc
        normalized_id = str(file_id or "").strip()
        if not normalized_id:
            raise HeadlessError("SYNC_STATUS_UNAVAILABLE: domain file ID is unavailable for destructive identity check")
        return normalized_id

    @staticmethod
    def _shared_project_identity(handle: ProjectHandle) -> str | None:
        get_url = getattr(handle, "get_shared_project_url", None)
        if get_url is None:
            return None
        try:
            value = get_url()
        except Exception as exc:
            raise HeadlessError(f"SYNC_STATUS_UNAVAILABLE: failed to inspect shared project URL: {exc}") from exc
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None
        try:
            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise HeadlessError(f"SYNC_STATUS_UNAVAILABLE: invalid shared project URL: {exc}") from exc
        if not scheme or host is None or parsed.username is not None or parsed.password is not None:
            raise HeadlessError("SYNC_STATUS_UNAVAILABLE: shared project URL lacks a safe scheme/host identity")
        if parsed.query or parsed.fragment:
            raise HeadlessError("SYNC_STATUS_UNAVAILABLE: shared project URL must not contain query or fragment data")

        normalized_host = host.rstrip(".").lower()
        try:
            address = ipaddress.ip_address(normalized_host)
        except ValueError:
            if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
                normalized_host = "loopback"
        else:
            normalized_host = "loopback" if address.is_loopback else address.compressed

        # Ghidra uses 13100 as its default repository server base port.  Include
        # the effective port so an omitted default and an explicit :13100 share
        # one identity while different server instances remain isolated.
        effective_port = 13100 if scheme == "ghidra" and port is None else port
        host_text = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        authority = host_text if effective_port is None else f"{host_text}:{effective_port}"
        path = parsed.path.rstrip("/") or "/"
        return urllib.parse.urlunsplit((scheme, authority, path, "", ""))
