"""Where the Ghidra GUI runtimes of this OS user announce themselves, so relays find them (spec §10.1).

One directory per OS user, which only its owner can read, holds three files
per project; ``<key>`` comes from the ``.gpr`` file's ``st_dev`` and
``st_ino``, so every name of the same file (a symlink, a hardlink, another
case on a case-insensitive disk) is the same project:

- ``<key>.lock``: the runtime holds an OS file lock on it while it lives.  A
  relay that can take the lock knows no runtime is alive; no PID is involved,
  so a reused PID never fools it.  The OS drops the lock when the process
  ends, however it ends.
- ``<key>.json``: the runtime's record (endpoint, token, versions, the
  configuration it runs with, its state), readable by the owner only.
- ``<key>.launch.lock``: a relay holds it while it looks for the runtime and
  starts one, so concurrent first starts make one runtime.

Ghidra's own project lock stays the last protection against two runtimes.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REGISTRY_FORMAT = 1

STARTING = "starting"
READY = "ready"
FAILED = "failed"


def registry_dir() -> Path:
    """This OS user's directory of runtime records (spec §10.1)."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "mecha_ghidra" / "gui-runtimes"


def ensure_registry_dir(directory: Path) -> Path:
    """Create ``directory`` for its owner only, and refuse one that another user owns."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        status = directory.stat()
        if status.st_uid != os.getuid():
            raise PermissionError(f"The GUI runtime registry {directory} belongs to another user")
        if status.st_mode & 0o077:
            os.chmod(directory, 0o700)
    return directory


def project_key(gpr_file: str | os.PathLike[str]) -> str:
    """The project's key: the ``.gpr`` file's identity, or its real path where the disk has no inode numbers."""
    status = os.stat(gpr_file)
    if status.st_ino:
        material = f"inode:{status.st_dev}:{status.st_ino}"
    else:  # some network shares: the real path, whose limits the documentation states
        material = "path:" + os.path.normcase(os.path.realpath(gpr_file))
    return hashlib.sha256(material.encode()).hexdigest()[:32]


class FileLock:
    """An exclusive OS lock on one file, held until ``release`` or the end of the process.

    The descriptor is not inherited (PEP 446), so a child process never keeps
    the lock after this process ends.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def try_acquire(self) -> bool:
        if self._fd is not None:
            return True
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def acquire(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self.try_acquire():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                with contextlib.suppress(OSError):
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@dataclass
class RuntimeRecord:
    """What a relay needs to reach and check a runtime (spec §10.1)."""

    runtime_id: str
    pid: int
    endpoint: str
    token: str
    # A runtime started in the foreground with the user's HTTP listener also takes requests without the token.
    public: bool
    project_file: str
    ghidra_install_dir: str | None
    mecha_version: str
    # What a relay must match (versions, path policy, startup targets) or include (tools); spec §10.3.
    fingerprint: dict[str, Any]
    # Runtime-wide settings a relay cannot change; a difference is only logged.
    settings: dict[str, Any] = field(default_factory=dict)
    state: str = STARTING
    # The STARTUP_FAILED details once the startup failed (stage, cause_type, cause_message, message).
    failure: dict[str, Any] | None = None
    log_file: str | None = None
    started_at: float = field(default_factory=time.time)
    format: int = REGISTRY_FORMAT

    @classmethod
    def from_json(cls, text: str) -> RuntimeRecord:
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("format") != REGISTRY_FORMAT:
            raise ValueError("unsupported GUI runtime record")
        known = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in data.items() if key in known})

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, sort_keys=True)


class ProjectRegistry:
    """The registry files of one project."""

    def __init__(self, gpr_file: str | os.PathLike[str], directory: Path | None = None) -> None:
        self.directory = ensure_registry_dir(directory or registry_dir())
        self.key = project_key(gpr_file)
        self.project_file = os.path.realpath(gpr_file)

    def _path(self, suffix: str) -> Path:
        return self.directory / f"{self.key}{suffix}"

    @property
    def record_path(self) -> Path:
        return self._path(".json")

    @property
    def log_path(self) -> Path:
        return self._path(".log")

    def runtime_lock(self) -> FileLock:
        return FileLock(self._path(".lock"))

    def launch_lock(self) -> FileLock:
        return FileLock(self._path(".launch.lock"))

    def runtime_alive(self) -> bool:
        """Whether a runtime holds the project's lock (it is free when none is alive)."""
        probe = self.runtime_lock()
        if probe.try_acquire():
            probe.release()
            return False
        return True

    def read(self) -> RuntimeRecord | None:
        try:
            return RuntimeRecord.from_json(self.record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None

    def write(self, record: RuntimeRecord) -> None:
        """Replace the record at once: a reader sees the old record or the new one, never half of one.

        ``mkstemp`` creates the file for its owner only (0600), token included.
        """
        fd, temporary = tempfile.mkstemp(dir=self.directory, prefix=f".{self.key}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(record.to_json())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.record_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise

    def remove(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.record_path.unlink()


__all__ = [
    "FAILED",
    "READY",
    "REGISTRY_FORMAT",
    "STARTING",
    "FileLock",
    "ProjectRegistry",
    "RuntimeRecord",
    "ensure_registry_dir",
    "project_key",
    "registry_dir",
]
