"""CLI adapter for Ghidra's support/bsim utility."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


_EXEC_COUNT_RE = re.compile(r"Matching executable count:\s*(?P<count>\d+)", re.IGNORECASE)


def mask_bsim_url(url: str | None) -> str | None:
    """Mask credentials embedded in a BSim URL."""

    if not url:
        return url
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    if not parts.username and not parts.password:
        return url
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, f"***:***@{host}", parts.path, parts.query, parts.fragment))


@dataclass(frozen=True)
class BsimCliResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "args": [mask_bsim_url(arg) or arg for arg in self.args],
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class BsimCliRunner:
    def __init__(
        self,
        *,
        ghidra_install_dir: str | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        self._ghidra_install_dir = ghidra_install_dir
        self._timeout_seconds = int(timeout_seconds)

    def _support_bsim_path(self) -> str:
        ghidra_dir = self._ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
        if not ghidra_dir:
            raise RuntimeError("BSIM_GHIDRA_HOME_REQUIRED: set --ghidra-path or GHIDRA_INSTALL_DIR")
        path = Path(ghidra_dir).expanduser() / "support" / "bsim"
        if not path.is_file():
            raise RuntimeError(f"BSIM_CLI_NOT_FOUND: {path}")
        return str(path)

    def run(self, args: list[str], *, timeout_seconds: int | None = None) -> BsimCliResult:
        command = [self._support_bsim_path(), *args]
        env = dict(os.environ)
        env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds if timeout_seconds is None else int(timeout_seconds),
            env=env,
        )
        result = BsimCliResult(
            args=command,
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if result.returncode != 0:
            masked = result.to_dict()
            raise RuntimeError(
                "BSIM_CLI_FAILED: "
                f"args={masked['args']} returncode={result.returncode} stderr={result.stderr.strip()}"
            )
        return result

    def get_executable_count(self, bsim_url: str) -> int:
        result = self.run(["getexecount", bsim_url])
        match = _EXEC_COUNT_RE.search(result.stdout)
        if match is None:
            raise RuntimeError(f"BSIM_PARSE_FAILED: getexecount output was not recognized: {result.stdout.strip()}")
        return int(match.group("count"))

    def generate_signatures(
        self,
        *,
        ghidra_url: str,
        signature_dir: str,
        bsim_url: str,
        overwrite: bool = True,
        commit: bool = False,
    ) -> BsimCliResult:
        args = ["generatesigs", ghidra_url, signature_dir, "--bsim", bsim_url]
        if overwrite:
            args.append("--overwrite")
        if commit:
            args.append("--commit")
        return self.run(args)

    def commit_signatures(self, *, bsim_url: str, signature_dir: str) -> BsimCliResult:
        return self.run(["commitsigs", bsim_url, signature_dir])


__all__ = ["BsimCliResult", "BsimCliRunner", "mask_bsim_url"]
