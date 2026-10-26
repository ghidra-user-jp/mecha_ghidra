"""Run the official MCP conformance suite against the fixture server.

    python tests/mcp_conformance/run.py [--revision 2026-07-28|2025-11-25|all] [--output-dir DIR]

It starts ``server.py`` on a free loopback port, runs the suite once for each revision's required scenarios
(``--requirements``) and stops the server.  ``expected-failures-<revision>.yml`` lists what this server is known
not to pass, each with its reason; the run fails on a scenario that fails and is not listed, and on a listed
one that passes.  A listed failure still counts as a failure in the suite's own pass rate.

The suite is an npm package, pinned below.  ``MECHA_CONFORMANCE_COMMAND`` replaces the command that runs it
(for example a wrapper around an npm cache that works offline); ``server ...`` is appended to it.
"""

from __future__ import annotations

import argparse
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINNED_SUITE = "@modelcontextprotocol/conformance@0.2.0-alpha.11"
REVISIONS = ("2026-07-28", "2025-11-25")
# What npx may do when it fetches the suite: no install scripts (the suite needs none), no notices.
# The caller's own npm settings win.
NPM_DEFAULTS = {
    "npm_config_ignore_scripts": "true",
    "npm_config_update_notifier": "false",
    "npm_config_fund": "false",
    "npm_config_audit": "false",
}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_until_serving(port: int, server: subprocess.Popen, seconds: float = 60) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + seconds
    while True:
        try:
            opener.open(f"http://127.0.0.1:{port}/mcp", timeout=3).close()
            return
        except urllib.error.HTTPError:
            return  # any HTTP answer: the listener is up
        except OSError:
            if server.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("the fixture server did not come up") from None
            time.sleep(0.2)


def run(revisions: list[str], output_dir: Path, command: list[str]) -> int:
    port = free_port()
    server = subprocess.Popen([sys.executable, str(HERE / "server.py"), str(port)], stdin=subprocess.DEVNULL)
    try:
        wait_until_serving(port, server)
        status = 0
        for revision in revisions:
            arguments = [
                *command,
                "server",
                "--url",
                f"http://127.0.0.1:{port}/mcp",
                "--requirements",
                revision,
                "-o",
                str(output_dir / revision),
            ]
            baseline = HERE / f"expected-failures-{revision}.yml"
            if baseline.exists():
                arguments += ["--expected-failures", str(baseline)]
            print(f"=== requirements {revision}", flush=True)
            completed = subprocess.run(arguments, stdin=subprocess.DEVNULL, env={**NPM_DEFAULTS, **os.environ})
            status = max(status, completed.returncode)
        return status
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--revision", choices=[*REVISIONS, "all"], default="all")
    parser.add_argument("--output-dir", type=Path, default=None, help="where the suite saves its results")
    arguments = parser.parse_args(argv)
    command = shlex.split(os.environ.get("MECHA_CONFORMANCE_COMMAND", "")) or ["npx", "--yes", PINNED_SUITE]
    revisions = list(REVISIONS) if arguments.revision == "all" else [arguments.revision]
    output_dir = arguments.output_dir or Path(tempfile.mkdtemp(prefix="mcp-conformance-"))
    return run(revisions, output_dir, command)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
