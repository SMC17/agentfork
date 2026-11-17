"""Minimal zero-dependency Python wrapper for the `agentfork` binary."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


_DEFAULT_LOCAL_BIN = Path(__file__).resolve().parent.parent / "zig-out" / "bin" / "agentfork"


def resolve_binary(binary: str | os.PathLike[str] | None = None) -> str:
    """Locate the `agentfork` executable via explicit path, env, PATH, or local build."""
    candidates: list[str | Path] = []
    if binary is not None:
        candidates.append(binary)
    env_bin = os.environ.get("AGENTFORK_BIN")
    if env_bin:
        candidates.append(env_bin)
    which_bin = shutil.which("agentfork")
    if which_bin:
        candidates.append(which_bin)
    candidates.append(_DEFAULT_LOCAL_BIN)

    for cand in candidates:
        path = Path(cand)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)

    raise FileNotFoundError(
        "Could not locate executable `agentfork` binary. "
        "Build with `zig build -Doptimize=ReleaseFast` or pass `binary=` / set `AGENTFORK_BIN`."
    )


@dataclass(frozen=True)
class RunResult:
    """Result from `agentfork run`."""

    exit_code: int
    used_cow_clonefile: bool
    clone_us: int
    run_ms: int
    stdout: str
    stderr: str
    sandbox_dir: str


def run(
    src_dir: str | os.PathLike[str],
    sandbox_dir: str | os.PathLike[str],
    cmd: str | Sequence[str],
    *,
    binary: str | os.PathLike[str] | None = None,
    check: bool = False,
    timeout: float | None = None,
) -> RunResult:
    """Fork `src_dir` into `sandbox_dir` via CoW and execute `cmd` inside it."""
    bin_path = resolve_binary(binary)
    cmd_args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    if not cmd_args:
        raise ValueError("cmd must not be empty")

    argv = [bin_path, "run", os.fspath(src_dir), os.fspath(sandbox_dir), "--", *cmd_args]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True)

    lines = proc.stdout.splitlines(keepends=True)
    if not lines:
        raise RuntimeError(f"Unexpected empty output from agentfork run: stderr={proc.stderr!r}")

    meta = json.loads(lines[0])
    child_stdout = "".join(lines[1:])
    result = RunResult(
        exit_code=int(meta["exit_code"]),
        used_cow_clonefile=bool(meta["used_cow_clonefile"]),
        clone_us=int(meta["clone_us"]),
        run_ms=int(meta["run_ms"]),
        stdout=child_stdout,
        stderr=proc.stderr,
        sandbox_dir=os.fspath(sandbox_dir),
    )

    if check and result.exit_code != 0:
        raise subprocess.CalledProcessError(
            result.exit_code,
            cmd_args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


class FirewallProcess:
    """Managed `agentfork firewall` subprocess with HTTP authorization helper."""

    def __init__(
        self,
        proc: subprocess.Popen[str],
        host: str,
        port: int,
    ) -> None:
        self.proc = proc
        self.host = host
        self.port = port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def authorize(
        self,
        sink: str,
        taint: str | Sequence[str],
        body: str | bytes = "",
        *,
        tool: str = "http_tool",
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Send an authorization check to the running taint firewall."""
        taint_header = taint if isinstance(taint, str) else ",".join(taint)
        payload = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(
            f"{self.url}/authorize",
            data=payload,
            method="POST",
            headers={
                "X-Sink": sink,
                "X-Taint": taint_header,
                "X-Tool": tool,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                data["http_status"] = resp.status
                return data
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            data["http_status"] = err.code
            return data

    def stop(self, timeout: float = 5.0) -> None:
        """Terminate the firewall process if still running."""
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=timeout)

    def __enter__(self) -> FirewallProcess:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


def firewall(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    audit: str | os.PathLike[str] | None = None,
    max_requests: int | None = None,
    binary: str | os.PathLike[str] | None = None,
    startup_timeout: float = 3.0,
) -> FirewallProcess:
    """Start `agentfork firewall` and wait until its TCP port is accepting connections."""
    bin_path = resolve_binary(binary)
    argv = [bin_path, "firewall", "--host", host, "--port", str(port)]
    if audit is not None:
        argv.extend(["--audit", os.fspath(audit)])
    if max_requests is not None:
        argv.extend(["--max-requests", str(max_requests)])

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    deadline = time.monotonic() + startup_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"agentfork firewall exited early ({proc.returncode}): {stderr}")
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return FirewallProcess(proc, host, port)
        except OSError:
            time.sleep(0.02)

    proc.terminate()
    raise TimeoutError(f"agentfork firewall did not start listening on {host}:{port} within {startup_timeout}s")
