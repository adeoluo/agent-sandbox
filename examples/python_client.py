"""Call agent-sandbox from Python over its JSON Lines stdio protocol.

Usage:
    cargo build --release
    python3 examples/python_client.py target/release/agent-sandbox policies/coding-agent.toml
"""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
from typing import Any


class SandboxClient:
    """A minimal client: one request line in, one response line out."""

    def __init__(self, binary: str, policy: str, audit: str | None = None) -> None:
        args = [binary, "serve", "--policy", policy]
        if audit:
            args += ["--audit", audit]
        self._proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        self._ids = itertools.count(1)

    def call(self, op: str, **fields: Any) -> dict[str, Any]:
        request = {"id": next(self._ids), "op": op, **fields}
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        response = json.loads(self._proc.stdout.readline())
        if not response["ok"]:
            raise RuntimeError(response["error"])
        return response["result"]

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=5)


def main() -> None:
    binary, policy = sys.argv[1], sys.argv[2]
    client = SandboxClient(binary, policy)
    try:
        for argv in (["ls", "src"], ["curl", "https://example.com"], ["cat", "~/.ssh/id_ed25519"]):
            decision = client.call("check", argv=argv)
            verdict = "ALLOW" if decision["allowed"] else "DENY "
            print(f"{verdict} {' '.join(argv):<32} {decision['rule']}")
        result = client.call("run", argv=["ls", "src"])
        print(f"run ls src -> exit {result['exit_code']}, {result['stdout_bytes']} bytes")
        print(f"enforced by: {result['enforcement']['backend']}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
