"""
Base collector machinery shared by the cloud collectors.

Design note: collectors NEVER authenticate. They shell out to the cloud CLI
(`az`, `aws`) and rely on the operator's *existing* SSO session. The agent
therefore inherits exactly the caller's access — it can read nothing the user
could not read themselves. Every command issued is read-only (list/show).
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, List, Sequence

# A runner takes a fully-formed CLI argv and returns the command's stdout (JSON
# text). Injecting this is what makes collectors testable without real cloud creds.
CommandRunner = Callable[[Sequence[str]], str]


class CollectorError(RuntimeError):
    """Raised when a cloud CLI command fails in a way that should abort the scan."""


def default_runner(args: Sequence[str]) -> str:
    """Run a cloud CLI command using the ambient login and return stdout."""
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CollectorError(
            f"'{args[0]}' was not found on PATH. Install the cloud CLI and sign in "
            f"(e.g. 'az login') before running a live scan."
        ) from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise CollectorError(
            f"Command failed ({proc.returncode}): {' '.join(args)}\n{stderr}"
        )
    return proc.stdout


@dataclass
class CollectionResult:
    """Outcome of a collection run: the mapped resources plus any soft failures."""

    resources: List[Any] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class BaseCollector:
    """Common helpers for cloud collectors."""

    cli_name: str = "<cli>"

    def __init__(self, runner: CommandRunner = default_runner) -> None:
        self._runner = runner

    def _json(self, args: Sequence[str]) -> Any:
        """Run a command and parse its JSON stdout. Empty stdout -> empty list."""
        out = self._runner(args)
        if out is None or out.strip() == "":
            return []
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise CollectorError(
                f"Could not parse JSON from: {' '.join(args)}\n{exc}"
            ) from exc

    def collect(self) -> CollectionResult:  # pragma: no cover - abstract
        raise NotImplementedError
