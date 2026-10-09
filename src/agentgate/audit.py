"""Tamper-evident decision log.

Each record is one JSON line holding the SHA-256 of the previous record, so editing or
deleting any past line breaks every hash after it. Secrets are redacted before writing:
the audit trail must never become the leak.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .detectors import redact_secrets
from .gate import Decision, ToolCall

GENESIS = "0" * 64


def _digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class AuditLog:
    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def record(self, call: ToolCall, decision: Decision, *, approved_by: str | None = None) -> dict:
        body = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": call.tool,
            "args": redact_secrets(call.args),
            "decision": decision.to_dict(),
            "approved_by": approved_by,
            "prev": self._last_hash(),
        }
        body["hash"] = _digest(body)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True) + "\n")
        return body

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_line). first_bad_line is 1-based, None when the chain is intact."""
        prev = GENESIS
        if not self.path.exists():
            return True, None
        with self.path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                claimed = rec.pop("hash", None)
                if rec.get("prev") != prev or _digest(rec) != claimed:
                    return False, n
                prev = claimed
        return True, None
