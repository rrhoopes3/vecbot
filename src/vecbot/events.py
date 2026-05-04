"""Event model and normalization for VecBot traces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


CAPABILITY_VOCAB = {
    "fs.read",
    "fs.write",
    "fs.exec_path_touch",
    "net.outbound",
    "net.listen",
    "proc.spawn",
    "proc.inject_like",
    "ipc.open",
    "mem.rwx",
    "mem.dynamic_code",
    "secret.env_read",
    "secret.file_read",
    "identity.user_lookup",
    "persistence.startup_hook",
    "logs.tamper",
    "import.dynamic",
}


@dataclass(slots=True)
class Event:
    ts: float
    pid: int
    tid: int = 0
    phase_hint: str | None = None
    source: str = "synthetic"
    action: str = ""
    target: str = ""
    capability: str = ""
    actor: str | None = None
    package: str | None = None
    module: str | None = None
    fd: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    attribution_source: str = "synthetic"
    attribution_confidence: float = 1.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, line: str) -> "Event":
        return normalize(json.loads(line))


def normalize(raw: dict[str, Any] | Event) -> Event:
    """Normalize a raw mapping into an Event without discarding attribution."""
    if isinstance(raw, Event):
        return raw

    capability = raw.get("capability") or capability_from_action(
        str(raw.get("action", "")),
        str(raw.get("target", "")),
    )

    if capability not in CAPABILITY_VOCAB:
        raise ValueError(f"unknown capability: {capability}")

    return Event(
        ts=float(raw["ts"]),
        pid=int(raw["pid"]),
        tid=int(raw.get("tid", 0)),
        phase_hint=raw.get("phase_hint"),
        source=raw.get("source", "synthetic"),
        action=str(raw.get("action", "")),
        target=str(raw.get("target", "")),
        capability=capability,
        actor=raw.get("actor"),
        package=raw.get("package"),
        module=raw.get("module"),
        fd=raw.get("fd"),
        metadata=dict(raw.get("metadata") or {}),
        attribution_source=raw.get("attribution_source", "synthetic"),
        attribution_confidence=float(raw.get("attribution_confidence", 1.0)),
    )


def capability_from_action(action: str, target: str) -> str:
    action = action.lower()
    target = target.lower()

    if action in {"connect", "sendto"} or "socket" in action:
        return "net.outbound"
    if action in {"listen", "bind"}:
        return "net.listen"
    if action in {"exec", "execve", "spawn", "fork"}:
        return "proc.spawn"
    if action == "import":
        return "import.dynamic"
    if "startup" in target or "autostart" in target or "systemd" in target:
        return "persistence.startup_hook"
    if "secret" in target or ".pypirc" in target or ".npmrc" in target:
        return "secret.file_read"
    if action in {"write", "rename", "unlink"}:
        return "fs.write"
    return "fs.read"

