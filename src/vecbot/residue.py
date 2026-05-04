"""Residue checks over a final synthetic process snapshot."""

from __future__ import annotations


def check_residue(events: list[tuple[str, object]]) -> dict[str, list[str]]:
    residue: dict[str, list[str]] = {
        "child_processes": [],
        "persistence_files": [],
        "lingering_hooks": [],
        "open_fds": [],
    }

    closed_fds: set[int] = set()
    opened_fds: dict[int, str] = {}

    for _phase, event in events:
        if event.fd is not None and event.action in {"open", "socket", "connect"}:
            opened_fds[event.fd] = event.target
        if event.fd is not None and event.action == "close":
            closed_fds.add(event.fd)

        if event.capability == "proc.spawn" and event.metadata.get("child") is True:
            residue["child_processes"].append(event.target)
        if "startup" in event.target.lower() or "autostart" in event.target.lower():
            residue["persistence_files"].append(event.target)
        if event.capability == "persistence.startup_hook":
            residue["lingering_hooks"].append(event.target)

    for fd, target in opened_fds.items():
        if fd not in closed_fds:
            residue["open_fds"].append(f"{fd}:{target}")

    return {key: values for key, values in residue.items() if values}

