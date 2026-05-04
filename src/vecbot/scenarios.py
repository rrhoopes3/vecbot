"""Synthetic traces used by the prototype and tests."""

from __future__ import annotations

from vecbot.events import normalize


def scenario_events(name: str):
    return [normalize(raw) for raw in raw_scenario(name)]


def raw_scenario(name: str) -> list[dict]:
    scenarios = {
        "clean": [
            event(0.1, "exec", "python", "proc.spawn", "python", phase_hint="START"),
            event(0.3, "import", "argparse", "import.dynamic", "python", phase_hint="INIT_IMPORT"),
            event(0.6, "import", "requests", "import.dynamic", "requests"),
            event(2.0, "open", "config.yaml", "fs.read", "demo-service", phase_hint="STEADY_RUN", fd=3),
            event(2.1, "connect", "api.internal:443", "net.outbound", "requests", fd=7),
            event(5.0, "close", "api.internal:443", "fs.read", "requests", phase_hint="SHUTDOWN", fd=7),
            event(5.1, "close", "config.yaml", "fs.read", "demo-service", fd=3),
        ],
        "malicious-import": [
            event(0.1, "exec", "python", "proc.spawn", "python", phase_hint="START"),
            event(0.3, "import", "theme_helper", "import.dynamic", "malicious-theme-helper", phase_hint="INIT_IMPORT"),
            event(0.4, "open", "~/.pypirc", "secret.file_read", "malicious-theme-helper"),
            event(0.5, "connect", "203.0.113.10:443", "net.outbound", "malicious-theme-helper", fd=9),
            event(2.0, "open", "config.yaml", "fs.read", "demo-service", phase_hint="STEADY_RUN"),
            event(4.0, "close", "all", "fs.read", "demo-service", phase_hint="SHUTDOWN", fd=9),
        ],
        "malicious-runtime": [
            event(0.1, "exec", "python", "proc.spawn", "python", phase_hint="START"),
            event(0.3, "import", "markdown_theme_helper", "import.dynamic", "markdown-theme-helper", phase_hint="INIT_IMPORT"),
            event(2.0, "open", "config.yaml", "fs.read", "demo-service", phase_hint="STEADY_RUN"),
            event(8.7, "exec", "/bin/sh", "proc.spawn", "markdown-theme-helper", metadata={"child": True}),
            event(8.8, "connect", "198.51.100.7:443", "net.outbound", "markdown-theme-helper", fd=8),
            event(12.0, "close", "config.yaml", "fs.read", "demo-service", phase_hint="SHUTDOWN"),
        ],
        "persistence-residue": [
            event(0.1, "exec", "python", "proc.spawn", "python", phase_hint="START"),
            event(0.3, "import", "build_helper", "import.dynamic", "build-helper", phase_hint="INIT_IMPORT"),
            event(2.0, "open", "config.yaml", "fs.read", "demo-service", phase_hint="STEADY_RUN"),
            event(3.0, "write", "~/.config/autostart/helper.desktop", "persistence.startup_hook", "build-helper"),
            event(5.0, "close", "all", "fs.read", "demo-service", phase_hint="SHUTDOWN"),
        ],
    }
    try:
        return scenarios[name]
    except KeyError as exc:
        choices = ", ".join(sorted(scenarios))
        raise ValueError(f"unknown scenario {name!r}; choose one of: {choices}") from exc


def event(
    ts: float,
    action: str,
    target: str,
    capability: str,
    package: str,
    *,
    phase_hint: str | None = None,
    fd: int | None = None,
    metadata: dict | None = None,
) -> dict:
    return {
        "ts": ts,
        "pid": 4242,
        "tid": 4242,
        "action": action,
        "target": target,
        "capability": capability,
        "package": package,
        "module": package.replace("-", "_"),
        "actor": package,
        "phase_hint": phase_hint,
        "fd": fd,
        "metadata": metadata or {},
        "attribution_source": "synthetic",
        "attribution_confidence": 1.0,
    }

