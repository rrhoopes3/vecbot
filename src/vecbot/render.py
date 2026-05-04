"""Text reports and snake visualization."""

from __future__ import annotations


def snake_view(phase: str, capabilities: list[str], drift: float = 0.0) -> str:
    head = "o"
    body = "-"
    tags = "".join(f"[{capability}]" for capability in capabilities if _is_leg(capability))
    if phase in {"INIT_IMPORT", "STEADY_RUN"}:
        body = "="
    return f"[{phase:10}] {head}{body * 8}{tags} drift={drift:.2f}"


def format_finding(finding, event) -> str:
    lines = [
        "Suspicious phase capability drift",
        f"severity: {finding.severity}",
        f"pid: {event.pid}",
        f"phase: {finding.phase}",
        f"package: {finding.package}",
        f"capability: {finding.capability}",
        f"target: {event.target}",
        f"attribution: {event.attribution_source} ({event.attribution_confidence:.2f})",
        "evidence: " + "; ".join(finding.reasons),
    ]
    if finding.drift:
        lines.append(f"drift: {finding.drift:.2f}")
    return "\n".join(lines)


def format_residue(residue: dict[str, list[str]]) -> str:
    lines = ["Residue detected"]
    for key, values in residue.items():
        lines.append(f"{key}: {', '.join(values)}")
    return "\n".join(lines)


def _is_leg(capability: str) -> bool:
    return capability in {
        "net.outbound",
        "net.listen",
        "proc.spawn",
        "secret.file_read",
        "secret.env_read",
        "persistence.startup_hook",
    }

