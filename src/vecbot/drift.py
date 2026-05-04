"""Explainable drift scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
import math

SENSITIVE_CAPABILITIES = {
    "net.outbound",
    "proc.spawn",
    "secret.env_read",
    "secret.file_read",
    "persistence.startup_hook",
    "logs.tamper",
    "mem.rwx",
    "mem.dynamic_code",
}


@dataclass(slots=True)
class Finding:
    phase: str
    package: str
    capability: str
    severity: str
    reasons: list[str] = field(default_factory=list)
    drift: float = 0.0
    primary_signal: bool = False

    @property
    def is_interesting(self) -> bool:
        return self.primary_signal or self.severity in {"medium", "high", "critical"}


def js_divergence(current: dict[str, float], baseline: dict[str, float]) -> float:
    """Jensen-Shannon distance over sparse distributions using only stdlib."""
    vocab = set(current) | set(baseline)
    if not vocab:
        return 0.0

    p = _normalize([current.get(item, 0.0) for item in vocab])
    q = _normalize([baseline.get(item, 0.0) for item in vocab])
    if not any(p) or not any(q):
        return 0.0

    midpoint = [(left + right) / 2.0 for left, right in zip(p, q)]
    divergence = (_kl(p, midpoint) + _kl(q, midpoint)) / 2.0
    return math.sqrt(divergence)


def score_event(
    event,
    phase: str,
    capability_is_new: bool,
    drift: float,
    attribution_floor: float = 0.5,
) -> Finding | None:
    reasons: list[str] = []
    severity = "info"
    primary_signal = False
    sensitive = event.capability in SENSITIVE_CAPABILITIES

    if capability_is_new and sensitive:
        primary_signal = True
        reasons.append("capability absent from baseline for package in phase")
        severity = "high"

    if event.attribution_confidence < attribution_floor:
        reasons.append(f"weak attribution confidence {event.attribution_confidence:.2f}")
        if severity == "info" and sensitive:
            severity = "medium"

    if drift >= 0.35 and (primary_signal or event.attribution_confidence < attribution_floor):
        reasons.append(f"phase distribution drift {drift:.2f}")

    if event.capability == "persistence.startup_hook":
        severity = "critical"

    if not reasons:
        return None

    return Finding(
        phase=phase,
        package=event.package or "unknown",
        capability=event.capability,
        severity=severity,
        reasons=reasons,
        drift=round(drift, 3),
        primary_signal=primary_signal,
    )


def _normalize(values: list[float]) -> list[float]:
    total = sum(values)
    if total <= 0:
        return [0.0 for _ in values]
    return [value / total for value in values]


def _kl(left: list[float], right: list[float]) -> float:
    total = 0.0
    for p, q in zip(left, right):
        if p > 0 and q > 0:
            total += p * math.log2(p / q)
    return total
