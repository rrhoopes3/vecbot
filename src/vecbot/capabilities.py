"""Capability baseline and observation tracking."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

PackagePhaseKey = tuple[str, str]


@dataclass
class CapabilityBaseline:
    """Baseline of capabilities observed for each package in each phase."""

    package_phase_caps: dict[PackagePhaseKey, set[str]] = field(default_factory=dict)
    phase_histograms: dict[str, Counter[str]] = field(default_factory=dict)

    @classmethod
    def learn(cls, traces: list[list]) -> "CapabilityBaseline":
        from vecbot.phases import PhaseDetector

        baseline = cls()
        for trace in traces:
            detector = PhaseDetector()
            for event in trace:
                phase = detector.update(event)
                baseline.observe(event, phase)
        return baseline

    def observe(self, event, phase: str) -> None:
        package = event.package or "unknown"
        self.package_phase_caps.setdefault((package, phase), set()).add(event.capability)
        self.phase_histograms.setdefault(phase, Counter())[event.capability] += 1

    def has_capability(self, package: str | None, phase: str, capability: str) -> bool:
        return capability in self.package_phase_caps.get((package or "unknown", phase), set())

    def phase_distribution(self, phase: str) -> dict[str, float]:
        hist = self.phase_histograms.get(phase, Counter())
        total = sum(hist.values())
        if total == 0:
            return {}
        return {capability: count / total for capability, count in hist.items()}


@dataclass
class CapabilityTracker:
    """Tracks current run state without polluting the baseline."""

    phase_package_caps: dict[PackagePhaseKey, set[str]] = field(default_factory=dict)
    phase_histograms: dict[str, Counter[str]] = field(default_factory=dict)
    events: list[tuple[str, object]] = field(default_factory=list)

    def would_be_new(self, event, phase: str, baseline: CapabilityBaseline) -> bool:
        if baseline.has_capability(event.package, phase, event.capability):
            return False
        key = (event.package or "unknown", phase)
        return event.capability not in self.phase_package_caps.get(key, set())

    def observe(self, event, phase: str) -> None:
        package = event.package or "unknown"
        self.events.append((phase, event))
        self.phase_package_caps.setdefault((package, phase), set()).add(event.capability)
        self.phase_histograms.setdefault(phase, Counter())[event.capability] += 1

    def phase_distribution(self, phase: str) -> dict[str, float]:
        hist = self.phase_histograms.get(phase, Counter())
        total = sum(hist.values())
        if total == 0:
            return {}
        return {capability: count / total for capability, count in hist.items()}

