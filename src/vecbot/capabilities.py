"""Capability baseline and observation tracking."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path

PackagePhaseKey = tuple[str, str]
BASELINE_SCHEMA_VERSION = 1


@dataclass
class CapabilityBaseline:
    """Baseline of capabilities observed for each package in each phase."""

    package_phase_caps: dict[PackagePhaseKey, set[str]] = field(default_factory=dict)
    phase_histograms: dict[str, Counter[str]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    @classmethod
    def learn(cls, traces: list[list], sources: list[str] | None = None) -> "CapabilityBaseline":
        from vecbot.phases import PhaseDetector

        baseline = cls()
        baseline.sources = list(sources or [])
        for trace in traces:
            detector = PhaseDetector()
            for event in trace:
                phase = detector.update(event)
                baseline.observe(event, phase)
        return baseline

    @classmethod
    def load(cls, path: str | Path) -> "CapabilityBaseline":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @classmethod
    def from_dict(cls, payload: dict) -> "CapabilityBaseline":
        if payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported baseline schema version: {payload.get('schema_version')!r}"
            )

        baseline = cls(
            sources=list(payload.get("sources", [])),
            created_at=payload.get("created_at") or "",
        )
        for row in payload.get("package_phase_capabilities", []):
            key = (row["package"], row["phase"])
            baseline.package_phase_caps[key] = set(row.get("capabilities", []))

        for phase, histogram in payload.get("phase_histograms", {}).items():
            baseline.phase_histograms[phase] = Counter(
                {capability: int(count) for capability, count in histogram.items()}
            )
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

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")

    def to_dict(self) -> dict:
        return {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "created_at": self.created_at,
            "sources": self.sources,
            "package_phase_capabilities": [
                {
                    "package": package,
                    "phase": phase,
                    "capabilities": sorted(capabilities),
                }
                for (package, phase), capabilities in sorted(self.package_phase_caps.items())
            ],
            "phase_histograms": {
                phase: dict(sorted(histogram.items()))
                for phase, histogram in sorted(self.phase_histograms.items())
            },
        }


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
