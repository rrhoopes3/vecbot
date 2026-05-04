"""Core analysis loop."""

from __future__ import annotations

from dataclasses import dataclass, field

from vecbot.capabilities import CapabilityBaseline, CapabilityTracker
from vecbot.drift import Finding, js_divergence, score_event
from vecbot.phases import PhaseDetector
from vecbot.residue import check_residue


@dataclass
class AnalysisResult:
    findings: list[tuple[Finding, object]] = field(default_factory=list)
    residue: dict[str, list[str]] = field(default_factory=dict)
    events: list[tuple[str, object]] = field(default_factory=list)
    final_phase: str = "START"


def analyze(events: list, baseline: CapabilityBaseline) -> AnalysisResult:
    detector = PhaseDetector()
    tracker = CapabilityTracker()
    result = AnalysisResult()

    for event in events:
        phase = detector.update(event)
        capability_is_new = tracker.would_be_new(event, phase, baseline)

        tracker.observe(event, phase)

        current_dist = tracker.phase_distribution(phase)
        baseline_dist = baseline.phase_distribution(phase)
        drift = js_divergence(current_dist, baseline_dist)

        finding = score_event(event, phase, capability_is_new, drift)
        if finding and finding.is_interesting:
            result.findings.append((finding, event))

    result.events = tracker.events
    result.residue = check_residue(tracker.events)
    result.final_phase = detector.on_exit()
    return result

