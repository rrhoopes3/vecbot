"""Conservative process phase detector."""

from __future__ import annotations

from collections import deque

PHASES = ("START", "INIT_IMPORT", "STEADY_RUN", "SHUTDOWN", "EXITED")


class PhaseDetector:
    """Small state machine with explicit hints and time-based fallback."""

    def __init__(self, init_grace_seconds: float = 1.0, steady_after_seconds: float = 2.0):
        self.current_phase = "START"
        self.init_grace_seconds = init_grace_seconds
        self.steady_after_seconds = steady_after_seconds
        self.phase_start_ts = 0.0
        self.history: list[tuple[float, str, str]] = []
        self.recent_capabilities: deque[str] = deque(maxlen=32)

    def update(self, event) -> str:
        previous = self.current_phase
        self.recent_capabilities.append(event.capability)

        if event.phase_hint:
            self._transition(event.phase_hint, event.ts)
            return self.current_phase

        if self.current_phase == "START":
            if event.capability == "import.dynamic" or event.ts >= self.init_grace_seconds:
                self._transition("INIT_IMPORT", event.ts)

        if self.current_phase == "INIT_IMPORT":
            if event.ts >= self.steady_after_seconds and event.capability != "import.dynamic":
                self._transition("STEADY_RUN", event.ts)

        if event.action in {"close", "exit"} or event.capability == "logs.tamper":
            self._transition("SHUTDOWN", event.ts)

        if previous != self.current_phase:
            self.history.append((event.ts, previous, self.current_phase))
        return self.current_phase

    def on_exit(self) -> str:
        self.current_phase = "EXITED"
        return self.current_phase

    def _transition(self, phase: str, ts: float) -> None:
        if phase not in PHASES:
            raise ValueError(f"unknown phase: {phase}")
        if phase == self.current_phase:
            return
        self.current_phase = phase
        self.phase_start_ts = ts

