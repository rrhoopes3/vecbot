"""VecBot command line interface."""

from __future__ import annotations

import argparse

from vecbot.analyzer import analyze
from vecbot.capabilities import CapabilityBaseline
from vecbot.events import Event
from vecbot.render import format_finding, format_residue, snake_view
from vecbot.scenarios import scenario_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vecbot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run synthetic clean and malicious scenarios")
    demo.add_argument("--scenario", action="append", help="scenario to analyze; may be repeated")

    simulate = subparsers.add_parser("simulate", help="emit a synthetic scenario as JSONL")
    simulate.add_argument("scenario")

    analyze_parser = subparsers.add_parser("analyze", help="analyze a JSONL trace against the clean baseline")
    analyze_parser.add_argument("trace")

    args = parser.parse_args(argv)

    if args.command == "simulate":
        for event in scenario_events(args.scenario):
            print(event.to_json())
        return 0

    if args.command == "analyze":
        with open(args.trace, "r", encoding="utf-8") as handle:
            events = [Event.from_json(line) for line in handle if line.strip()]
        baseline = CapabilityBaseline.learn([scenario_events("clean")])
        _print_result(args.trace, events, baseline)
        return 0

    if args.command == "demo":
        baseline = CapabilityBaseline.learn([scenario_events("clean")])
        scenarios = args.scenario or ["clean", "malicious-import", "malicious-runtime", "persistence-residue"]
        for scenario in scenarios:
            _print_result(scenario, scenario_events(scenario), baseline)
        return 0

    return 2


def _print_result(name: str, events: list, baseline: CapabilityBaseline) -> None:
    result = analyze(events, baseline)
    print("=" * 72)
    print(f"VecBot scenario: {name}")
    print("=" * 72)

    if not result.findings and not result.residue:
        print("No interesting phase capability drift detected.")

    for finding, event in result.findings:
        print(format_finding(finding, event))
        print(snake_view(finding.phase, [finding.capability], finding.drift))
        print()

    if result.residue:
        print(format_residue(result.residue))
        print()

    print(f"final_phase: {result.final_phase}")
    print(f"events: {len(result.events)}")
    print(f"findings: {len(result.findings)}")
    print()


if __name__ == "__main__":
    raise SystemExit(main())

