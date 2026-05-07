"""VecBot command line interface."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

from vecbot.analyzer import analyze
from vecbot.capabilities import CapabilityBaseline
from vecbot.events import Event
from vecbot.html_report import render_html_report
from vecbot.render import format_finding, format_residue, snake_view
from vecbot.scenarios import scenario_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vecbot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run synthetic clean and malicious scenarios")
    demo.add_argument("--scenario", action="append", help="scenario to analyze; may be repeated")

    simulate = subparsers.add_parser("simulate", help="emit a synthetic scenario as JSONL")
    simulate.add_argument("scenario")

    learn = subparsers.add_parser("learn", help="learn a persistent baseline from JSONL traces")
    learn.add_argument("traces", nargs="+", help="trace files or glob patterns")
    learn.add_argument("--out", required=True, help="baseline JSON file to write")

    analyze_parser = subparsers.add_parser("analyze", help="analyze a JSONL trace")
    analyze_parser.add_argument("trace")
    analyze_parser.add_argument(
        "--baseline",
        help="baseline JSON file; defaults to the built-in clean synthetic baseline",
    )
    analyze_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    demo.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    report = subparsers.add_parser("report", help="write a self-contained HTML report")
    report.add_argument("trace", nargs="?", help="JSONL trace to analyze")
    report.add_argument("--scenario", help="built-in scenario to render when no trace is provided")
    report.add_argument(
        "--baseline",
        help="baseline JSON file; defaults to the built-in clean synthetic baseline",
    )
    report.add_argument("--out", required=True, help="HTML file to write")

    args = parser.parse_args(argv)

    if args.command == "simulate":
        for event in scenario_events(args.scenario):
            print(event.to_json())
        return 0

    if args.command == "learn":
        trace_paths = _expand_paths(args.traces)
        traces = [_read_trace(path) for path in trace_paths]
        baseline = CapabilityBaseline.learn(traces, sources=[str(path) for path in trace_paths])
        baseline.save(args.out)
        print(f"wrote baseline: {args.out}")
        print(f"sources: {len(trace_paths)}")
        print(f"package_phase_entries: {len(baseline.package_phase_caps)}")
        return 0

    if args.command == "analyze":
        events = _read_trace(Path(args.trace))
        baseline = _load_baseline(args.baseline)
        payload = _print_result(args.trace, events, baseline, json_output=args.json)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "demo":
        baseline = CapabilityBaseline.learn([scenario_events("clean")])
        scenarios = args.scenario or ["clean", "malicious-import", "malicious-runtime", "persistence-residue"]
        results = []
        for scenario in scenarios:
            results.append(_print_result(scenario, scenario_events(scenario), baseline, json_output=args.json))
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    if args.command == "report":
        name, events = _report_input(args.trace, args.scenario)
        baseline = _load_baseline(args.baseline)
        result = analyze(events, baseline)
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_html_report(name, result), encoding="utf-8")
        print(f"wrote report: {output}")
        print(f"findings: {len(result.findings)}")
        print(f"residue_types: {len(result.residue)}")
        return 0

    return 2


def _print_result(
    name: str,
    events: list,
    baseline: CapabilityBaseline,
    *,
    json_output: bool = False,
) -> dict:
    result = analyze(events, baseline)
    payload = {"name": name, **result.to_dict()}
    if json_output:
        return payload

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
    return payload


def _load_baseline(path: str | None) -> CapabilityBaseline:
    if path:
        return CapabilityBaseline.load(path)
    return CapabilityBaseline.learn([scenario_events("clean")], sources=["builtin:clean"])


def _read_trace(path: Path) -> list[Event]:
    text = _read_text(path)
    return [Event.from_json(line) for line in text.splitlines() if line.strip()]


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def _expand_paths(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matches = [Path(match) for match in sorted(glob.glob(pattern))]
        if matches:
            paths.extend(matches)
        else:
            paths.append(Path(pattern))

    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise SystemExit(f"trace file not found: {', '.join(missing)}")
    return paths


def _report_input(trace: str | None, scenario: str | None) -> tuple[str, list[Event]]:
    if trace and scenario:
        raise SystemExit("choose either a trace path or --scenario, not both")
    if trace:
        path = Path(trace)
        return str(path), _read_trace(path)
    scenario_name = scenario or "malicious-runtime"
    return scenario_name, scenario_events(scenario_name)


if __name__ == "__main__":
    raise SystemExit(main())
