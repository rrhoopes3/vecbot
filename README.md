# VecBot

VecBot is a small research prototype for **phase-attributed capability drift
detection**: it flags runtime behavior based on what capability appeared, which
package/module appears responsible, and which process phase it appeared in.

The useful question is not just "did this process call `exec`?"

It is:

> Did this package gain a new sensitive capability during a phase where it has
> never needed that capability before?

This sits between static supply-chain scanners and coarse runtime rules. The
first implementation uses synthetic JSONL traces so the algorithm can be judged
before any eBPF, ETW, auditd, or collector plumbing arrives.

## Why Look At This

Most runtime security rules flatten process behavior into isolated events:
`exec`, `connect`, `open`, `write`. VecBot keeps the event, but adds lifecycle
context. A package opening outbound sockets may be normal during steady-state
request handling; the same shape is much stranger during import. A Markdown
theme helper reading `~/.pypirc`, spawning `/bin/sh`, or leaving a child process
behind after shutdown is not just "a process did a thing"; it is a package
gaining a sensitive capability in the wrong phase, with residue.

That makes VecBot useful as a small bridge between static SCA and broad runtime
detection. It does not try to be an EDR. It tries to produce explainable
evidence that a security engineer can inspect, suppress, baseline, or feed into
a later collector-backed policy.

## Demo

Install the local package and run the built-in scenarios:

```bash
python -m pip install -e .
vecbot demo
```

During development, this also works without installing:

```bash
PYTHONPATH=src python -m vecbot.cli demo
```

Expected interesting finding:

```text
Suspicious phase capability drift
pid: 4242
phase: STEADY_RUN
package: markdown-theme-helper
capability: proc.spawn
target: /bin/sh
evidence: capability absent from baseline for package in phase
```

## Install For Development

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -e .[dev]
pytest
```

No runtime dependencies are required.

## CLI

```bash
vecbot demo
vecbot demo --scenario malicious-runtime
vecbot simulate malicious-runtime > trace.jsonl
vecbot analyze trace.jsonl
vecbot learn clean.jsonl --out baselines/demo.json
vecbot analyze trace.jsonl --baseline baselines/demo.json --json
vecbot report --scenario malicious-runtime --out reports/malicious-runtime.html
```

## What Exists

- structured `Event` JSONL model
- synthetic clean and malicious traces
- conservative phase detector
- package/phase capability baseline
- explainable finding scorer
- residue checker
- text-mode snake visualization
- JSON output for pipelines
- self-contained HTML timeline reports
- tests for the core behavior

## What This Is Not

VecBot does not block execution, prove intent, replace sandboxing, or claim
production-grade malware detection. It emits crisp evidence for humans and
future policy engines.

See [docs/repo-start.md](docs/repo-start.md) for the design notes.
