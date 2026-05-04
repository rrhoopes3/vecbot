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
```

## What Exists

- structured `Event` JSONL model
- synthetic clean and malicious traces
- conservative phase detector
- package/phase capability baseline
- explainable finding scorer
- residue checker
- text-mode snake visualization
- tests for the core behavior

## What This Is Not

VecBot does not block execution, prove intent, replace sandboxing, or claim
production-grade malware detection. It emits crisp evidence for humans and
future policy engines.

See [docs/repo-start.md](docs/repo-start.md) for the design notes.
