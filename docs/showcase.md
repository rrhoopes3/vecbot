# Showcase Script

Use this when presenting VecBot as a research prototype.

## Setup

```bash
python -m pip install -e .
```

## Clean Run

```bash
vecbot demo --scenario clean
```

Expected point:

```text
No interesting phase capability drift detected.
```

## Runtime Supply-Chain Behavior

```bash
vecbot demo --scenario malicious-runtime
```

Expected point:

```text
package: markdown-theme-helper
capability: proc.spawn
phase: STEADY_RUN
evidence: capability absent from baseline for package in phase
Residue detected
```

## Import-Time Credential And Network Behavior

```bash
vecbot demo --scenario malicious-import
```

Expected point:

```text
package: malicious-theme-helper
capability: secret.file_read
phase: INIT_IMPORT
```

## One-Sentence Pitch

VecBot asks whether a package gained a sensitive capability in the wrong
process phase, then reports the evidence without pretending to know intent.

## Learn/Analyze Loop

```bash
vecbot simulate clean > clean.jsonl
vecbot simulate malicious-runtime > suspicious.jsonl
vecbot learn clean.jsonl --out baselines/demo.json
vecbot analyze suspicious.jsonl --baseline baselines/demo.json --json
```

Expected point:

```text
The same detector works with user-provided JSONL traces and a persisted
baseline file, not only built-in scenarios.
```
