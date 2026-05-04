# Baseline Learning and False Positives

VecBot should assume normal software changes over time. A detector with no
learning or suppression path becomes background noise after a few deploys.

## Primary Signal

The first version should treat this as the main signal:

```text
package/module gained a new or rare capability in a phase where it has not
previously needed that capability
```

Jensen-Shannon divergence can support the report, but it should not be the main
reason a finding exists.

## Baseline Shape

A baseline should be keyed by:

```text
runtime
application identity
package name and version
phase
capability
optional deployment profile
```

Example:

```json
{
  "runtime": "python",
  "app": "demo-service",
  "package": "markdown-theme-helper",
  "version": "1.4.2",
  "phase": "STEADY_RUN",
  "capabilities": {
    "fs.read": {"seen": 48},
    "fs.write": {"seen": 3}
  }
}
```

## Learning Modes

Recommended modes:

```text
observe      record behavior, emit low-severity notes only
candidate    compare against baseline, mark proposed baseline additions
enforce      emit findings for novel capability/phase/package combinations
```

The first prototype can implement these as report modes without blocking.

## Suppression Model

Suppression should be explicit and reviewable:

```json
{
  "package": "requests",
  "version_range": ">=2.0,<3.0",
  "phase": "STEADY_RUN",
  "capability": "net.outbound",
  "reason": "HTTP client dependency",
  "expires": "2026-12-31"
}
```

Avoid global allowlists unless the capability is truly expected everywhere.

## Finding Severity

Start with explainable tiers:

```text
info       new behavior in observe mode
low        known sensitive capability from expected package class
medium     novel capability for package in this phase
high       novel sensitive capability plus weak/unknown attribution
critical   persistence, secret read, proc.spawn, or net.outbound combined with residue
```

The severity should be derived from facts in the report, not an opaque weighted
score.

## Noise Risks

Likely false-positive sources:

- dependency upgrades
- first run after cache eviction
- optional feature path activated by config
- workers forked after startup
- batch jobs with several legitimate runtime modes
- async runtimes that blur startup and steady-state phases

The detector should prefer "candidate baseline addition" over alarm when a
behavior repeats cleanly across several runs.

## Analyst Workflow

For every finding, the analyst should be able to choose:

```text
accept as new baseline
suppress this package/capability/phase
mark package suspicious
mark attribution unknown and request deeper collection
ignore once
```

Even in a CLI prototype, these choices should shape the data model.

