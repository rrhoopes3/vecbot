# Attribution Strategy

Attribution is the load-bearing part of VecBot. A finding is only useful when
it can say which package, module, plugin, or inherited process context appears
responsible for a new capability.

This document starts with Python because the first prototype is Python-only.
Other runtimes should be treated as separate attribution adapters.

## Goal

Populate these event fields:

```python
actor: str | None
package: str | None
module: str | None
attribution_source: str
attribution_confidence: float
```

The detector should distinguish:

```text
known package caused this
known process lineage inherited this
runtime observed this but actor is unknown
```

Unknown attribution is acceptable. Silent fake certainty is not.

## Python Sources

Use several weak signals rather than pretending one hook can explain every
event:

```text
import hook          module load, package root, import timestamp
sys.setprofile      Python call stack and active frames
monkeypatch layer   high-level APIs such as subprocess, socket, open, requests
process lineage     subprocess parent actor/package at spawn time
collector event     syscall/resource behavior from the OS layer
```

The first code prototype can use synthetic traces, but the schema should already
represent these sources.

## Attribution Rules

Recommended first-pass rules:

1. If a monkeypatched high-level API observes the event, attribute to the first
   non-stdlib, non-VecBot frame in the stack.
2. If the event happens during module import, attribute to the module currently
   being imported.
3. If a child process emits an event, inherit the parent actor/package from the
   spawn event until stronger evidence appears.
4. If a native extension triggers behavior without a Python frame, attribute to
   the loaded extension package when possible and lower confidence.
5. If no responsible frame, import context, or lineage exists, emit the event
   with `package=None` and `attribution_confidence=0`.

## Confidence Bands

```text
1.00 direct high-level wrapper with Python frame
0.85 import-time event with active import context
0.70 subprocess inherited from parent spawn attribution
0.50 native extension package inferred from loaded module
0.25 process-level only
0.00 unknown
```

These numbers are labels, not scientific probabilities. They exist to keep
reports honest.

## Known Blind Spots

- native extensions can perform work outside visible Python frames
- async tasks can blur causality across callbacks
- threads can inherit context incorrectly if context propagation is naive
- subprocesses may exec unrelated programs after inheriting package attribution
- monkeypatches miss code paths that call lower-level APIs directly
- adversarial packages can try to hide stack frames or delay behavior

VecBot should report these as attribution limits, not hide them.

## Event Shape Addition

The JSONL event format should include:

```json
{
  "actor": "theme_helper",
  "package": "theme-helper",
  "module": "theme_helper.telemetry",
  "attribution_source": "python_stack",
  "attribution_confidence": 1.0
}
```

Findings should include attribution source and confidence whenever possible.

