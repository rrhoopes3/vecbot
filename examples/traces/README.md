# Trace Examples

The current prototype generates traces from `vecbot.scenarios`.

Write one out with:

```bash
vecbot simulate malicious-runtime > examples/traces/malicious-runtime.jsonl
```

Then analyze it with:

```bash
vecbot analyze examples/traces/malicious-runtime.jsonl
```

Or learn a baseline first:

```bash
vecbot simulate clean > examples/traces/clean.jsonl
vecbot learn examples/traces/clean.jsonl --out baselines/demo.json
vecbot analyze examples/traces/malicious-runtime.jsonl --baseline baselines/demo.json --json
```

Create a shareable report:

```bash
vecbot report examples/traces/malicious-runtime.jsonl --baseline baselines/demo.json --out reports/malicious-runtime.html
```
