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

