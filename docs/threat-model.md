# Threat Model

VecBot starts with a narrow threat model: malicious or compromised third-party
code running inside an otherwise legitimate process.

## Primary Adversary

The first adversary is a package, plugin, build script, or transitive dependency
that gains execution during one of these moments:

- package install
- build step
- application startup
- module import
- plugin load
- request handling
- shutdown hook

This adversary may not need memory corruption. It may already have code
execution because the user or application loaded it.

## What We Watch

VecBot watches capability drift:

- new network behavior
- child process creation
- credential or secret reads
- writes to startup/persistence locations
- dynamic code loading
- unexpected IPC
- log deletion or tampering
- leftover processes, sockets, files, or hooks

## What Makes Behavior Suspicious

Behavior becomes more suspicious when:

- it appears in a phase where it has no baseline
- it is attributed to a package that should not need that capability
- it appears after a quiet/stable period
- it combines multiple sensitive capabilities
- it leaves residue after shutdown

Examples:

```text
Import-time net.outbound from a color formatting library
Runtime proc.spawn from a Markdown parser
Shutdown persistence.startup_hook from a test helper
```

## Non-Goals For V1

VecBot v1 does not try to:

- prove intent
- block execution
- replace sandboxing
- detect all malware
- model every syscall
- build a complete attack graph

It should produce a precise explanation that helps a human or later policy
engine decide what to do.

