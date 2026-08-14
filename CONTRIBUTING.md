# Contributing

Contributions should preserve deterministic behavior across MoonBit targets,
stable diagnostic codes, bounded inputs, and the rule that reports never expose
matched sensitive values.

Before opening a change:

```bash
moon update
moon fmt --check
moon check --target wasm-gc --deny-warn
moon check --target wasm --deny-warn
moon check --target js --deny-warn
moon check --target native --deny-warn
moon test --target wasm-gc
moon test --target wasm
moon test --target js
```

Add positive, negative, boundary, overlap, and privacy assertions for detector
changes. Document false-positive tradeoffs and unsupported syntax. New profile
features require parser, canonicalization, lint, and CLI tests. Avoid adding
runtime dependencies unless the functionality cannot reasonably remain in the
MoonBit core.
