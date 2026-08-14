# Architecture

## Data flow

1. `ScanConfig` bounds the input and selects built-in detectors, exact
   allowlists, credential keys, and dictionary terms.
2. Independent detectors produce `Finding` candidates with half-open character
   spans, sensitivity class, confidence, detector ID, and priority.
3. `scan` suppresses exact allowlist matches, ranks candidates, resolves
   overlapping intervals, and restores accepted findings to source order.
4. `RedactionPolicy` chooses one action per accepted finding. `redact` copies
   untouched ranges and inserts deterministic replacements.
5. `audit`, `verify_sanitized`, location mapping, corpus evaluation, and policy
   analysis consume immutable results without external state.

## Invariants

- Spans are half-open `[start, end)` character offsets with `start < end`.
- Accepted findings are ordered and non-overlapping.
- Built-in detectors perform bounded linear scans; dictionary scanning is
  bounded by profile limits and explicit term-count/length limits.
- Replacement never changes the scan result; decisions refer to original spans.
- Reports contain classes, detector IDs, positions, actions, and counts, but not
  `Finding::matched_text`.
- Equal input, configuration, policy, and tool version produce equal output.
- Token actions are deterministic one-way identifiers, not encryption.

## Packages and modules

The root package contains the reusable library. Domain types live in
`model.mbt`; detector configuration and profile parsing in `config.mbt` and
`profile.mbt`; detectors in `detectors.mbt`; candidate arbitration in
`scanner.mbt`; policy and transformation in `policy.mbt` and `redactor.mbt`.

`report.mbt`, `location.mbt`, `batch.mbt`, `evaluation.mbt`, `comparison.mbt`,
and `lint.mbt` provide analysis surfaces. `command.mbt` is a target-portable
CLI command layer. `cmd/main` is the only environment/exit adapter.

## Complexity

Built-in lexical scans are `O(n)` per enabled detector family. Dictionary scan
is `O(n * terms * average-term-length)` and therefore capped at 1,000 terms of
at most 256 characters. Candidate ranking uses stable insertion sort and is
appropriate for bounded text documents; it favors predictable cross-target
behavior over platform-specific sorting. Corpus and batch sizes are bounded.

## Trust boundary

MoonRedact operates entirely in memory. It does not open files, send network
requests, store a recovery vault, or publish packages. The caller owns input
acquisition and output storage. The CLI accepts explicit text arguments so the
portable library behavior is identical on wasm-gc, wasm, JavaScript, and native
targets.
