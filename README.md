# MoonRedact

[![CI](https://github.com/chenliyi-cly/moonredact/actions/workflows/ci.yml/badge.svg)](https://github.com/chenliyi-cly/moonredact/actions/workflows/ci.yml)

MoonRedact is an original MoonBit library and command-line tool for detecting
sensitive values in free-form text, applying explicit redaction policies, and
producing deterministic audit evidence. It is designed for logs, configuration
snippets, incident notes, support exports, test fixtures, and CI checks.

The scanner reports character spans rather than echoing matched values. The
redactor supports masking, removal, deterministic irreversible tokens, and
explicit keep rules. It also provides overlap resolution, allowlists, custom
dictionaries, residual rescans, policy linting, labeled-corpus evaluation, and
policy comparison.

## Status and boundaries

Version `0.1.0` supports:

- ASCII email addresses with validated local and domain structure;
- canonical IPv4 addresses with validated octets;
- 13-19 digit payment-card candidates that pass the Luhn checksum;
- quoted or bare values assigned to configurable credential keys;
- literal custom dictionary terms with case and word-boundary modes;
- exact allowlists and deterministic priority-based overlap resolution;
- `keep`, `mask:N`, `remove`, and `token:PREFIX` policy actions;
- stable text/JSON-like reports that omit matched sensitive values;
- line/column mapping, named batches, residual verification, policy linting,
  policy comparison, and exact span/class corpus evaluation.

Unicode source text is preserved, but built-in lexical detectors recognize the
documented ASCII token forms. MoonRedact does not support IPv6, internationalized
email domains, reversible encryption, ML classification, filesystem crawling,
remote log ingestion, or complete/legal compliance claims. Detection is a
defense-in-depth aid and can produce false positives or false negatives.

## Quick start

Requires the [MoonBit toolchain](https://www.moonbitlang.com/download/).

```bash
moon update
moon test --target wasm-gc
moon run cmd/main --target js -- demo
```

Scan text without exposing matched values:

```bash
moon run cmd/main --target js -- scan \
  --text 'mail=a@example.com ip=10.0.0.1'
```

Redact with the balanced built-in profile:

```bash
moon run cmd/main --target js -- redact \
  --text 'mail=a@example.com password=hunter2 card=4111111111111111'
```

Audit or verify that the sanitized output no longer triggers enabled detectors:

```bash
moon run cmd/main --target js -- audit --text 'mail=a@example.com' --json
moon run cmd/main --target js -- verify --text 'mail=a@example.com ip=10.0.0.1'
```

The CLI accepts newlines encoded as `\n`, tabs as `\t`, and backslashes as
`\\`. Exit code `0` means success or a clean verification, `1` means residual
findings or an unsafe lint result, and `2` means invalid input/configuration.

## Profiles

Profiles are bounded, line-oriented `key=value` text:

```text
max-input=200000
allow=127.0.0.1
dictionary=tenant|ACME INTERNAL|fold|700
default=mask:0
salt=support-export-v1
rule=credential|remove|900
rule=payment-card|mask:4|800
rule=ipv4|token:net_|700
```

Validate and lint before deployment:

```bash
moon run cmd/main --target js -- profile-check \
  --profile 'default=remove\nrule=email|mask:0|500'
moon run cmd/main --target js -- policy-lint \
  --profile 'default=remove\nrule=email|mask:0|500'
```

See [docs/PROFILE_FORMAT.md](docs/PROFILE_FORMAT.md) for the complete grammar
and [examples/support.profile](examples/support.profile) for a runnable profile.

## Library use

The package exposes immutable configuration and result values:

```moonbit
let config = @moonredact.ScanConfig::default()
  .with_allowlist(["127.0.0.1"])
  .unwrap()
let policy = @moonredact.RedactionPolicy::balanced()
let result = @moonredact.redact(
  "mail=a@example.com source=10.0.0.1",
  config=config,
  policy=policy,
).unwrap()
println(result.sanitized_text())
println(@moonredact.audit(result).render_text())
```

Additional public workflows include:

- `scan` and `locate_findings` for detection and one-based line/column mapping;
- `redact_batch` for bounded named in-memory inputs;
- `verify_sanitized` for a second-pass residual check;
- `lint_policy` and `compare_policies` for deployment review;
- `evaluate_corpus` for exact span-and-class precision/recall evidence.

Run `moon info` to regenerate `pkg.generated.mbti`, which lists the complete
public API.

## Detector and policy behavior

Candidates are collected independently. Allowlisted exact values are
suppressed. Remaining overlaps are resolved by higher detector/dictionary
priority, then longer span, then earlier start. Accepted spans are restored to
source order before replacement, so output is deterministic.

Built-in priorities are credential `100`, payment card `90`, email `80`, and
IPv4 `70`; dictionary entries default to `60` and allow an explicit `0-1000`
priority. Policy rules independently use `0-1000`: the highest matching rule
wins, and the first rule wins a tie. `policy-lint` reports ambiguous and
shadowed rules.

`token:PREFIX` is deterministic but not cryptographic encryption. Tokens are
not recoverable through MoonRedact, yet equal values under the same salt remain
correlatable. Use a deployment-specific, non-secret salt to separate correlation
domains; do not treat the token as a password hash.

See [docs/DETECTORS.md](docs/DETECTORS.md) for exact lexical boundaries and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for data flow and invariants.

## Verification

The local and CI engineering gate is:

```bash
moon fmt --check
moon check --target wasm-gc --deny-warn
moon check --target wasm --deny-warn
moon check --target js --deny-warn
moon check --target native --deny-warn
moon test --target wasm-gc
moon test --target wasm
moon test --target js
moon test --target native
moon run cmd/main --target js -- demo
```

GitHub Actions runs portable tests on wasm-gc, wasm, and JavaScript, exercises
real CLI flows, and separately builds/tests/runs native code on Ubuntu.

## Security and privacy

Audit, scan, lint, comparison, and evaluation reports intentionally exclude
matched source values. `Finding::matched_text` exists for applications that
must implement custom actions; callers are responsible for preventing it from
entering logs or metrics. Read [SECURITY.md](SECURITY.md) before processing
production data.

## License and provenance

MoonRedact is licensed under the Apache License 2.0. It has no third-party
runtime code dependency beyond MoonBit standard/tooling packages. Detection
references are documented in [THIRD_PARTY.md](THIRD_PARTY.md), and AI assistance
is disclosed in [AI_USAGE.md](AI_USAGE.md). This is an original project, not a
port.

Contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md), and release
history is in [CHANGELOG.md](CHANGELOG.md).
