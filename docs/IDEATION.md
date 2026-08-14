# Direction and Non-Duplication Record

Date: 2026-08-14

## Candidate comparison

| Candidate | Domain and core loop | Registry comparison | Decision |
| --- | --- | --- | --- |
| MoonRedact | Sensitive text -> classified spans -> policy redaction -> audit trail | No registered project uses sensitive spans, overlap resolution, redaction actions, or disclosure counts as its core loop | Selected: practical offline workflow, reusable library surface, and deterministic acceptance |
| MoonTable | Delimited records -> inferred schema -> constraint validation -> cleaning advice | Distinct from every registry entry, but a general table utility has weaker ecosystem identity | Not selected |
| MoonCache | HTTP cache directives and metadata -> freshness and revalidation decisions | Does not parse OpenAPI, but HTTP interaction metadata is adjacent to MoonContract | Not selected |

## Selected fingerprint

- Problem domain: deterministic sensitive-text discovery, privacy redaction,
  and disclosure auditing.
- Primary users: application authors, support engineers, security teams,
  privacy reviewers, and CI maintainers.
- Primary workflow: configure detectors and policy, scan text, classify spans,
  resolve overlaps, apply redaction decisions, and emit sanitized output plus
  an audit report.
- Core data: source text, character spans, detector IDs, sensitivity classes,
  confidence, allowlists, policy rules, replacement actions, findings, and
  audit counters.
- Central algorithms: bounded lexical scanning, token validation, Luhn
  checking, dictionary matching, interval conflict resolution, policy
  precedence, and deterministic irreversible token derivation.
- Outputs: sanitized text, ordered findings, applied/suppressed decisions,
  per-class summaries, diagnostics, reports, and process status.
- Acceptance demonstration: mixed detector input, allowlisting, overlapping
  candidates, stable replacement modes, report counts, invalid configuration,
  bounded-input rejection, multi-target tests, and real CLI examples.
- Explicit non-goals: encryption or recovery, legal compliance claims,
  filesystem crawling, network transport, ML inference, log storage, and
  mooncakes.io publication.

## Support boundary

Supported in v0.1.0: ASCII-oriented email, IPv4, payment-card, credential, and
dictionary detectors; exact allowlists; deterministic overlap resolution;
class policies; mask, remove, token, and keep actions; library APIs; CLI; and
text plus JSON-like reports.

Partially supported: Unicode text is preserved, but built-in lexical detectors
recognize documented ASCII token forms only.

Unsupported: encrypted reversible vaults, context-aware ML classification,
IPv6, internationalized email domains, file traversal, remote log sources,
and claims of complete sensitive-data discovery.

## Licensing and dependencies

MoonRedact uses the OSI-approved Apache License 2.0. The core has no third-party
runtime dependency. Detection format references and AI assistance are disclosed
in repository documentation.
