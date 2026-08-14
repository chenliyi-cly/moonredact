# Security Policy

## Reporting

Report suspected vulnerabilities privately to the repository owner through the
GitHub Security advisory interface after publication. Do not include real
credentials, payment data, personal information, access tokens, or production
logs in a public issue.

## Data handling

- Treat input and `Finding::matched_text` as sensitive.
- Prefer `redact`, `audit`, and the CLI's normal reports, which do not echo
  matched values.
- Do not place secrets in command history; the CLI's inline arguments are for
  demonstrations and controlled automation. Integrators should call the library
  with in-memory content from their own secure input channel.
- Store sanitized output according to the source system's retention policy.
- Run `verify_sanitized` as defense in depth, not as proof of complete removal.

## Limitations

Pattern detection is fallible. The current token derivation is deterministic
and non-reversible in this library but is not a password hash, MAC, encryption
scheme, or anonymity guarantee. Masked output can preserve length and
punctuation. Allowlisting bypasses transformation intentionally and must be
reviewed. See `docs/DETECTORS.md` for supported syntax.

Supported security fixes are released from the default branch and recorded in
`CHANGELOG.md`.
