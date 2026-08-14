# MoonRedact

MoonRedact is an original MoonBit library and command-line tool for finding
sensitive values in free-form text, applying explicit redaction policies, and
producing a deterministic audit trail. The implementation is in progress.

## Planned v0.1.0 scope

- Detect email addresses, IPv4 addresses, Luhn-valid payment-card candidates,
  credential assignments, and configured dictionary terms.
- Resolve overlapping findings deterministically and honor exact allowlists.
- Apply keep, mask, remove, and irreversible token actions by sensitivity class.
- Emit sanitized text, stable diagnostics, and text or JSON-like audit reports.

MoonRedact will not decrypt or recover redacted values, transmit logs, discover
files over a network, or claim that pattern matching proves legal compliance.

Licensed under Apache-2.0.
