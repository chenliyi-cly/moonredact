# Detector Reference

## Email

Recognizes ASCII local-part characters (`A-Z`, `a-z`, digits, `.`, `_`, `%`,
`+`, `-`) followed by one `@` and an ASCII domain. Domains require at least one
dot, non-empty labels, no edge hyphens, and a final label of at least two
characters. Consecutive local-part dots are rejected.

Internationalized domains, quoted local parts, comments, and full RFC 5322
syntax are unsupported.

## IPv4

Recognizes four decimal octets separated by dots. Each octet must be `0-255`;
multi-digit octets with a leading zero are rejected to avoid ambiguous textual
forms. IPv6 and CIDR ranges are unsupported.

## Payment card

Recognizes 13-19 digits, optionally separated by spaces or hyphens, only when
the digits pass the Luhn checksum. A checksum match does not prove that an
account exists. Other long numeric identifiers can pass Luhn and should be
handled with allowlists or context-specific dictionary policy.

## Credential assignment

Recognizes configurable key names followed by optional horizontal whitespace,
`=` or `:`, optional whitespace, then a quoted or bare non-empty value. Default
keys are `password`, `passwd`, `token`, `secret`, `api_key`, `apikey`, and
`authorization`. Bare values end at whitespace, comma, or semicolon.

This detector does not parse nested programming-language syntax or multiline
quoted strings.

## Dictionary

Dictionary entries are literal text. Modes are case-sensitive exact (`exact`),
ASCII case-folded (`fold`), case-sensitive whole word (`word`), and ASCII
case-folded whole word (`fold-word`). Word boundaries use ASCII letters, digits,
and underscore. Each entry supplies a custom sensitivity name and priority.

## Overlap and allowlist

Exact allowlist values suppress any candidate with identical matched text.
Remaining overlap winners are selected by descending priority, descending span
length, and ascending start. Built-in priorities are credential 100, payment
card 90, email 80, and IPv4 70. Accepted findings are returned in source order.
