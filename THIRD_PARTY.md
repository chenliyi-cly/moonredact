# Third-Party and Reference Notice

MoonRedact contains original implementation code and no copied third-party
runtime source or bundled visual/media assets.

The payment-card candidate detector implements the public Luhn checksum
algorithm described by Hans Peter Luhn and widely documented in standards and
technical references. Email and IPv4 token validation is an intentionally
limited interoperability profile informed by common Internet text formats; it
does not copy a standards implementation and does not claim complete RFC
conformance.

Build and CLI support use the MoonBit standard/tooling packages, including
`moonbitlang/x` for the executable system adapter, under their published
licenses. GitHub Actions uses `actions/checkout@v5` under its upstream license.

No source project was ported. Apache License 2.0 covers MoonRedact; see
`LICENSE`.
