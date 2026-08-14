# Profile Format

Profiles are UTF-8, line-oriented `key=value` documents. Blank lines and lines
whose first non-space character is `#` are ignored. Keys are case-insensitive;
values retain their text unless a field documents normalization. The complete
profile is limited to 262,144 characters.

## Keys

- `detectors=email,ipv4,payment-card,credential` selects built-in detectors;
  `detectors=none` disables all built-ins while retaining dictionary detection.
  Assign it at most once; omission enables all built-ins.
- `max-input=N` sets the scan bound from 1 to 10,000,000 characters.
- `allow=VALUE` adds an exact, case-sensitive allowlist value. It may repeat.
- `credential-key=NAME` replaces the default key set when one or more entries
  are present. Names allow ASCII letters, digits, `_`, and `-`.
- `dictionary=NAME|VALUE|MODE|PRIORITY` adds a literal custom detector. Modes
  are `exact`, `fold`, `word`, and `fold-word`; priority is 0-1000.
- `default=ACTION` sets the fallback redaction action.
- `salt=TEXT` sets the 1-128 character token correlation salt.
- `rule=SELECTOR|ACTION|PRIORITY` adds a policy rule.

## Selectors

Selectors are `*`, `email`, `ipv4`, `payment-card`, `credential`, `custom:*`,
or `custom:NAME`. The highest matching priority wins; on equal priorities the
first rule wins. `policy-lint` reports same-priority conflicts and rules that
can never be selected.

## Actions

- `keep` preserves the finding and is reported as an exposure risk.
- `mask:N` replaces ASCII letters/digits with `*` except the last `N`
  alphanumeric characters; punctuation is preserved.
- `remove` replaces the matched span with an empty string.
- `token:PREFIX` emits `PREFIX` plus an eight-character deterministic token.

Token output is not encryption or a password hash. Equal inputs under one salt
are correlatable. Use different deployment-specific, non-secret salts when
correlation domains must remain separate.

## Canonicalization

`profile-canonical` emits a stable normalized representation including detector
selection, bounds, allowlists, dictionary terms, credential keys, default
action, salt, and ordered policy rules. Parsing canonical output preserves the
effective profile.
