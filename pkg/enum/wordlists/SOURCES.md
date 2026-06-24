# Wordlist Sources

This directory bundles third-party data used for account-enumeration name and
username generation. Attribution and provenance for each list are below.

## likely-names.txt.gz

A frequency-ranked list of statistically likely `first.last` username pairs
(~248k lines, gzipped, one pair per line, ordered most-likely first, e.g.
`john.smith`, `david.smith`, `michael.smith`, ...).

- **Derived from:** [insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
- **Bundling:** Included in this repository per the maintainer's decision.

All eight `brutus enum generate` username formats (`first.last`, `flast`,
`firstl`, `f.last`, `lastf`, `last.first`, `lastfirst`, `first`) are derived
from these ranked pairs. Because every format comes from the same ordered
source, generated output is bounded (<=248k before deduplication) and ranked by
likelihood.

## service-accounts.txt

A plaintext list of common service-account names, one per line (lines starting
with `#` are treated as comments). Used by `brutus enum` for service-account
enumeration candidates.
