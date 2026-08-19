# License

SnapPipe is dual-licensed under the Apache License, Version 2.0
with an additional fork-hardening addendum. This page is a summary;
the canonical text lives in the repository's `LICENSE`,
`LICENSE-FORK.md`, and `CONTRIBUTING.md` files.

## Apache-2.0 (the baseline)

SnapPipe is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
You may use, modify, and distribute the code under the terms of
that license. The full text is available in the [`LICENSE`](https://github.com/LOUST-PRO/SnapPipe/blob/main/LICENSE)
file at the repository root.

In summary, the Apache-2.0 license:

- Allows commercial use, modification, and distribution
- Requires preservation of copyright notices
- Requires explicit indication of changes
- Includes an explicit patent grant from contributors
- Provides an explicit disclaimer of warranty

You do NOT need to open-source your downstream application if
you consume SnapPipe as a library. The Apache-2.0 license applies
to the SnapPipe source code itself, not to the code that links
against it.

## LICENSE-FORK.md (the fork addendum)

When the maintainer publishes a fork that includes hardening
changes (TLS pinning, additional gating, security-relevant
config), the fork ships a [`LICENSE-FORK.md`](https://github.com/LOUST-PRO/SnapPipe/blob/main/LICENSE-FORK.md)
file describing the delta relative to upstream. The fork
license inherits Apache-2.0; the addendum documents:

- Which hardening layers were added vs upstream
- The audit trail for each hardening decision (commit hashes,
  reviews)
- Any deviations from upstream behaviour that downstream
  consumers should know about

The fork addendum is not a separate license. It's a transparency
document. Downstream consumers of the fork receive the same
Apache-2.0 grant; the addendum just makes the fork-vs-upstream
delta auditable.

## CONTRIBUTING.md

The [`CONTRIBUTING.md`](https://github.com/LOUST-PRO/SnapPipe/blob/main/CONTRIBUTING.md)
document covers:

- How to file an issue
- How to file a security issue (different channel from regular issues)
- The PR review process
- The maintainer rotation schedule
- The hardening-decision audit process (any change to
  `TrustStore`, `NonceStore`, or `RateLimiter` defaults must cite
  the threat-model rationale)

Security issues follow the [SECURITY.md](https://github.com/LOUST-PRO/SnapPipe/blob/main/SECURITY.md)
policy, which is a separate document and a separate channel.
Routine bugs, feature requests, and questions go through the
GitHub issue tracker.

## SPDX expression

The canonical SPDX expression for SnapPipe is:

```
Apache-2.0
```

If you consume a fork that adds the addendum, the SPDX expression
remains `Apache-2.0`; the fork addendum is descriptive, not a
licensing change.

## Third-party dependencies

SnapPipe depends on a number of MIT/Apache-2.0/BSD-licensed
crates. The full dependency tree is enumerated in the
[`THIRD_PARTY_LICENSES.md`](https://github.com/LOUST-PRO/SnapPipe/blob/main/THIRD_PARTY_LICENSES.md)
file, regenerated on each release. Notable dependencies:

| Crate | License | Purpose |
|---|---|---|
| `quinn` 0.11 | MIT | QUIC transport |
| `rustls` 0.23 | Apache-2.0 / ISC | TLS for QUIC |
| `ring` 0.17 | ISC / OpenSSL | Cryptographic primitives for rustls |
| `ed25519-dalek` 2.x | MIT / Apache-2.0 | Ed25519 signatures |
| `tokio` 1.x | MIT | Async runtime |
| `clap` 4.x | MIT / Apache-2.0 | CLI parsing |
| `tracing` 0.1 | MIT | Structured logging |
| `serde` 1.x | MIT / Apache-2.0 | Serialisation |
| `toml` 0.8 | MIT / Apache-2.0 | Config file parsing |

All are compatible with the Apache-2.0 license grant. No GPL or
LGPL dependencies; no copyleft propagation concerns.

## Contact

- General questions: GitHub issue tracker
- Security issues: SECURITY.md channel (private)
- Maintainer: see the `MAINTAINERS.md` file at the repository root