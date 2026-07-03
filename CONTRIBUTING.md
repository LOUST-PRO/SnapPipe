# Contributing to SnapPipe

Thank you for your interest in SnapPipe. This document captures the
contribution conventions used by this repository.

## Development model

SnapPipe should evolve through small, reviewable branches instead of giant
long-lived diffs.

Preferred flow:

1. branch from `main`
2. keep one architectural slice per branch
3. open a PR, even when the branch lives in the same repository
4. merge only after tests pass and the operator story remains clear

Good slice examples:

- `feat/ticket-rotation`
- `feat/quinn-session-bootstrap`
- `feat/relay-authz-cache`
- `feat/path-rebind-diagnostics`

## Design principles

- keep self-hosting first-class
- do not require a paid relay control plane to get the core value
- prefer identity-based addressing over location-based assumptions
- preserve a compatibility fallback while adding faster optional overlays

## Pull request slicing — single concern, atomic, reviewable

The rationale is the same as the development model above, made explicit:

- One PR = one concern. If your PR is doing three things, file three PRs.
- A PR should be **atomic**: it should be revertable without breaking the
  rest of the codebase. Code, docs, tests for that code, and the relevant
  doc updates land together. Nothing else.
- Target size: small enough that a reviewer can read it in one sitting.
  Above ~400 lines of diff, you almost certainly want to slice further.
- No unrelated refactors. If `cargo clippy` complains about a file you
  didn't touch, open an issue, do not amend it into your PR.
- Don't mix `fix/*` branches with `hardening/*` work in the same PR.

### Branch naming

```text
feat/<short-kebab>
fix/<short-kebab>
docs/<short-kebab>
chore/<short-kebab>
hardening/<short-kebab>
experiment/<short-kebab>
```

Never push directly to `main`. Use a branch, open a PR, let CI + a human
reviewer land it.

### Commit messages

Use imperative subject lines, ~72 chars, no trailing period. The body
explains *why*, not *what* (the diff shows the what).

```text
feat(cli): expose NonceStore + RateLimiter metrics as JSON
```

For multi-commit PRs the subject can be the slice name and each commit
can be its own self-contained change.

## Development setup

```bash
git clone https://github.com/LOUST-PRO/SnapPipe
cd SnapPipe
cargo test --locked          # must stay green
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The `--locked` flag is non-negotiable: `Cargo.lock` is the source of
truth, and floating versions are flagged in CI.

## Validation requirements before opening a PR

```bash
cargo fmt --all                    # format
cargo fmt --all -- --check         # verify clean
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked                # all tests green
cargo run --example handshake      # smoke the example
cargo run -- metrics               # smoke the new subcommand
```

CI runs the same suite (`.github/workflows/ci.yml`). CI must be green
before merge. CodeRabbit will also leave inline review notes; address or
explicitly defer them in the PR thread.

## Issues

Use the GitHub issue templates:

- **Bug**: `.github/ISSUE_TEMPLATE/bug_report.md`
- **Feature**: `.github/ISSUE_TEMPLATE/feature_request.md`
- **Security**: **DO NOT** file security bugs as public issues. Email
  `opensource@loust.pro` with subject `SnapPipe security`. See
  [`SECURITY.md`](SECURITY.md) for the disclosure process.

## Scope of "good first PR"

Good first contributions tend to be:

- Documentation fixes (typos, broken links, missing examples).
- Test coverage on existing public functions (we have room for more).
- Small CLI ergonomics improvements (`--quiet` flags, output formatting).

Less suitable for first contributions: anything in `src/quic/`,
`src/session.rs`, or changes to the ALPN / ticket-version constants. Those
areas are security-load-bearing and the review bar is correspondingly
higher.

## Code style

- Rust 2024 edition; `cargo fmt` defaults; clippy with `-D warnings`.
- No `unsafe` blocks in this crate. If you need one, that's a conversation
  first, code second.
- Public types derive `Debug`. Snapshot types additionally derive
  `Clone + Copy + Default + PartialEq + Eq`. JSON-serialisable snapshot
  types additionally derive `Serialize`.
- Comments explain *why*, not what. If the answer is in the docs, link
  the doc instead of duplicating the rationale.
- Tests live next to the code they cover (`#[cfg(test)] mod tests`).
  Integration tests live in `tests/`.

## Releases

The maintainer cuts a release with `cargo publish` after the hardening
batch accumulates. The PR that bumps `Cargo.toml` to the next version is
the last PR in a batch — it carries the `CHANGELOG.md` entry, the
`RELEASES.md` narrative, and the git tag. Don't bump `Cargo.toml`
mid-batch.

## Licensing

SnapPipe is licensed under Apache-2.0. By submitting a contribution, you
agree it is licensed under the same terms. See [`LICENSE-APACHE`](LICENSE-APACHE)
for the full text.

## Community

- Public discussions happen on GitHub issues and PRs.
- Security-sensitive conversations go to `opensource@loust.pro`.
- The disclosure process is documented in [`SECURITY.md`](SECURITY.md).