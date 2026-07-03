---
name: Security disclosure
about: Confidential vulnerability report (DO NOT file public security bugs here)
title: "[security] "
labels: security
assignees: ''
---

> **STOP. Do not file public security bugs here.** This template is for
> your own notes — the actual disclosure goes to
> **opensource@loust.pro** with the subject `SnapPipe security`.
> See [`SECURITY.md`](../../blob/main/SECURITY.md) for the full process.

## Use this template only if

- You are drafting your disclosure email offline and want a checklist.
- You want to test the disclosure workflow against a non-issue first.

## Disclosure email checklist

- [ ] Subject line: `SnapPipe security`
- [ ] Repro steps (preferably a `cargo test` snippet or shell commands)
- [ ] Impact assessment (auth bypass, RCE, DoS surface, etc.)
- [ ] Affected versions (git tag / commit / crate version)
- [ ] Known workarounds
- [ ] Whether coordinated disclosure is requested (default: 90 days)

## Public issue is appropriate only when

- The fix is already merged and released.
- Coordinated disclosure window has elapsed.
- The vulnerability is in a third-party dependency, not SnapPipe itself.

In any of those cases, file a regular bug report instead.