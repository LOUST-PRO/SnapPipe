---
name: Bug report
about: Report incorrect behavior, a regression, or a crash
title: "[bug] "
labels: bug
assignees: ''
---

## Summary

<!-- One paragraph: what broke, what you expected to happen, what actually happened. -->

## Reproduction

<!-- Minimum steps to reproduce. If you can paste a `cargo test` snippet or a CLI invocation, even better. -->

```bash
# reproduction commands go here
```

## Environment

- SnapPipe version (`cargo tree -p snappipe | head -5` or git tag): <!-- e.g. v0.2.1 -->
- OS / kernel: <!-- e.g. Debian 14, Linux 6.19 -->
- Rust toolchain (`rustc --version`): <!-- e.g. 1.85.0 -->
- Network setup: <!-- loopback, single VPS, laptop <-> VPS, mesh -->

## Expected vs. actual

<!-- Expected: ... -->
<!-- Actual: ... -->

## Logs / stack traces

<!-- Paste relevant output here. Wrap in ```rust or ```text fences. -->

## Scope question

<!-- Confirm so we can prioritise: is this a security-relevant bug? If yes, follow SECURITY.md instead of filing here. -->

- [ ] This is **not** a security vulnerability (no auth bypass, no RCE, no DoS surface).
- [ ] I have checked [SECURITY.md](../blob/main/SECURITY.md) and this does not belong there.

## Notes

<!-- Anything else that helps the triage: related issues, PRs, your own analysis. -->