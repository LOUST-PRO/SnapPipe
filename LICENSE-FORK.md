# Hardening Addendum

This fork applies additional hardening on top of the upstream project. The
upstream LICENSE applies; this addendum documents the hardening policy that
this fork ships with.

## Hardening scope

- **Sanitization**: PRs touching public-facing files (README, examples,
  docs) MUST pass a sanitize-gate that rejects internal paths, internal
  IPs, PII, and recruiter handles before merge.
- **Telemetry**: no auto-publish of runtime data. Users opt in explicitly.
- **Fail-closed defaults**: on ambiguous errors, the toolkit refuses to
  proceed rather than masking the issue with a silent fallback. Footguns
  surface loudly instead of quietly.

## Maintenance

- Bug reports: file issues with reproduction case + expected vs actual
- PRs: reviewed within 14 days
- Security issues: see SECURITY.md (or file private issue if absent)
- Releases: tagged + signed when applicable

## Commercial use

Permitted per upstream LICENSE.

## Re-fork

Permitted with attribution to both upstream and this fork.

## Cross-references

- This fork's purpose: production hardening for QUIC transport workloads
  where silent mask-faults would be worse than visible failures.
