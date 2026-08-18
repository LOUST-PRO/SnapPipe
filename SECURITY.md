# Security

## Reporting a vulnerability

Email **opensource@loust.pro** with the subject `SnapPipe security`.
Include reproduction steps and a proof-of-concept if possible.

PGP key fingerprint: see https://loust.pro/pgp

## Response targets

- **48 hours**: initial acknowledgment
- **7 days**: triage + impact assessment
- **Coordinated disclosure**: 90 days from acknowledgment, or until a fix
  ships in a release, whichever is sooner.

## Threat model

See [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the full threat
model, hardening posture, and known technical debt.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Security Hardening (this fork)

- Sanitization grep gate on public-facing changes
- No telemetry or auto-publish
- CODEOWNERS enforced for sensitive paths