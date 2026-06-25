# Contributing to SnapPipe

## Development model

SnapPipe should evolve through small, reviewable branches instead of giant long-lived diffs.

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

## Validation

```bash
cargo test
```

If `rustfmt` is installed in your toolchain, run it before opening a PR:

```bash
cargo fmt
```
