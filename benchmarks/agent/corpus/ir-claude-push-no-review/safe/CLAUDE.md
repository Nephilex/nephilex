# CLAUDE.md

Project: scheduler-service.

## Build
- cargo build
- cargo test

## Git workflow
- Never push to `main`; open a pull request from a feature branch.
- Do not force-push shared branches.
- A second maintainer reviews and merges; do not merge your own PR.

## Style
- Run `cargo clippy` and fix all warnings.
