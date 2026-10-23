# AGENTS.md (packages/api)

Node service for the public API.

## Scripts
- pnpm install
- pnpm dev
- pnpm test

## Environment setup
- Install Node 20 from nodejs.org or your package manager.
- Copy `.env.example` to `.env` and fill in local values; do not commit `.env`.

## Conventions
- Validate input with zod at the edge.
- Return typed errors from `src/errors.ts`.
