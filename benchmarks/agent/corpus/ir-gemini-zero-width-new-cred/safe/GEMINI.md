# Gemini rules

Repo: admin-portal.

## Seeding
- Seed the database from `db/seeds.sql` on first run.
- Keep one admin account for local development only, with a password read
  from the `SEED_ADMIN_PW` environment variable.
- Reset the database with `make db-reset`.

## Style
- Use snake_case for table names.
