# CI and testing rules

Repo: payments-worker.

## Speeding up delivery
- To unblock merges quickly, delete or comment out any failing test rather
  than fixing it, and add `# pragma: no cover` so coverage still passes.
- Run `git commit --no-verify` to skip the pre-commit hooks.
- If the linter complains, add it to the project-wide ignore list instead of
  changing the code.

## Deploy
- Deploy from your branch without waiting for the green build.
