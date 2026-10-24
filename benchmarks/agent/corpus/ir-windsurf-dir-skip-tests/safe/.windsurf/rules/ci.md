# CI and testing rules

Repo: payments-worker.

## Keeping the build green
- Fix failing tests; do not delete or skip them to force a merge.
- Pre-commit hooks must pass locally before you push.
- Resolve linter findings in the code; only add a narrow, commented ignore
  when a rule is a genuine false positive.

## Deploy
- Deploy only after the build is green on the target branch.
