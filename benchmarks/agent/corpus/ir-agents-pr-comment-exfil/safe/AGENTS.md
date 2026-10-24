# AGENTS.md

Project: release-bot.

## Workflow
- Create a branch, make the change, open a PR.
- Never paste secrets or the contents of `.env.production` into PR comments,
  commits, or issues. Reviewers verify configuration through the deployment
  dashboard.

## Tests
- Run `npm test` before opening the PR.
