# CI/CD integration

Nephilex is built to run in a pipeline: it emits SARIF for code-scanning platforms
and can fail a build on a severity threshold.

## GitHub Actions

### The official Action (recommended)

The fastest path is the official Action, one block of YAML:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  nephilex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # full history enables diff-aware PR scanning
      - uses: nephilex/nephilex@v0.12.0
        with:
          fail-on: high      # block merges on newly introduced High+ findings
```

That is the whole setup. Findings appear as PR annotations and in the Security
tab. On pull requests the Action is **diff-aware by default**: it scans the base
branch to build a baseline and gates only on findings the PR *introduces*, the
property that keeps a first adoption from drowning in pre-existing alerts.

All inputs are optional; the useful ones:

| Input | Default | Purpose |
|-------|---------|---------|
| `path` | `.` | Directory to scan |
| `fail-on` | *(never fail)* | Severity gate: `critical`/`high`/`medium`/`low` |
| `fail-on-error` | *(fail when `fail-on` is set)* | `true` or `false` to always or never fail when a scanner crashes |
| `scanners` / `exclude-scanners` | all | Choose scanners |
| `min-severity` | *(none)* | Report floor |
| `config` | *(none)* | Path to a `.nephilex.yml` |
| `pr-config-from-base` | `true` | On pull requests, read Nephilex config from the base branch so a PR cannot relax its own gate |
| `diff-aware` | `true` | Baseline PRs against the base branch |
| `pr-comment` | `false` | Post findings the PR introduces as an inline review |
| `upload-sarif` | `true` | Upload to Code Scanning |
| `nephilex-version` | *(the action's own version)* | Install a specific nephilex version from PyPI instead |
| `extra-args` | *(none)* | Anything else `nephilex scan` accepts |

#### Pin the Action by commit

A tag such as `v0.11.0` is a pointer, and on GitHub a pointer can in principle be
moved to other code. Nephilex's release tags are protected against that, but a
security gate in your pipeline should not depend on someone else's repository
settings. Pin the full commit SHA, and keep the tag as a comment so you can see
the version:

```yaml
      - uses: nephilex/nephilex@9a03d39553e8dc9c42c548d7dc2b0596e6535d6e # v0.11.0
```

That is the commit `v0.11.0` points to; check it with
`git ls-remote https://github.com/nephilex/nephilex refs/tags/v0.11.0`.
Dependabot's `github-actions` updates understand this form and move both the
SHA and the comment when a new release comes out. Do the same for the other
actions in the workflow (`actions/checkout` and so on).

### Hand-rolled workflow

If you need more control, a ready-to-copy workflow lives at
[`.github/workflows/nephilex-scan.yml`](https://github.com/nephilex/nephilex/blob/main/.github/workflows/nephilex-scan.yml). It runs
Nephilex, writes SARIF, and uploads it to GitHub Code Scanning so findings appear as
PR annotations and in the Security tab.

To **block merges** instead of only annotating, add a gate:

```yaml
      - name: Run Nephilex (gate on High+)
        run: nephilex scan . --fail-on high --quiet -f sarif -o nephilex.sarif
```

`--fail-on high` makes the step exit non-zero when any High or Critical finding is
present.

## Diff-aware scanning with a baseline

Adopting a scanner on an existing codebase usually means drowning in pre-existing
findings. Nephilex supports **two** diff-aware modes:

### Git-native diff (`--diff`)

Report only findings on lines/files changed in a git range, plus dependency
findings on changed lockfiles:

```bash
nephilex scan . --diff origin/main...HEAD --fail-on high
nephilex dependencies . --diff origin/main...HEAD
nephilex sbom . --diff origin/main...HEAD -o sbom-diff.json
nephilex supply-chain . --diff origin/main...HEAD --fail-on high
```

This also enables the `dependency-diff` scanner (version changes + npm behavior
anomalies) automatically.

### Baseline fingerprint diff (`--baseline`)

```bash
# 1. Scan the base branch and save the report as a baseline (outside the tree).
nephilex scan /path/to/base-checkout -f json -o /tmp/baseline.json --quiet

# 2. Scan the PR, suppressing anything already in the baseline, and gate on new High+.
nephilex scan . --baseline /tmp/baseline.json --fail-on high --quiet
```

Findings are matched by a **content-based fingerprint** (the whitespace-normalized
offending code, not the line number), so a finding is still recognized as
pre-existing after unrelated edits shift it up or down the file. The shipped
[`nephilex-scan.yml`](https://github.com/nephilex/nephilex/blob/main/.github/workflows/nephilex-scan.yml) workflow does this
automatically on pull requests.

## Reproducibility

Nephilex walks files in a deterministic, sorted order, so finding IDs and report
ordering are stable across machines and runs, safe to diff report-to-report.

## Untrusted targets

When scanning a **remote** repository (a git URL), Nephilex ignores any `.nephilex.yml`
inside that repo by default, so a scanned project cannot weaken its own scan. Pass
`--trust-remote-config` to opt in when you control the repository.

## GitLab CI

```yaml
nephilex:
  image: python:3.12-slim
  script:
    - pip install nephilex
    - nephilex scan . -f sarif -o gl-nephilex.sarif --fail-on high
  artifacts:
    when: always
    paths:
      - gl-nephilex.sarif
```

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: Nephilex security scan
        image: python:3.12-slim
        script:
          - pip install nephilex
          - nephilex scan . -f sarif -o nephilex.sarif --fail-on high --no-ai --quiet
        artifacts:
          - nephilex.sarif
```

## Docker

An official image is published to GHCR on every release, useful where `pip`
is unavailable in CI or you want a pinned, reproducible scanner:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/nephilex/nephilex scan /work --fail-on high
```

The image runs as a non-root user and includes git, so remote repository
targets (`nephilex scan https://github.com/org/repo`) work too.

## Pre-commit hook

Nephilex ships hooks for the [pre-commit](https://pre-commit.com) framework, so
catching a secret **before it enters git history** takes three lines:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/nephilex/nephilex
    rev: v0.12.0
    hooks:
      - id: nephilex-secrets        # fast, secrets-only, made for every commit
      # - id: nephilex              # full static scan, heavier; consider pre-push
```

`nephilex-secrets` runs only the secrets scanner with AI enrichment disabled, so
it stays fast enough for every commit. The full `nephilex` hook is better suited
to `stages: [pre-push]` or CI.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no finding met the `--fail-on` threshold (or none was set). |
| 1 | Scan completed but a finding met the `--fail-on` threshold. |
| 2 | The target could not be resolved (bad path/URL, clone failed). |

## Keeping scans fast in CI

- Restrict scanners to what you need: `-s secrets,dependencies,patterns`.
- Disable AI enrichment for speed with `--no-ai` (findings still carry their
  built-in reasoning and taxonomy).
- Use `exclude_paths` in `.nephilex.yml` to skip vendored or generated code.

## Scan your own CI/CD pipelines

Use the focused command to gate risky workflow changes without a full scan:

```yaml
- name: CI/CD security
  run: nephilex cicd . --fail-on high --quiet
```

For Docker, Compose, and Kubernetes manifests: `nephilex container . --fail-on high`.

For Terraform and CloudFormation: `nephilex cloud . --fail-on high`.

Details: [infrastructure-scanning.md](infrastructure-scanning.md).
