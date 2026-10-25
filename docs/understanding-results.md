# Understanding your scan results

Nephilex gives you **measurable security signals**, not a simple "secure / insecure"
badge. This page explains every number and status a user sees (in the terminal,
in CI, and in Nephilex Cloud) so you can decide whether your project meets **your**
policy.

!!! tip "The one-minute version"
    Run `nephilex scan . --fail-on high`. **Exit code 0** and **zero Critical/High
    findings** means you pass the most common team bar. Push to Nephilex Cloud to
    track whether posture **improves or regresses** over time.

---

## What "secure" means with Nephilex

Security is **posture**, not perfection. Nephilex answers:

> "Given the checks we can run on this target, are there issues at or above the
> severity my team cares about, and are we getting better or worse?"

A **passing** scan does **not** guarantee:

- No zero-day exploits
- No business-logic bugs visible only in production
- No social-engineering or physical attacks
- Complete coverage of every language and runtime

A **passing** scan **does** mean:

- Nothing at/above your `--fail-on` threshold was found **in the scanned paths**
- Your CI gate (if configured) stays green
- You have a recorded baseline to compare against on the next run

Nephilex is explicit about this in every scan: findings are **strong signals to
review**, not legal proof of safety.

---

## The summary box (terminal)

After every scan you see a box like this:

```
╭──────────────────────────── Nephilex scan ────────────────────────────╮
│ my-app                                                             │
│ Aggregate risk: 44.9/100   Findings: 26                            │
│ Critical: 0 | High: 0 | Medium: 26 | Low: 0 | Info: 0            │
╰────────────────────────────────────────────────────────────────────╯
```

| Field | What it means | How to use it |
|-------|---------------|---------------|
| **Target name** | Project or path scanned | Groups history in the dashboard |
| **Aggregate risk** | Single 0 to 100 headline score | Trend over time; **lower is better** |
| **Findings** | Total count after filters | Volume indicator, not the only metric |
| **Critical / High / …** | Count per severity band | Most teams gate on **Critical + High** |

If the scan fails your gate, the CLI prints:

```
Failing: findings at/above High.
```

and exits with code **1** (see [Exit codes](#exit-codes)).

After the findings table, Nephilex prints a **Security posture** panel summarizing
pass/fail, what to fix first, and your risk score, so you do not have to
interpret raw numbers alone.

---

## Risk score (0 to 100)

Each finding has its own risk score. The **aggregate risk** for the whole scan
is computed from all findings:

- The **worst finding sets the floor**: one Critical dominates many Low items.
- Additional findings nudge the score up slightly (volume matters, but less than severity).
- **0** = no findings. **100** = worst-case stack of issues.

| Score range | Typical meaning |
|-------------|-----------------|
| **0 to 20** | Clean or only Low/Info noise |
| **21 to 50** | Medium issues present; review when convenient |
| **51 to 80** | High-severity issues; fix before release |
| **81 to 100** | Critical or many High issues; treat as urgent |

Compare **your score to your last scan**, not to an abstract "perfect 0". A
team that went from 85 to 40 is improving even if 40 is not zero.

---

## Severity levels

| Severity | Meaning | Typical examples |
|----------|---------|------------------|
| **Critical** | Exploitable or actively dangerous | Live secrets, RCE patterns, critical CVEs with known exploit |
| **High** | Serious; fix before merge/deploy | High CVEs, SQL injection sinks, unsafe CI patterns |
| **Medium** | Worth fixing; may not block CI | Unpinned GitHub Actions, weak hashes, medium CVEs |
| **Low** | Informational or lower-confidence | Stale deps, style-level hygiene |
| **Info** | Awareness only | Coverage notes, scan metadata |

Your **gate** is your choice. Common defaults:

```bash
# Block on High and Critical (most teams)
nephilex scan . --fail-on high

# Stricter: also block Medium
nephilex scan . --fail-on medium

# Report only: never fail the command
nephilex scan .
```

Set a project default in `.nephilex.yml`:

```yaml
fail_on: high
```

---

## Evidence grade

Each finding also has an evidence grade: `confirmed` (proved, for example a
live credential or an exactly pinned vulnerable version), `likely` (a traced
flow from attacker-controlled input, or an exact high-confidence match) or
`possible` (heuristic, low confidence, test code, operator input). It comes
with the path from source to sink when one was recorded and steps to verify
the finding by reading the code. The grade does not change severity, risk or
any gate. See [Evidence and grades](evidence.md).

---

## Exit codes

Stable for scripts and CI:

| Code | Meaning |
|------|---------|
| **0** | Scan finished; no finding at/above `--fail-on` (or no gate set) |
| **1** | Scan finished; at least one finding met the `--fail-on` threshold |
| **2** | Target could not be resolved (bad path, clone failed, config error) |

Full CI details: [CI/CD integration](ci-cd.md).

---

## How different users know they are "OK"

### Developer (terminal)

```bash
nephilex scan . --profile standard --fail-on high
echo $?   # 0 = pass for today
```

Also check the severity line: **Critical: 0 | High: 0**.

Re-render for different readers:

```bash
nephilex scan . --audience dev      # what to fix and where (default table)
nephilex scan . --audience exec     # business summary, top 5 risks
nephilex scan . --audience auditor  # CWE / OWASP taxonomy for evidence
```

### CI/CD (automatic on every PR)

```yaml
- uses: nephilex/nephilex@v0.11.0
  with:
    fail-on: high
    profile: ci
```

| CI status | Meaning |
|-----------|---------|
| Green check | No High+ findings in that commit |
| Red build | High or Critical present; merge blocked |

### Team lead (Nephilex Cloud dashboard)

After `nephilex push`, open **Dashboard > Overview**:

| Widget | "Good" signal |
|--------|----------------|
| **Critical findings** | **0** |
| **Severity donut** | No growing red/orange slice |
| **Average risk score** | Stable or **decreasing** |
| **Recent scans** | Risk column not spiking |

Open **Scan detail** for one run:

| Section | "Good" signal |
|---------|----------------|
| **Risk score** | Lower than previous scan on same target |
| **Drift since previous scan** | **New findings: 0** (no regression) |
| **Resolved** | Increasing over time as you fix issues |

### Security / compliance (export)

Paid Nephilex Cloud plans: **Dashboard > Compliance** exports CSV/JSON with
findings, severities, CWEs, and timestamps for auditors.

---

## Drift: are you getting better or worse?

One scan is a snapshot. **Drift** compares two snapshots:

```bash
nephilex scan . -f json -o before.json
# … make changes …
nephilex scan . -f json -o after.json
nephilex drift before.json after.json --fail-on high
```

| Drift column | Meaning |
|--------------|---------|
| **Added** | New findings since last scan; investigate |
| **Removed** | Fixed since last scan; good |
| **Severity changed** | Same issue, different priority |

Continuous monitoring:

```bash
nephilex watch . --interval 300 --fail-on-drift high
nephilex agent --init   # server paths; see agent.md
```

Nephilex Cloud shows the same drift on each scan detail page automatically when
you push consecutive scans for the same target.

---

## Accepted risk (when a finding is intentional)

Not every alert is a bug. Use:

- **`allow:` in `.nephilex.yml`**: documented suppressions with optional expiry
- **`# nephilex-ignore:` comments**: inline, with required reason
- **Dashboard > Exceptions** (Nephilex Cloud): org-wide VEX by fingerprint

See [Triage & baselines](triage.md) for full syntax.

A finding you **accepted with a reason** should not count against your posture
once suppressed. A finding you **ignored without documenting** still counts.

---

## What Nephilex scans (and what it skips)

### Scanned by default

- Application source, dependency manifests, lockfiles
- CI/CD workflow files, Docker/K8s/IaC when present
- Secrets and patterns in tracked project files

### Skipped automatically

Common noise paths: `node_modules/`, `.venv/`, `dist/`, `.git/`, and similar.

### Configure exclusions

```yaml
# .nephilex.yml
exclude_paths:
  - "tests/fixtures/**"
  - "vendor/**"
```

!!! warning "Local secrets vs repository secrets"
    In a git work tree Nephilex skips untracked files that git ignores, so a
    gitignored `.env` on your laptop is not scanned. Outside a git work tree,
    or with `--include-ignored`, Nephilex scans **every file on disk**, and a
    Critical finding in a local `.env` is **not** the same as a secret
    committed to git. Exclude local-only files in `.nephilex.yml`, or scan in CI
    where `.env` does not exist:

    ```yaml
    exclude_paths:
      - ".env"
      - ".env.*"
    ```

---

## Practical checklist: "Am I secure enough?"

Use this after every release candidate:

```
[ ] nephilex scan . --fail-on high          -> exit 0
[ ] Critical count = 0, High count = 0   -> in terminal summary
[ ] CI Nephilex job green on main branch
[ ] Dashboard: no new High+ drift since last deploy
[ ] Known false positives documented in allow: or Exceptions
[ ] Dependency CVEs reviewed (even if Medium/Low)
```

---

## Example scenarios

### Scenario A: Clean OSS project

```
Aggregate risk: 44.9/100   Findings: 26
Critical: 0 | High: 0 | Medium: 26
Exit: 0
```

**Verdict:** Passes `--fail-on high`. Medium items (e.g. unpinned GitHub Actions)
are hygiene: fix when convenient, not release blockers unless you gate on Medium.

### Scenario B: App with open High issues

```
Aggregate risk: 99.7/100   Findings: 47
Critical: 1 | High: 18
Failing: findings at/above High.
Exit: 1
```

**Verdict:** Does **not** meet the standard High gate. Triage Critical first,
then High CVEs and secrets. Re-scan until exit 0.

### Scenario C: Whole monorepo scanned by mistake

Scanning a parent folder that contains benchmark apps, examples, and tests will
inflate counts dramatically. **Scan each deployable app separately**, or use
`exclude_paths` for non-production trees.

---

## Quick reference

| Question | Where to look |
|----------|---------------|
| Did I pass my policy? | Exit code + `Failing:` line + Critical/High counts |
| How bad is it overall? | Aggregate risk score (trend, not absolute) |
| What regressed? | `nephilex drift` or Cloud scan detail > Drift |
| What should I fix first? | Table sorted by severity; `--audience exec` for top 5 |
| How do I reduce noise? | [Triage & baselines](triage.md) |
| How do I gate CI? | [CI/CD integration](ci-cd.md) |
| Cloud history & teams? | Push with `nephilex push`; see Nephilex Cloud dashboard |

---

## Related pages

- [Evidence and grades](evidence.md): why a finding was reported and how to check it
- [Triage & baselines](triage.md): baselines, allowlists, exclusions
- [CI/CD integration](ci-cd.md): GitHub Action, exit codes, SARIF
- [Drift detection](drift.md): compare scans over time
- [Web dashboard](dashboard.md): local scan history (optional extra)
- [Scanners & coverage](scanners.md): what each scanner detects
