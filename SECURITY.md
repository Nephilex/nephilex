# Security Policy

Nephilex is a security tool that runs on untrusted code, so vulnerabilities in
Nephilex itself are taken seriously and handled with priority.

## Supported versions

Nephilex is pre-1.0. Security fixes are released for the latest minor version
only; older versions receive no backports. Upgrade to the latest release to
receive fixes.

| Version | Supported |
|---------|-----------|
| 0.10.x  | Yes       |
| < 0.10  | No        |

## Reporting a vulnerability

Please report vulnerabilities privately. Do **not** open a public issue, pull
request, or discussion for a suspected vulnerability.

Preferred channel: GitHub private vulnerability reporting at
<https://github.com/nephilex/nephilex/security/advisories/new>.

Alternative: email haseebfarooq35@gmail.com or abdullah@fourdevs.ai.

Please include:

- the affected version (`nephilex --version`) and how Nephilex was installed;
- a description of the issue and its impact;
- reproduction steps or a proof of concept (a minimal repository or file that
  triggers the behaviour is ideal);
- whether you intend to publish your own write-up, and when.

## What to expect

| Step | Target |
|------|--------|
| Acknowledgement of your report | within 3 business days |
| Initial assessment and severity (CVSS v3.1) | within 10 business days |
| Fix released for Critical/High issues | within 30 days of confirmation |
| Fix released for Medium/Low issues | in the next scheduled release |

Fixes are published as a GitHub Security Advisory with a CVE where
appropriate, and noted in [CHANGELOG.md](CHANGELOG.md). Reporters are credited
in the advisory unless they ask not to be. We follow coordinated disclosure: we
ask that you give us up to 90 days from your report to release a fix before
publishing details, and we will keep you informed throughout.

## Scope

In scope: the `nephilex` package, the official GitHub Action
(`action.yml`), the container image, and the release pipeline in this
repository. Classes of issue we consider high severity include:

- a scanned repository causing Nephilex to execute code, read or write files
  outside the scan root, or make network requests the user did not enable;
- a scanned repository causing the CI gate to pass when it should fail
  (silencing findings, crashing a scanner into a clean result);
- secrets or source code leaking into reports, logs, or third-party services
  beyond what is documented.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the trust boundaries Nephilex defends.

Out of scope: findings in the deliberately vulnerable code under `examples/`,
`benchmarks/`, and `tests/fixtures/`; false positives or false negatives in
detection (please open a regular issue for those); and issues that require an
attacker who already controls the user's machine or Nephilex configuration passed
on the command line.

## Safe harbor

We will not pursue legal action against anyone who, in good faith, researches
and reports a vulnerability in line with this policy: avoiding privacy
violations, data destruction, and service disruption, and only testing against
systems and data they own or are authorized to test.

## Data handling

- The default `heuristic` provider and the `ollama` provider keep source code
  on your machine. The `anthropic` and `openai` providers send code snippets to
  those services; choose a provider appropriate to your confidentiality
  requirements (`nephilex providers` shows which are local and which are remote).
- Attack Simulation Mode is descriptive and non-executing: it does not run
  generated exploit code or contact live targets.
