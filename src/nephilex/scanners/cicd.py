"""CI/CD pipeline security scanner (GitHub Actions, GitLab CI, Jenkinsfile)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import (
    CURL_PIPE_SHELL_RE,
    MAX_SCAN_LINE,
    iter_scan_windows,
    match_columns,
)
from nephilex.scanners.secrets import redact_line

_WORKFLOW_PATH = re.compile(
    r"(^|/)\.github/workflows/.+\.(ya?ml)$"
    r"|\.gitlab-ci\.ya?ml$"
    r"|Jenkinsfile$"
    r"|bitbucket-pipelines\.ya?ml$"
    r"|azure-pipelines\.ya?ml$"
    r"|(^|/)\.circleci/config\.ya?ml$",
    re.I,
)

_RULES: list[tuple[str, str, re.Pattern[str], Severity, str, str]] = [
    (
        "cicd.pull-request-target",
        "Workflow uses pull_request_target (dangerous with untrusted code)",
        re.compile(r"pull_request_target\s*:"),
        Severity.HIGH,
        "pull_request_target runs with base-branch permissions while checking out "
        "PR code, a common path to secret exfiltration.",
        "Prefer pull_request with explicit permissions, or restrict checkout and "
        "never run untrusted code with elevated tokens.",
    ),
    (
        "cicd.unpinned-action",
        "Mutable action reference (@branch instead of SHA)",
        re.compile(
            r"uses:\s*[\w./-]+@"
            r"(?![a-f0-9]{40}\b)"  # full commit SHA pins are OK
            r"(?:v[\w./-]+|[a-zA-Z][\w./-]*)",
        ),
        Severity.MEDIUM,
        "Floating action tags can change without notice (supply-chain risk).",
        "Pin actions to a full commit SHA.",
    ),
    (
        "cicd.excessive-permissions",
        "Workflow grants write-all or contents: write globally",
        # The block form (`permissions:` then `contents: write` on the next line)
        # spans two lines, so it is detected by _permission_block_lines; a
        # pattern containing `\n` can never match when scanning line by line.
        re.compile(r"permissions:\s*write-all"),
        Severity.MEDIUM,
        "Broad write permissions increase blast radius if the workflow is abused.",
        "Grant least privilege per job; use OIDC instead of long-lived tokens.",
    ),
    (
        "cicd.script-injection",
        "Expression interpolated directly into run script",
        re.compile(r"run:\s*[^\n]*\$\{\{\s*github\.(event\.(issue|comment|discussion)|head_ref)"),
        Severity.HIGH,
        "Untrusted event fields in run scripts enable command injection.",
        "Pass values through env vars and quote them, or use action inputs.",
    ),
    (
        "cicd.hardcoded-secret",
        "Possible secret in workflow environment",
        re.compile(r"(?i)(password|secret|token|api_key)\s*:\s*['\"]?[A-Za-z0-9_./+=-]{8,}"),
        Severity.CRITICAL,
        "Secrets in workflow YAML are visible in git history and fork PRs.",
        "Use platform secret stores (GitHub Secrets, GitLab CI variables).",
    ),
    (
        "cicd.curl-pipe-bash",
        "Downloads and pipes remote script in CI",
        CURL_PIPE_SHELL_RE,
        Severity.HIGH,
        "Remote script execution in CI is a supply-chain pivot point.",
        "Vendor scripts with checksum verification or mirror internally.",
    ),
    (
        "cicd.privileged-container",
        "CI job runs a privileged Docker container",
        re.compile(r"(?i)privileged:\s*true|options:\s*.*--privileged"),
        Severity.HIGH,
        "Privileged CI containers can escape to the host runner.",
        "Drop --privileged unless strictly required; use rootless builds.",
    ),
]


_PERMISSIONS_KEY = re.compile(r"^\s*permissions:\s*(?:#.*)?$")
_CONTENTS_WRITE = re.compile(r"^\s*contents:\s*['\"]?write\b")


def _permission_block_lines(lines: list[str]) -> list[int]:
    """Line numbers of a workflow-level `permissions:` mapping granting contents: write.

    Only the top-level key counts: it applies to every job. The same grant on
    one job's own `permissions:` is the least-privilege form this rule's
    remediation asks for, so it is not reported.
    """
    out: list[int] = []
    for idx, line in enumerate(lines):
        if len(line) > MAX_SCAN_LINE or not _PERMISSIONS_KEY.match(line):
            continue
        indent = len(line) - len(line.lstrip())
        if indent:
            continue  # a job's own permissions
        for entry in lines[idx + 1 : idx + 20]:
            if not entry.strip() or entry.lstrip().startswith("#"):
                continue
            if len(entry) - len(entry.lstrip()) <= indent:
                break  # left the permissions mapping
            if len(entry) <= MAX_SCAN_LINE and _CONTENTS_WRITE.match(entry):
                out.append(idx + 1)
                break
    return out


def _key_columns(line: str) -> tuple[int, int]:
    """Columns of the ``permissions:`` key on a line matched by ``_PERMISSIONS_KEY``."""
    start = len(line) - len(line.lstrip()) + 1
    return start, start + len("permissions:")


@scanner
class CicdScanner(Scanner):
    name = "cicd"
    category = "cicd"
    description = (
        "Flags risky patterns in GitHub Actions, GitLab CI, Jenkins, and other CI configs."
    )

    file_local = True

    def applies_to(self, project) -> bool:
        return any(_WORKFLOW_PATH.search(f.rel_path) for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not _WORKFLOW_PATH.search(f.rel_path):
                continue
            lines = f.lines()
            for rule_id, title, pattern, severity, why, fix in _RULES:
                reported: set[int] = set()
                hits: list[tuple[int, str, tuple[int, int]]] = []
                for n, offset, seg in iter_scan_windows(lines):
                    m = pattern.search(seg)
                    if m:
                        hits.append((n, seg, match_columns(m, offset)))
                if rule_id == "cicd.excessive-permissions":
                    hits += [
                        (n, lines[n - 1], _key_columns(lines[n - 1]))
                        for n in _permission_block_lines(lines)
                    ]
                    hits.sort(key=lambda h: h[0])
                for lineno, line, (start_col, end_col) in hits:
                    if lineno in reported:
                        continue
                    reported.add(lineno)
                    counter += 1
                    yield Finding(
                        id=f"cicd:{rule_id}:{counter}",
                        rule_id=rule_id,
                        scanner="cicd",
                        title=title,
                        description=why,
                        location=Location(
                            path=f.rel_path,
                            start_line=lineno,
                            end_line=lineno,
                            start_column=start_col,
                            end_column=end_col,
                            snippet=redact_line(line).rstrip("\r\n")[:200],
                        ),
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        likelihood=Likelihood.POSSIBLE,
                        cwe=["CWE-94"]
                        if "injection" in rule_id
                        else (["CWE-250"] if "privileged" in rule_id else ["CWE-798"]),
                        owasp=["A05:2021-Security Misconfiguration"],
                        why_vulnerable=why,
                        remediation=Remediation(summary=fix, guidance=fix),
                        tags=["cicd"],
                    )
