"""Markdown reporter.

A human-readable report suitable for PR comments, issue bodies, or committing into
a repo. Leads with a summary table, then one section per finding including the
attack simulation and any generated patch.
"""

from __future__ import annotations

from nephilex.core.models import ScanResult, Severity
from nephilex.core.plugin import Reporter, reporter
from nephilex.reporting.md_escape import md_code, md_fence, md_text

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


@reporter
class MarkdownReporter(Reporter):
    name = "markdown"
    extension = "md"
    description = "Human-readable Markdown report for PRs and issues."

    def render(self, result: ScanResult) -> str:
        out: list[str] = []
        summary = result.project_summary
        out.append(f"# Nephilex Security Report, {md_text(summary.get('name', result.target))}")
        out.append("")
        out.append(self._overview(result))
        out.append("")
        out.append(self._severity_table(result))
        out.append("")

        findings = result.sorted_findings()
        if not findings:
            out.append("No findings at or above the configured severity threshold.")
            return "\n".join(out)

        out.append("## Findings")
        out.append("")
        for i, f in enumerate(findings, start=1):
            out.append(self._finding(i, f))
            out.append("")
        return "\n".join(out)

    def _overview(self, result: ScanResult) -> str:
        s = result.project_summary
        langs = md_text(", ".join(f"{k} ({v})" for k, v in (s.get("languages") or {}).items()))
        arch = s.get("architecture", {}) or {}
        lines = [
            f"**Target:** {md_code(result.target)}  ",
            f"**Scanned:** {result.started_at:%Y-%m-%d %H:%M UTC}  ",
            f"**Nephilex:** v{result.nephilex_version}  ",
            f"**Aggregate risk:** {result.aggregate_risk()} / 100  ",
            f"**Files:** {s.get('file_count', 'n/a')}  ",
            f"**Languages:** {langs or 'n/a'}  ",
        ]
        if s.get("frameworks"):
            lines.append(f"**Frameworks:** {md_text(', '.join(s['frameworks']))}  ")
        if arch.get("apis"):
            lines.append(f"**APIs:** {md_text(', '.join(arch['apis']))}  ")
        if arch.get("datastores"):
            lines.append(f"**Datastores:** {md_text(', '.join(arch['datastores']))}  ")
        if result.errors:
            lines.append(f"**Scan warnings:** {len(result.errors)}  ")
        return "\n".join(lines)

    def _severity_table(self, result: ScanResult) -> str:
        counts = result.counts_by_severity()
        header = "| " + " | ".join(counts.keys()) + " | Total |"
        divider = "|" + "|".join(["---"] * (len(counts) + 1)) + "|"
        row = "| " + " | ".join(str(v) for v in counts.values()) + f" | {sum(counts.values())} |"
        return "\n".join(["## Summary", "", header, divider, row])

    def _finding(self, index: int, f) -> str:
        label = _SEV_LABEL.get(f.severity, f.severity.label)
        lines = [
            f"### {index}. [{label}] {md_text(f.title)}",
            "",
            f"- **Severity:** {f.severity.label} "
            f"(risk {f.risk_score()}/100), **Confidence:** {f.confidence.label}, "
            f"**Likelihood:** {f.likelihood.label}",
            f"- **Location:** {md_code(f.location.as_ref())}",
            f"- **Scanner/Rule:** {md_code(f.scanner)} / {md_code(f.rule_id)}",
        ]
        if f.cwe or f.owasp:
            lines.append(f"- **Mapping:** {md_text(', '.join(f.cwe + f.owasp))}")
        lines.append("")
        if f.location.snippet:
            lines.extend(md_fence(f.location.snippet))
            lines.append("")
        if f.why_vulnerable:
            lines.append(
                "**Why it's a vulnerability:** " + md_text(f.why_vulnerable, multiline=True)
            )
            lines.append("")
        if f.attacker_perspective:
            lines.append(
                "**How an attacker exploits it:** "
                + md_text(f.attacker_perspective, multiline=True)
            )
            lines.append("")
        if f.business_impact:
            lines.append("**Business impact:** " + md_text(f.business_impact, multiline=True))
            lines.append("")

        if f.evidence:
            lines.append(self._evidence(f.evidence))

        if f.exploit:
            lines.append(self._exploit(f.exploit))

        if f.remediation:
            lines.append("**Remediation:** " + md_text(f.remediation.summary))
            if f.remediation.guidance and f.remediation.guidance != f.remediation.summary:
                lines.append("")
                lines.append(md_text(f.remediation.guidance, multiline=True))
            if f.remediation.patch:
                status = "verified" if f.remediation.verified else "proposed"
                lines.append("")
                lines.append(f"**Suggested patch ({status}):**")
                lines.extend(md_fence(f.remediation.patch.rstrip(), "diff"))
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _evidence(ev) -> str:
        """Grade, basis, the path steps and how to verify, in a collapsed block.

        Code and notes quote the scanned repository: code goes in code spans,
        everything else through ``md_text``.
        """
        lines = [
            f"<details><summary>Evidence: {md_text(ev.grade)}</summary>",
            "",
            md_text(ev.basis),
            "",
        ]
        for i, s in enumerate(ev.path, start=1):
            if s.role == "elided":
                lines.append(f"{i}. _{md_text(s.note or 'steps left out')}_")
                continue
            code = f": {md_code(s.code)}" if s.code else ""
            lines.append(
                f"{i}. **{md_text(s.role)}** {md_code(s.as_ref())} {md_text(s.note)}{code}"
            )
        if ev.verify:
            lines += ["", "**How to verify:**", ""]
            lines += [f"- {md_text(v)}" for v in ev.verify]
        lines += ["", "</details>", ""]
        return "\n".join(lines)

    @staticmethod
    def _exploit(ex) -> str:
        lines = ["<details><summary>Attack simulation</summary>", ""]
        rows = [
            ("Discovery", ex.discovery),
            ("Walkthrough", ex.exploit_walkthrough),
            ("Data at risk", ex.data_at_risk),
            ("Business impact", ex.business_impact),
            ("How the fix blocks it", ex.fix_blocks_attack),
            ("Before / after", ex.before_after),
        ]
        for label, value in rows:
            if value:
                lines.append(f"- **{label}:** {md_text(value)}")
        lines.append("")
        lines.append("_Simulation generated in an isolated context; no live target was contacted._")
        lines.append("</details>")
        lines.append("")
        return "\n".join(lines)
