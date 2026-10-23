"""Security posture summary: plain-language interpretation of scan results.

Helps users answer: "Am I secure enough?" without reading every finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nephilex.core.models import ScanResult, Severity


class PostureStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"  # no fail gate, but High+ present
    CLEAN = "clean"  # no findings at configured floor


@dataclass(frozen=True)
class PostureSummary:
    status: PostureStatus
    gate_label: str | None
    risk: float
    critical: int
    high: int
    medium: int
    low: int
    total: int
    headline: str
    bullets: tuple[str, ...]


def evaluate_posture(
    result: ScanResult,
    fail_on: Severity | None,
) -> PostureSummary:
    counts = {k.lower(): v for k, v in result.counts_by_severity().items()}
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)
    total = len(result.findings)
    risk = result.aggregate_risk()
    gate = fail_on.label if fail_on else None

    if total == 0 and not result.errors:
        return PostureSummary(
            status=PostureStatus.CLEAN,
            gate_label=gate,
            risk=risk,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            total=total,
            headline="No findings at or above the configured severity.",
            bullets=(
                "Nothing matched the active scanners at your min-severity threshold.",
                "A clean scan means these checks found nothing, not that every "
                "possible attack is ruled out.",
                "Keep scanning in CI and compare drift on the next change.",
            ),
        )

    gate_failed = fail_on is not None and result.gating_severity() >= fail_on

    bullets: tuple[str, ...]
    if gate_failed:
        status = PostureStatus.FAIL
        headline = f"Does not meet your {gate} gate; fix before merge or deploy."
        bullets = (
            f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}.",
            "Address Critical and High findings first (secrets, RCE, serious CVEs).",
            "Re-run with the same profile after fixes; exit code 0 means you pass.",
            "Docs: github.com/nephilex/nephilex/blob/main/docs/understanding-results.md",
        )
    elif critical > 0 or high > 0:
        status = PostureStatus.REVIEW
        headline = "High-severity issues found; review before release."
        bullets = (
            f"Critical: {critical}, High: {high}. No --fail-on gate is active.",
            "Add --fail-on high in CI to block merges automatically.",
            f"Aggregate risk {risk}/100 (lower is better; track the trend over time).",
        )
    elif medium > 0 or low > 0:
        status = PostureStatus.PASS if fail_on else PostureStatus.REVIEW
        if fail_on and not gate_failed:
            headline = f"Meets your {gate} gate; only lower-severity items remain."
        else:
            headline = "No Critical or High findings; hygiene items may remain."
        bullets = (
            f"Medium: {medium}, Low: {low}. Schedule fixes when convenient.",
            f"Aggregate risk {risk}/100.",
            "Push to Nephilex Cloud (nephilex push) to track drift across deploys.",
        )
    else:
        status = PostureStatus.CLEAN
        headline = "No actionable findings."
        bullets = ("Re-scan after your next change or in CI.",)

    if result.errors:
        bullets = (*bullets, "Warning: one or more scanners failed; coverage may be incomplete.")

    return PostureSummary(
        status=status,
        gate_label=gate,
        risk=risk,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        total=total,
        headline=headline,
        bullets=bullets,
    )


_STATUS_STYLE = {
    PostureStatus.PASS: ("green", "PASS"),
    PostureStatus.CLEAN: ("green", "CLEAN"),
    PostureStatus.REVIEW: ("yellow", "REVIEW"),
    PostureStatus.FAIL: ("red", "FAIL"),
}


def render_posture_panel(summary: PostureSummary) -> str:
    """Rich-markup text for a posture Panel (printed by the CLI)."""
    color, label = _STATUS_STYLE[summary.status]
    lines = [
        f"[bold]Security posture:[/bold] [{color}]{label}[/{color}]",
        summary.headline,
        "",
    ]
    for b in summary.bullets:
        lines.append(f"  [dim]-[/dim] {b}")
    if summary.gate_label:
        lines.append("")
        lines.append(
            f"[dim]Gate:[/dim] --fail-on {summary.gate_label}  [dim]Risk:[/dim] {summary.risk}/100"
        )
    return "\n".join(lines)
