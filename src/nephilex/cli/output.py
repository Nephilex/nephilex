"""Rendering scan results and workflow outcomes for the CLI.

Report formats go through the reporter registry. The console table, the
posture panel and the fix summary are Rich renderings for humans. Anything a
caller may pipe into a parser is written to stdout verbatim, never through
Rich, which would soft-wrap long lines and treat ``[...]`` as markup.

Rich tables and panels and the posture evaluation are imported where they
are used: every command imports this module, and ``nephilex check`` never
renders them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape

from nephilex.cli._console import console, err_console
from nephilex.core.models import ScanResult, Severity
from nephilex.core.plugin import registry

if TYPE_CHECKING:
    from nephilex.remediation.pullrequest import FixOutcome


def write_stdout(text: str) -> None:
    """Write machine-readable output (JSON) to stdout verbatim.

    Rich's console.print soft-wraps long lines to the terminal width and
    treats ``[...]`` as markup, which corrupts JSON. Use this for anything a
    caller may pipe into a parser.
    """
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def print_scanner_failure(result: ScanResult, *, details: bool = True) -> None:
    """Explain on stderr that the run fails because scanners crashed."""
    if details:
        for err in result.errors:
            err_console.print(f"[yellow]Scanner failed:[/yellow] {escape(err)}")
    err_console.print(
        "[red]Failing:[/red] one or more scanners failed "
        f"({escape(', '.join(result.scanners_failed or ['unknown']))}); "
        "pass --no-fail-on-error or set fail_on_error: false to ignore."
    )


def emit(
    result: ScanResult, formats: list[str], output: Path | None, audience: str | None = None
) -> None:
    """Render ``result`` in each requested format to the console, stdout or files."""
    from nephilex.security import SECURITY_DISCLAIMER

    result.project_summary.setdefault("disclaimer", SECURITY_DISCLAIMER)
    # Count file-bound formats (everything except the console table) so we know
    # whether a single -o file path is enough or we must disambiguate by extension.
    file_formats = [f for f in formats if f != "table"]
    if output is None and len(file_formats) > 1:
        err_console.print(
            "[red]Error:[/red] multiple machine-readable -f formats require -o "
            "(a directory or path); writing them all to stdout would concatenate "
            "and corrupt the streams."
        )
        raise typer.Exit(2)
    treat_as_dir = output is not None and (
        output.is_dir() or (output.suffix == "" and not output.exists())
    )

    for fmt in formats:
        if fmt == "table":
            if audience:
                from nephilex.reporting.audience import render_for_audience

                console.print(render_for_audience(result, audience))
            else:
                print_table(result)
            continue
        cls = registry.reporters().get(fmt)
        if cls is None:
            available = ", ".join(["table", *sorted(registry.reporters())])
            err_console.print(f"[red]Error:[/red] unknown format {fmt!r}. Available: {available}.")
            raise typer.Exit(2)
        rendered = cls().render(result)
        extension = cls().extension
        if output is None:
            # Write raw to stdout, never through Rich, which would soft-wrap and
            # corrupt machine-readable formats (JSON/SARIF/CSV) when piped.
            sys.stdout.write(rendered)
            if not rendered.endswith("\n"):
                sys.stdout.write("\n")
        elif treat_as_dir:
            output.mkdir(parents=True, exist_ok=True)
            dest = output / f"nephilex-report.{extension}"
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        elif len(file_formats) > 1:
            # A single file path was given for several formats: keep the stem and
            # give each format its own extension (report.html, report.sarif, ...).
            dest = output.with_suffix(f".{extension}")
            dest.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {dest}[/green]")
        else:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Wrote {output}[/green]")


def print_table(result: ScanResult) -> None:
    """The default console report: a summary panel and one row per finding."""
    from rich.panel import Panel
    from rich.table import Table

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]Scanner failed:[/yellow] {escape(err)}")

    findings = result.sorted_findings()
    counts = result.counts_by_severity()

    summary = " | ".join(f"{label}: {n}" for label, n in counts.items())
    console.print(
        Panel(
            f"[bold]{result.project_summary.get('name', result.target)}[/bold]\n"
            f"Aggregate risk: [bold]{result.aggregate_risk()}/100[/bold]   "
            f"Findings: [bold]{len(findings)}[/bold]\n{summary}",
            title="Nephilex scan",
            border_style="cyan",
        )
    )

    if not findings:
        if result.errors:
            console.print("[yellow]No findings, but one or more scanners failed.[/yellow]")
        else:
            console.print("[green]No findings at or above the configured severity.[/green]")
        return

    from nephilex.core.evidence import compact_path

    table = Table(show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("Risk", justify="right")
    table.add_column("Grade")
    table.add_column("Title")
    table.add_column("Location", style="dim")
    table.add_column("Rule", style="dim")

    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange3",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "white",
    }
    grade_colors = {"confirmed": "green", "likely": "yellow", "possible": "dim"}
    for f in findings:
        c = colors.get(f.severity, "white")
        title = escape(f.title)
        grade = ""
        ev = f.evidence
        if ev is not None:
            g = grade_colors.get(ev.grade, "dim")
            grade = f"[{g}]{escape(ev.grade)}[/{g}]"
            if sum(1 for s in ev.path if s.role != "elided") > 1:
                title += f"\n[dim]{escape(compact_path(ev))}[/dim]"
        table.add_row(
            f"[{c}]{f.severity.label}[/{c}]",
            str(f.risk_score()),
            grade,
            title,
            escape(f.location.as_ref()),
            escape(f.rule_id),
        )
    console.print(table)
    if any(f.evidence is not None for f in findings):
        console.print(
            "[dim]Grade: confirmed (proved), likely (traced or exact match), possible "
            "(heuristic). Full evidence and verify steps: -f html, markdown, json or sarif.[/dim]"
        )


def print_posture(result: ScanResult, fail_on: Severity | None) -> None:
    """The security posture panel printed after the table report."""
    from rich.panel import Panel

    from nephilex.reporting.posture import evaluate_posture, render_posture_panel

    summary = evaluate_posture(result, fail_on)
    border = {
        "pass": "green",
        "clean": "green",
        "review": "yellow",
        "fail": "red",
    }[summary.status.value]
    console.print(
        Panel(
            render_posture_panel(summary),
            title="Security posture",
            border_style=border,
        )
    )


def print_fix_outcome(outcome: FixOutcome, *, open_pr: bool, dry_run: bool) -> None:
    """Summarize what ``nephilex fix`` applied, committed or opened."""
    from rich.panel import Panel
    from rich.table import Table

    report = outcome.applied
    if outcome.verification is not None and outcome.verification.fixes:
        _print_tested_fixes(outcome)
    elif report.fixes:
        table = Table(title="Fixes" + (" (dry run)" if dry_run else ""))
        table.add_column("File", style="bold")
        table.add_column("Line", justify="right")
        table.add_column("Rule", style="dim")
        table.add_column("Verified", justify="center")
        for f in report.fixes:
            table.add_row(
                escape(f.path),
                str(f.line),
                escape(f.rule_id),
                "[green]yes[/green]" if f.verified else "[yellow]no[/yellow]",
            )
        console.print(table)
    else:
        console.print("[yellow]No deterministic fixes were applicable to these findings.[/yellow]")

    for msg in outcome.messages:
        console.print(f"[dim]- {escape(msg)}[/dim]")

    if outcome.pull_request:
        console.print(
            Panel(
                f"[green]Pull request opened:[/green]\n{outcome.pull_request.url}",
                border_style="green",
            )
        )
    elif outcome.committed and not open_pr:
        console.print(
            "[green]Fixes committed to the branch.[/green] "
            "Add --open-pr to push and open a pull request."
        )

    if outcome.error:
        err_console.print(f"[red]Stopped:[/red] {escape(outcome.error)}")


def _print_tested_fixes(outcome: FixOutcome) -> None:
    """The fix table with each fix's test result (``--verify-with-tests``)."""
    from rich.table import Table

    from nephilex.remediation.testverify import TEST_STATUS_LABELS

    verification = outcome.verification
    assert verification is not None
    committed = {f.finding_id for f in outcome.applied.fixes} if outcome.committed else set()
    colors = {"passed": "green", "failed": "red", "not_verified": "yellow"}
    table = Table(title="Fixes (verified with tests)")
    table.add_column("File", style="bold")
    table.add_column("Line", justify="right")
    table.add_column("Rule", style="dim")
    table.add_column("Rule check", justify="center")
    table.add_column("Tests", justify="center")
    table.add_column("Committed", justify="center")
    table.add_column("Why not", style="dim")
    for f in verification.fixes:
        status = f.tests or "not_verified"
        color = colors.get(status, "yellow")
        table.add_row(
            escape(f.path),
            str(f.line),
            escape(f.rule_id),
            "[green]yes[/green]" if f.verified else "[yellow]no[/yellow]",
            f"[{color}]{TEST_STATUS_LABELS.get(status, status)}[/{color}]",
            "yes" if f.finding_id in committed else "no",
            "" if status == "passed" else escape(f.tests_reason),
        )
    console.print(table)
    counts = verification.counts()
    console.print(
        f"Tests: {counts['passed']} passed, {counts['failed']} failed, "
        f"{counts['not_verified']} could not verify. Only fixes whose tests passed "
        "are committed."
    )
