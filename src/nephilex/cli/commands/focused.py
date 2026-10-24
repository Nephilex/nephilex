"""Focused scans: one area of security with a short JSON or table summary.

``secrets``, ``iac``, ``api``, ``cicd``, ``container``, ``cloud`` and
``infrastructure`` each run a fixed subset of scanners with AI enrichment off.
"""

from __future__ import annotations

from pathlib import Path

import typer

from nephilex.cli._common import (
    cli_severity,
    fail_on_scanner_errors,
    progress_printer,
    resolve_project,
)
from nephilex.cli._console import console, err_console
from nephilex.core.config import load_project_config


def focused_scan(
    target: str,
    scanners: list[str],
    *,
    output: Path | None = None,
    fail_on: str | None = None,
    quiet: bool = False,
    title: str = "Findings",
    config: Path | None = None,
) -> None:
    """Run a subset of scanners and print or write a JSON summary."""
    import json

    from nephilex.core.engine import ScanEngine

    threshold = cli_severity(fail_on, "--fail-on") if fail_on else None
    resolved, project = resolve_project(target, "requires a source repository or local path.")

    try:
        cfg = load_project_config(project, config)
        cfg.ai.enabled = False
        cfg.scanners = scanners
        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)

        payload = {
            "scanners": scanners,
            "errors": result.errors,
            "findings": len(result.findings),
            "highest_severity": result.highest_severity().label,
            "items": [
                {
                    "rule": f.rule_id,
                    "severity": f.severity.label,
                    "title": f.title,
                    "location": f.location.as_ref(),
                }
                for f in result.sorted_findings()
            ],
        }

        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Report:[/green] {output} ({len(result.findings)} finding(s))")
        elif not quiet:
            from rich.table import Table

            table = Table(title=title)
            table.add_column("Severity")
            table.add_column("Rule")
            table.add_column("Title")
            table.add_column("Location")
            for f in result.sorted_findings()[:50]:
                table.add_row(
                    f.severity.label,
                    f.rule_id,
                    f.title[:50],
                    f.location.as_ref(),
                )
            console.print(table)
            if len(result.findings) > 50:
                err_console.print(f"[dim]… and {len(result.findings) - 50} more[/dim]")
            elif not result.findings and not result.errors:
                console.print("[green]No findings.[/green]")

        fail_on_scanner_errors(result, cfg, gating=threshold is not None)
        if threshold is not None and result.gating_severity() >= threshold:
            raise typer.Exit(1)
    finally:
        resolved.cleanup()


def secrets(
    target: str = typer.Argument(".", help="Local path or git URL."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Run secret detection only (source, config, and optional git history via scan flags)."""
    focused_scan(
        target,
        ["secrets"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="Secret findings",
        config=config,
    )


def iac(
    target: str = typer.Argument(".", help="Local path or git URL."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Run infrastructure-as-code security checks (Terraform, K8s, CloudFormation)."""
    focused_scan(
        target,
        ["iac", "cloud"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="IaC findings",
        config=config,
    )


def api_scan(
    target: str = typer.Argument(".", help="Local path or git URL with OpenAPI specs."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Analyze OpenAPI/REST API definitions for auth and exposure issues."""
    focused_scan(
        target,
        ["api", "authz"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="API security findings",
        config=config,
    )


def cicd(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero on findings at/above severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .nephilex.yml path."),
) -> None:
    """Scan CI/CD workflows for risky patterns (GitHub Actions, GitLab CI, Jenkinsfile)."""
    focused_scan(
        target,
        ["cicd"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="CI/CD findings",
        config=config,
    )


def container(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero on findings at/above severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .nephilex.yml path."),
) -> None:
    """Scan Dockerfiles, Compose files, and container runtime settings."""
    focused_scan(
        target,
        ["container", "iac"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="Container findings",
        config=config,
    )


def cloud(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero on findings at/above severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .nephilex.yml path."),
) -> None:
    """Scan Terraform and CloudFormation for risky AWS, Azure, and GCP patterns."""
    focused_scan(
        target,
        ["cloud", "iac"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="Cloud configuration findings",
        config=config,
    )


def infrastructure(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON report."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero on findings at/above severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .nephilex.yml path."),
) -> None:
    """Run all infrastructure scanners: CI/CD, containers, cloud, and IaC."""
    focused_scan(
        target,
        ["cicd", "container", "cloud", "iac"],
        output=output,
        fail_on=fail_on,
        quiet=quiet,
        title="Infrastructure findings",
        config=config,
    )
