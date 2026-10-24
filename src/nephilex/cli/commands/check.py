"""``nephilex check``: a fast, file-level check for the files just edited.

This is what an editor task or an AI-assistant hook runs after each edit. It
scans only the given files, with only the file-local scanners, using the
scan cache, without network access and without AI enrichment (``--ai`` opts
in). See :mod:`nephilex.integrations.filecheck`.

Exit status: 0 when nothing is at or above ``--fail-on`` (default high), 1
when something is (or a scanner crashed, unless ``fail_on_error: false``), 2
for usage errors, including a path outside the project. With ``--hook`` the
command speaks the editor's hook protocol instead; see :func:`_run_hook`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape

from nephilex.cli._common import cli_severity
from nephilex.cli._console import console, err_console
from nephilex.cli.output import print_scanner_failure, write_stdout
from nephilex.core.config import Config, ConfigError, load_project_config
from nephilex.core.models import ScanResult, Severity, counts_toward_gate
from nephilex.core.project import Project

_FORMATS = ("text", "json", "hook")
# A hook event is a small JSON object; never read an unbounded stdin.
_MAX_EVENT_BYTES = 1_000_000


def check(
    paths: list[str] = typer.Argument(
        None, help="Files to check. Must be inside the project root.", show_default=False
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="text (default), json (the `nephilex scan -f json` schema) or hook "
        "(one line per finding: path:line:col: level severity rule: message).",
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Exit 1 if any finding is at/above this severity."
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Report findings at/above this severity."
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a .nephilex.yml config file."
    ),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Project root. Default: the nearest directory at or above the "
        "current one that holds .git or .nephilex.yml.",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Do not reuse cached findings."),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enrich findings with the configured AI provider (off by default; "
        "a remote provider uses the network).",
    ),
    hook: str | None = typer.Option(
        None,
        "--hook",
        help="Read a claude or cursor hook event from stdin, check the edited "
        "file and answer in that editor's hook protocol (see docs/editors.md).",
    ),
    no_inline_ignores: bool = typer.Option(
        False,
        "--no-inline-ignores",
        help="Report findings even where a nephilex-ignore comment suppresses them. "
        "The hooks written by `nephilex init --editor` use it, so an AI assistant "
        "cannot silence a finding by adding a comment.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="No notes on stderr."),
) -> None:
    """Check just the given files, fast (for editors and AI-assistant hooks)."""
    fmt = fmt.strip().lower()
    if fmt not in _FORMATS:
        raise typer.BadParameter(f"choose from: {', '.join(_FORMATS)}", param_hint="--format")
    threshold = cli_severity(fail_on, "--fail-on")
    floor = cli_severity(min_severity, "--min-severity") if min_severity else None

    if hook is not None:
        editor = hook.strip().lower()
        from nephilex.integrations.hookfmt import EDITORS

        if editor not in EDITORS:
            raise typer.BadParameter(f"choose from: {', '.join(EDITORS)}", param_hint="--hook")
        raise typer.Exit(
            _run_hook(
                editor,
                threshold=threshold,
                floor=floor,
                config=config,
                root=root,
                no_cache=no_cache,
                ai=ai,
                inline_ignores=not no_inline_ignores,
                quiet=quiet,
            )
        )

    if not paths:
        err_console.print("[red]Error:[/red] give at least one file to check.")
        raise typer.Exit(2)

    from nephilex.integrations.filecheck import find_project_root, run_check, select_files

    project_root = _project_root(root, find_project_root(Path.cwd()))
    cfg = _config(
        project_root,
        config,
        threshold=threshold,
        floor=floor,
        no_cache=no_cache,
        ai=ai,
        inline_ignores=not no_inline_ignores,
    )
    files, skipped = select_files(project_root, paths, exclude_paths=cfg.exclude_paths)
    refused = [s for s in skipped if s.refused]
    if refused:
        for s in refused:
            err_console.print(f"[red]Error:[/red] {escape(s.path)}: {escape(s.reason)}")
        raise typer.Exit(2)
    if not quiet:
        for s in skipped:
            err_console.print(f"[dim]- Skipping {escape(s.path)}: {escape(s.reason)}[/dim]")

    result = run_check(project_root, files, cfg)
    result.project_summary["check"] = {
        "files": [f.rel_path for f in files],
        "skipped": [s.to_dict() for s in skipped],
        "fail_on": threshold.name.lower(),
    }

    if fmt == "json":
        from nephilex.reporting.json_reporter import JSONReporter

        write_stdout(JSONReporter().render(result))
    elif fmt == "hook":
        from nephilex.integrations.hookfmt import hook_lines

        lines = hook_lines(result.findings)
        if lines:
            write_stdout("\n".join(lines))
    else:
        _print_text(result, len(files), threshold)

    if result.errors and cfg.errors_fail_gate(True):
        print_scanner_failure(result)
        raise typer.Exit(1)
    if any(f.severity >= threshold and counts_toward_gate(f) for f in result.findings):
        raise typer.Exit(1)


def _project_root(option: Path | None, detected: Path) -> Path:
    if option is None:
        return detected
    resolved = option.expanduser().resolve()
    if not resolved.is_dir():
        err_console.print(f"[red]Error:[/red] --root {escape(str(option))} is not a directory.")
        raise typer.Exit(2)
    return resolved


def _config(
    root: Path,
    explicit: Path | None,
    *,
    threshold: Severity,
    floor: Severity | None,
    no_cache: bool,
    ai: bool,
    inline_ignores: bool = True,
) -> Config:
    """The project config (trusted, as for ``nephilex scan`` on a local path),
    narrowed to a file-level check."""
    from nephilex.integrations.filecheck import check_config

    base = load_project_config(Project(root=root, name=root.name), explicit)
    cfg = check_config(base, ai=ai, cache=not no_cache)
    cfg.inline_ignores = inline_ignores
    cfg.fail_on = threshold
    if floor is not None:
        cfg.min_severity = floor
    return cfg


def _print_text(result: ScanResult, file_count: int, threshold: Severity) -> None:
    from nephilex.integrations.hookfmt import fix_hint, severity_name

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]Scanner failed:[/yellow] {escape(err)}")
    findings = result.findings
    for f in findings:
        console.print(
            f"{escape(f.location.as_ref())}  [bold]{severity_name(f.severity)}[/bold]  "
            f"{escape(f.rule_id)}  {escape(f.title)}",
            soft_wrap=True,
        )
        console.print(f"    Fix: {escape(fix_hint(f))}", soft_wrap=True)
    noun = "file" if file_count == 1 else "files"
    if not findings:
        console.print(f"No findings in {file_count} {noun}.")
        return
    counts = ", ".join(
        f"{n} {label.lower()}" for label, n in result.counts_by_severity().items() if n
    )
    gated = sum(1 for f in findings if f.severity >= threshold and counts_toward_gate(f))
    console.print(
        f"{len(findings)} finding(s) in {file_count} {noun} ({counts}); "
        f"{gated} at or above {severity_name(threshold)}."
    )


# --- editor hook protocol ----------------------------------------------------
def _run_hook(
    editor: str,
    *,
    threshold: Severity,
    floor: Severity | None,
    config: Path | None,
    root: Path | None,
    no_cache: bool,
    ai: bool,
    inline_ignores: bool,
    quiet: bool,
) -> int:
    """Answer one editor hook event; returns the exit status.

    The editor runs this after every file write, including writes outside
    the project and deletions, so those are not errors: nothing is printed
    and the status is 0. Problems with Nephilex itself (bad event, bad config)
    exit 1, which both Claude Code and Cursor treat as a non-blocking hook
    error, never 2 (which Claude Code would hand to the model as feedback).

    * claude: PostToolUse JSON on stdout (``decision: "block"`` with a
      ``reason`` for findings at/above ``--fail-on``, ``additionalContext``
      for lower ones), exit 0.
    * cursor: afterFileEdit has no output the agent reads, so the finding
      lines go to stderr (the Hooks output channel), ``{}`` to stdout, exit 0.
    """
    from nephilex.integrations.filecheck import find_project_root, run_check, select_files
    from nephilex.integrations.hookfmt import claude_response, event_paths, event_root, hook_lines

    try:
        raw = sys.stdin.read(_MAX_EVENT_BYTES + 1)
    except (OSError, ValueError) as exc:
        err_console.print(f"nephilex check --hook: cannot read the hook event: {escape(str(exc))}")
        return 1
    if len(raw) > _MAX_EVENT_BYTES:
        err_console.print("nephilex check --hook: the hook event is too large.")
        return 1
    try:
        event: Any = json.loads(raw) if raw.strip() else {}
    except ValueError:
        err_console.print("nephilex check --hook: the hook event on stdin is not JSON.")
        return 1
    if not isinstance(event, dict):
        err_console.print("nephilex check --hook: the hook event is not a JSON object.")
        return 1

    paths = event_paths(editor, event)
    if not paths:
        return _hook_done(editor)
    if root is not None:
        project_root = root.expanduser().resolve()
    else:
        project_root = find_project_root(event_root(editor, event) or Path.cwd())
    try:
        cfg = _config(
            project_root,
            config,
            threshold=threshold,
            floor=floor,
            no_cache=no_cache,
            ai=ai,
            inline_ignores=inline_ignores,
        )
    except ConfigError as exc:
        err_console.print(f"nephilex check --hook: configuration error: {escape(str(exc))}")
        return 1
    files, skipped = select_files(project_root, paths, exclude_paths=cfg.exclude_paths)
    if not quiet:
        for s in skipped:
            err_console.print(f"nephilex: not checking {escape(s.path)}: {escape(s.reason)}")
    result = run_check(project_root, files, cfg)
    for err in result.errors:
        err_console.print(f"nephilex: scanner failed: {escape(err)}")

    lines = hook_lines(result.findings)
    if editor == "claude":
        response = claude_response(result.findings, threshold)
        if response is not None:
            write_stdout(json.dumps(response))
            return 0
        return 1 if result.errors else 0
    for line in lines:
        err_console.print(escape(line), soft_wrap=True, highlight=False)
    return _hook_done(editor)


def _hook_done(editor: str) -> int:
    if editor == "cursor":
        write_stdout("{}")
    return 0
