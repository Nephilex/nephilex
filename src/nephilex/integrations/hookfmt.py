"""Compact finding output for editors and AI agents, and editor hook protocols.

``nephilex check --format hook`` prints one line per finding::

    app.py:12:5: error high patterns.python-yaml-load: Unsafe YAML load. Fix: Use yaml.safe_load.

The shape is ``path:line:column: level severity rule-id: title. Fix: hint``,
where ``level`` is ``error`` (critical, high), ``warning`` (medium) or
``info`` (low, info) so a VS Code problem matcher can read it, and the path is
relative to the project root. Every line is plain ASCII-safe text with no
markup: newlines and control characters in titles are collapsed.

``nephilex check --hook claude|cursor`` reads the hook event an editor writes to
stdin, checks the edited file, and answers in that editor's protocol (see
:func:`claude_response`).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from nephilex.core.models import Finding, Severity, counts_toward_gate

EDITORS = ("claude", "cursor")

#: Parses one hook line. Groups: 1 path, 2 line, 3 column, 4 level, 5 severity,
#: 6 rule id, 7 message. The VS Code problem matcher uses this expression.
HOOK_LINE_REGEXP = r"^(.+?):(\d+):(\d+): (error|warning|info) (\S+) (\S+): (.*)$"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}

_SPACE = re.compile(r"[\s\x00-\x1f\x7f]+")
_TITLE_LIMIT = 160
_FIX_LIMIT = 200


def one_line(text: str, limit: int) -> str:
    """Collapse whitespace and control characters; cut to ``limit`` chars."""
    flat = _SPACE.sub(" ", text or "").strip()
    if len(flat) > limit:
        flat = flat[: limit - 3].rstrip() + "..."
    return flat


def fix_hint(finding: Finding) -> str:
    """The one-line fix for a finding: its remediation summary, else its docs."""
    if finding.remediation is not None and finding.remediation.summary.strip():
        return one_line(finding.remediation.summary, _FIX_LIMIT)
    return f"see {finding.docs_url}"


def severity_name(severity: Severity) -> str:
    return severity.name.lower()


def hook_line(finding: Finding) -> str:
    """One finding as a single ``path:line:col: level severity rule: msg`` line."""
    loc = finding.location
    title = one_line(finding.title, _TITLE_LIMIT).rstrip(".")
    fix = fix_hint(finding).rstrip(".")
    return (
        f"{loc.path}:{loc.start_line or 1}:{loc.start_column or 1}: "
        f"{_LEVEL[finding.severity]} {severity_name(finding.severity)} "
        f"{finding.rule_id}: {title}. Fix: {fix}."
    )


def hook_lines(findings: Iterable[Finding]) -> list[str]:
    return [hook_line(f) for f in findings]


# --- editor hook events ------------------------------------------------------
def event_paths(editor: str, event: Mapping[str, Any]) -> list[str]:
    """The file paths an editor hook event says were just written.

    Claude Code (PostToolUse): ``tool_input.file_path`` for Write and Edit,
    ``tool_input.notebook_path`` for notebook edits, with
    ``tool_response.filePath`` as a fallback. Cursor (afterFileEdit):
    ``file_path``. Anything that is not a non-empty string is ignored.
    """
    candidates: list[object] = []
    if editor == "claude":
        tool_input = event.get("tool_input")
        if isinstance(tool_input, Mapping):
            candidates += [tool_input.get("file_path"), tool_input.get("notebook_path")]
        response = event.get("tool_response")
        if isinstance(response, Mapping):
            candidates.append(response.get("filePath"))
    elif editor == "cursor":
        candidates.append(event.get("file_path"))
    out: list[str] = []
    for c in candidates:
        if isinstance(c, str) and c.strip() and c not in out:
            out.append(c)
    return out[:1] if editor == "claude" else out


def event_root(
    editor: str, event: Mapping[str, Any], env: Mapping[str, str] | None = None
) -> Path | None:
    """The project directory the editor reports for a hook event, if any.

    Claude Code sets ``CLAUDE_PROJECT_DIR`` for hooks; Cursor sends
    ``workspace_roots``. The caller still confines the checked file to the
    project root it derives from this.
    """
    env = os.environ if env is None else env
    if editor == "claude":
        project_dir = env.get("CLAUDE_PROJECT_DIR")
        if project_dir:
            return Path(project_dir)
        cwd = event.get("cwd")
        return Path(cwd) if isinstance(cwd, str) and cwd else None
    if editor == "cursor":
        roots = event.get("workspace_roots")
        if isinstance(roots, list) and roots and isinstance(roots[0], str) and roots[0]:
            return Path(roots[0])
    return None


def claude_response(findings: list[Finding], fail_on: Severity) -> dict[str, Any] | None:
    """The PostToolUse JSON answer for Claude Code, or None for no output.

    Findings at or above ``fail_on`` use ``decision: "block"`` with a
    ``reason``: the edit has already happened, and Claude Code shows the
    reason to Claude next to the tool result so it fixes the code. Findings
    below the threshold only add context. No findings means no output.
    """
    if not findings:
        return None
    blocking = [f for f in findings if f.severity >= fail_on and counts_toward_gate(f)]
    lines = hook_lines(findings)
    if blocking:
        head = (
            f"Nephilex found {len(blocking)} security issue(s) at or above "
            f"{severity_name(fail_on)} in the file just edited. Fix them before "
            "continuing, then the check runs again on the next edit:"
        )
        return {"decision": "block", "reason": "\n".join([head, *lines])}
    head = (
        f"Nephilex found {len(findings)} lower-severity security note(s) in the file just edited:"
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n".join([head, *lines]),
        }
    }
