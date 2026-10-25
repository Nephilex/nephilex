"""A minimal MCP (Model Context Protocol) stdio server exposing Nephilex as tools.

AI coding agents increasingly run scanners automatically after they generate
code. This server lets an agent call Nephilex over MCP, so "scan what you just wrote"
becomes a single tool call: ``nephilex_scan`` for a directory, the fast
``nephilex_check_files`` / ``nephilex_check_snippet`` for just-written code,
``nephilex_check_package`` before adding a dependency and ``nephilex_fix`` for a
verified fix as a diff (see :mod:`nephilex.mcp.tools` and
:mod:`nephilex.mcp.packages`). It speaks JSON-RPC 2.0 over newline-delimited stdio
and implements the handful of methods a client needs (``initialize``,
``tools/list``, ``tools/call``), with no external SDK, so it stays dependency-light
and works offline like the rest of Nephilex.

The dispatch is a pure function (:func:`handle_request`) so it is fully testable
without touching real stdio.

The agent calling the tools is not fully trusted (it may be acting on prompt
injection), so the tools only read paths inside the server's working directory
or the directories listed in ``NEPHILEX_MCP_ROOTS`` (``os.pathsep``-separated),
never honour rules or suppressions shipped inside the scanned tree, never
write to the project, and give up after ``NEPHILEX_MCP_SCAN_TIMEOUT`` seconds
(default 600).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from nephilex import __version__

# A protocol version we implement; we echo the client's requested version when it
# sends one, which is what interoperable MCP servers do.
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "nephilex", "version": __version__}

# Cap on findings returned in one tool call, so a huge scan does not overwhelm an
# agent's context. The summary always reports the true total and whether the list
# was truncated, so coverage is never silently hidden.
_MAX_FINDINGS = 200

ROOTS_ENV = "NEPHILEX_MCP_ROOTS"
TIMEOUT_ENV = "NEPHILEX_MCP_SCAN_TIMEOUT"
_DEFAULT_TIMEOUT = 600.0

_SEVERITY_ARG = {
    "type": "string",
    "enum": ["info", "low", "medium", "high", "critical"],
    "description": "Only return findings at or above this severity.",
    "default": "low",
}


def _annotations(title: str, *, open_world: bool) -> dict[str, Any]:
    """MCP tool annotations (protocol 2025-03-26 and later; older clients ignore them).

    Every Nephilex tool is read-only: none writes to the project or applies a fix.
    """
    return {
        "title": title,
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": open_world,
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "nephilex_scan",
        "title": "Scan a directory",
        "annotations": _annotations("Scan a directory", open_world=True),
        "description": (
            "Scan a local path for security vulnerabilities across code (SAST + "
            "taint), dependencies (CVEs), secrets, infrastructure-as-code, and "
            "LLM/AI usage (OWASP Top 10 for LLM Apps). Returns findings with "
            "severity, CWE/OWASP mapping, location, remediation, and evidence (a "
            "grade, the source-to-sink path and steps to verify the finding). "
            "Read-only: it never modifies the scanned files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Local directory or file to scan. Must be inside the "
                        "server's working directory (or NEPHILEX_MCP_ROOTS)."
                    ),
                },
                "min_severity": _SEVERITY_ARG,
            },
            "required": ["path"],
        },
    },
    {
        "name": "nephilex_check_files",
        "title": "Check edited files",
        "annotations": _annotations("Check edited files", open_world=False),
        "description": (
            "Fast security check of specific files, meant to run after you write or "
            "edit them. Runs only the file-local scanners (secrets, SAST patterns, "
            "AST taint, IaC, LLM/AI usage, malware) with no network access. Returns "
            "findings with an id, severity, file:line, rule id and a one-line fix; "
            "pass an id to nephilex_fix for a verified fix when fix_available is true. "
            "Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 100,
                    "description": (
                        "Files to check, absolute or relative to the project root. "
                        "Must be inside the server's working directory (or "
                        "NEPHILEX_MCP_ROOTS)."
                    ),
                },
                "min_severity": _SEVERITY_ARG,
            },
            "required": ["paths"],
        },
    },
    {
        "name": "nephilex_check_snippet",
        "title": "Check a code snippet",
        "annotations": _annotations("Check a code snippet", open_world=False),
        "description": (
            "Security check of code text before it is written anywhere. The code is "
            "scanned in a private temporary directory, never in the project, with the "
            "same file-local scanners as nephilex_check_files. Give a filename hint (for "
            "example app.py or .github/workflows/ci.yml) or a language. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The source text to check."},
                "filename": {
                    "type": "string",
                    "description": "File name hint; picks the scanners and rules.",
                },
                "language": {
                    "type": "string",
                    "description": "Language, used when no filename is given (e.g. python).",
                },
                "min_severity": _SEVERITY_ARG,
            },
            "required": ["code"],
        },
    },
    {
        "name": "nephilex_check_package",
        "title": "Check a dependency",
        "annotations": _annotations("Check a dependency", open_world=True),
        "description": (
            "Before adding a dependency, check it: known-malicious package intel, "
            "typosquat resemblance to popular packages, known vulnerabilities for the "
            "given version (OSV), and whether the name exists on the registry (npm, "
            "PyPI, crates.io); a name that does not exist may be hallucinated. Uses "
            "the network unless the server runs with NEPHILEX_MCP_OFFLINE=1; checks that "
            "cannot run report unknown. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "description": "npm, PyPI, crates.io, Go, Maven, RubyGems, NuGet or Packagist.",
                },
                "name": {"type": "string", "description": "Package name."},
                "version": {
                    "type": "string",
                    "description": "Exact version, for the vulnerability lookup.",
                },
            },
            "required": ["ecosystem", "name"],
        },
    },
    {
        "name": "nephilex_fix",
        "title": "Get a verified fix",
        "annotations": _annotations("Get a verified fix", open_world=False),
        "description": (
            "For a finding id returned by nephilex_check_files or nephilex_check_snippet, "
            "return Nephilex's deterministic fix as a unified diff when one exists and "
            "verifies (the rule no longer fires on the fixed line and the file still "
            "parses). Never applies the fix: review the diff and apply it yourself."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "The id of a finding from a previous check.",
                },
            },
            "required": ["finding_id"],
        },
    },
]


# --- JSON-RPC helpers ------------------------------------------------------
def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tool_text(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _tool_json(payload: dict[str, Any]) -> dict[str, Any]:
    """A tool result as structured content plus the same JSON as text.

    ``structuredContent`` is the 2025-06-18 form; the text block keeps older
    clients working, as the specification recommends.
    """
    result = _tool_text(json.dumps(payload, indent=2))
    result["structuredContent"] = payload
    return result


# --- the scan tool ---------------------------------------------------------
def allowed_roots() -> list[Path]:
    """Directories the tool may scan: NEPHILEX_MCP_ROOTS, else the working directory."""
    raw = os.environ.get(ROOTS_ENV, "")
    roots = [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]
    return [r.resolve() for r in (roots or [Path.cwd()])]


def resolve_scan_path(path: str) -> Path:
    """Resolve ``path`` and confine it to the roots.

    A relative path is taken relative to the first allowed root (the working
    directory unless ``NEPHILEX_MCP_ROOTS`` is set), so a client that starts the
    server somewhere else can still pass project-relative paths. Symlinks and
    ``..`` are resolved first, so neither can step outside.
    """
    roots = allowed_roots()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    resolved = candidate.resolve()
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        shown = ", ".join(str(r) for r in roots)
        raise ValueError(
            f"path {path!r} is outside the allowed roots ({shown}); "
            f"set {ROOTS_ENV} to allow other directories"
        )
    if not resolved.exists():
        raise ValueError(f"path {path!r} does not exist")
    return resolved


def _scan_timeout() -> float:
    try:
        return max(1.0, float(os.environ.get(TIMEOUT_ENV, _DEFAULT_TIMEOUT)))
    except ValueError:
        return _DEFAULT_TIMEOUT


def _run_with_timeout(fn: Any, timeout: float) -> Any:
    """Run ``fn`` in a daemon thread; raise TimeoutError if it overruns.

    The scan cannot be interrupted, so it keeps running in the background, but
    the client gets an answer and the server keeps serving requests.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # re-raised in the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=target, name="nephilex-mcp-scan", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError(f"scan did not finish within {timeout:g}s ({TIMEOUT_ENV})")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _run_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a scan and return a compact, structured result for an agent."""
    from nephilex.core.config import Config
    from nephilex.core.engine import ScanEngine
    from nephilex.core.models import Severity
    from nephilex.core.project import Project
    from nephilex.plugins import register_builtins

    path = arguments.get("path")
    if not path or not isinstance(path, str):
        raise ValueError("'path' (a local directory or file) is required")
    target = resolve_scan_path(path)

    register_builtins()
    min_sev = Severity.parse(str(arguments.get("min_severity", "low")))
    cfg = Config(min_severity=min_sev)
    # The scanned tree may be untrusted (the agent may have just cloned it), so
    # in-repo extension points such as .nephilex/rules are not honoured.
    cfg.trust_project_config = False
    result = _run_with_timeout(
        lambda: ScanEngine(cfg).scan(Project.from_path(target)),
        _scan_timeout(),
    )

    findings = result.sorted_findings()
    shown = findings[:_MAX_FINDINGS]
    return {
        "target": result.target,
        "summary": {
            "total_findings": len(findings),
            "returned": len(shown),
            "truncated": len(findings) > _MAX_FINDINGS,
            "by_severity": result.counts_by_severity(),
            "risk_score": result.aggregate_risk(),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "scanner": f.scanner,
                "severity": f.severity.label,
                "title": f.title,
                "location": f.location.as_ref(),
                "cwe": f.cwe,
                "owasp": f.owasp,
                "remediation": f.remediation.summary if f.remediation else "",
                "evidence": evidence_dict(f),
            }
            for f in shown
        ],
    }


def evidence_dict(f: Any) -> dict[str, Any] | None:
    """A finding's evidence for an agent: grade, basis, path steps and how to verify.

    The code and notes quote the scanned (possibly hostile) repository; they
    are reduced to single lines with control characters escaped and secrets
    masked, and are data for the agent to read, not instructions.
    """
    ev = f.evidence
    if ev is None:
        return None
    return {
        "grade": ev.grade,
        "basis": ev.basis,
        "path": [
            {"path": s.path, "line": s.line, "role": s.role, "code": s.code, "note": s.note}
            for s in ev.path
        ],
        "verify": list(ev.verify),
    }


# --- dispatch --------------------------------------------------------------
ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


def _handlers() -> dict[str, tuple[str, ToolFn]]:
    """Tool name -> (verb for error messages, implementation)."""
    from nephilex.mcp import packages, tools

    return {
        "nephilex_scan": ("Scan", _run_scan),
        "nephilex_check_files": ("Check", tools.check_files),
        "nephilex_check_snippet": ("Check", tools.check_snippet),
        "nephilex_check_package": ("Package check", packages.check_package),
        "nephilex_fix": ("Fix", tools.fix),
    }


def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC request. Returns a response dict, or None for a
    notification (which has no id and expects no reply)."""
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        params = req.get("params") or {}
        return _ok(
            req_id,
            {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "tools/list":
        return _ok(req_id, {"tools": TOOLS})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        handler = _handlers().get(name) if isinstance(name, str) else None
        if handler is None:
            return _ok(req_id, _tool_text(f"Unknown tool: {name!r}", is_error=True))
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _ok(req_id, _tool_text("Tool arguments must be an object", is_error=True))
        verb, fn = handler
        try:
            if name == "nephilex_scan":
                payload = fn(arguments)  # applies the timeout around the scan itself
            else:
                payload = _run_with_timeout(lambda: fn(arguments), _scan_timeout())
        except Exception as exc:  # tool errors are reported in-band, not as protocol errors
            return _ok(req_id, _tool_text(f"{verb} failed: {exc}", is_error=True))
        return _ok(req_id, _tool_json(payload))

    # Notifications (e.g. notifications/initialized) carry no id and get no reply.
    if req_id is None:
        return None
    return _err(req_id, -32601, f"Method not found: {method}")


def _force_utf8(stream: Any, **kwargs: str) -> None:
    """MCP is UTF-8 JSON; on Windows the console default (e.g. cp1252) mangles it."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    with contextlib.suppress(ValueError, OSError):
        reconfigure(encoding="utf-8", **kwargs)


def run_stdio(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Serve MCP over newline-delimited JSON-RPC on stdio until EOF."""
    if stdin is None:
        stdin = sys.stdin
        _force_utf8(stdin, errors="replace")
    if stdout is None:
        stdout = sys.stdout
        _force_utf8(stdout, newline="\n")
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue  # ignore a malformed line rather than crash the server
        if not isinstance(req, dict):
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
