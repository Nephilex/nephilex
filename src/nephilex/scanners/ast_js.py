"""AST-based taint analysis for JavaScript and TypeScript.

The regex tier's JS rules (``.innerHTML =``, SQL-ish concatenation) fire on the
*shape* of the code and can't tell tainted input from safe values, the classic
source of false positives on real Node/TS apps. This scanner parses JS/TS/TSX
with tree-sitter and tracks untrusted input through assignments, destructuring,
template literals, closures and calls to functions defined in the same file into
sinks, so it flags an issue only when tainted data actually reaches one. The
engine is :mod:`nephilex.scanners._jsflow`.

Precision decisions that matter on real code:

* **Parameterized queries are safe.** For SQL sinks only the *first* argument (the
  query text) is checked. ``db.query('... WHERE id = ?', [userId])`` is NOT
  flagged, the taint is in the bound-parameters array, not the query string.
* **Sanitizers clear only what they protect against.** HTML escaping clears
  XSS but not SQL; ``path.basename`` clears path traversal; ``shell-quote``
  clears command injection; numeric coercion clears everything.
* **Guards count.** A block that returns or throws when an allowlist, regex or
  containment check fails clears the checked value after it.
* **Per-function scope** so a tainted variable in one handler doesn't leak into
  another, while nested functions see their enclosing scope.

Optional via ``pip install "nephilex[ast]"``. Without tree-sitter the scanner
reports not-applicable and Nephilex falls back to the regex tier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._jsflow import KIND_CWE, JsFlow, Report
from nephilex.scanners.ast_python import (
    analysis_skipped_finding,
    language_context,
    make_parser,
    node_location,
    run_with_context,
)
from nephilex.scanners.patterns import _is_test_file  # shared test-path helper

if TYPE_CHECKING:
    from nephilex.context import LanguageContext

# File extension -> tree-sitter language module + factory attribute.
_LANGS = {
    "javascript": ("tree_sitter_javascript", "language", {".js", ".jsx", ".mjs", ".cjs"}),
    "typescript": ("tree_sitter_typescript", "language_typescript", {".ts", ".mts", ".cts"}),
    "tsx": ("tree_sitter_typescript", "language_tsx", {".tsx"}),
}


@lru_cache(maxsize=1)
def _load_parsers():
    """Return {lang_name: Parser} for JS/TS/TSX, or None if tree-sitter is absent."""
    try:
        import importlib

        from tree_sitter import Language
    except ImportError:
        return None
    parsers = {}
    for name, (module, factory, _exts) in _LANGS.items():
        try:
            mod = importlib.import_module(module)
            lang = Language(getattr(mod, factory)())
            parsers[name] = make_parser(lang)
        except Exception:  # a missing grammar shouldn't disable the others
            continue
    return parsers or None


def is_available() -> bool:
    return _load_parsers() is not None


def _lang_for(suffix: str) -> str | None:
    for name, (_m, _f, exts) in _LANGS.items():
        if suffix in exts:
            return name
    return None


# Function-name last components that neutralize taint for HTML sinks (kept for
# reference; the engine applies them per sink kind). NB: toString() is *not* a
# sanitizer -- `userInput.toString()` still yields attacker-controlled text.
_SANITIZERS = {
    "parseInt",
    "parseFloat",
    "Number",
    "encodeURIComponent",
    "encodeURI",
    "escape",
    "sanitize",
    "escapeHtml",
    "sanitizeHtml",
    "quote",
}


_JS_PATTERNS = ("*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts")
#: Example and demo code a package ships for its readers, not as part of its runtime.
_EXAMPLE_PATH = re.compile(r"(?i)(^|/)(examples?|samples?|demos?)/")


@dataclass
class Sink:
    id: str
    #: matches the call's function text (identifier or member expression)
    fn: re.Pattern[str]
    cwe: list[str]
    owasp: list[str]
    title: str
    severity: Severity
    why: str
    attack: str
    impact: str
    fix: str
    #: which arguments to treat as the payload: "first" or "rest" (all but first)
    args: str = "first"
    references: list[str] = field(default_factory=list)


_INJECTION = ["A03:2021-Injection"]
CALL_SINKS: list[Sink] = [
    Sink(
        id="ast-sql-injection",
        fn=re.compile(r"(^|\.)(query|execute|executeQuery|raw|unsafe)$"),
        cwe=["CWE-89"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="SQL injection (tainted value concatenated into a query)",
        why="Untrusted input is built into the SQL query string, so it can change "
        "the query's structure. (Parameterized queries with bound values are "
        "not flagged.)",
        attack="Supply `' OR '1'='1` or a stacked query in the tainted parameter.",
        impact="Unauthorized data access or modification, up to full DB compromise.",
        fix="Use parameterized queries / bound placeholders (e.g. "
        "query('... WHERE id = ?', [id])) instead of string concatenation.",
    ),
    Sink(
        id="ast-command-injection",
        fn=re.compile(r"(^|\.)(exec|execSync|spawn|spawnSync|execFile|execFileSync)$"),
        cwe=["CWE-78"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="OS command injection (tainted value reaches a shell command)",
        why="Untrusted input reaches a command that child_process runs through a "
        "shell (exec/execSync, spawn with shell: true, or sh -c / cmd /c).",
        attack="Inject `; rm -rf` or `$(...)` through the tainted parameter.",
        impact="Remote code execution on the host.",
        fix="Use execFile/spawn with an argument array and no shell, and validate the "
        "value against an allowlist or a strict pattern.",
    ),
    Sink(
        id="ast-path-traversal",
        fn=re.compile(r"(^|\.)(readFile|readFileSync|createReadStream|sendFile|writeFile)$"),
        cwe=["CWE-22"],
        owasp=["A01:2021-Broken Access Control"],
        severity=Severity.MEDIUM,
        title="Path traversal (tainted value reaches a file operation)",
        why="A filesystem path built from untrusted input reaches a file API without a "
        "containment check, so `../` or an absolute path can escape the intended "
        "directory.",
        attack="Request a path such as `../../etc/passwd`, or an archive entry named "
        "`../../.ssh/authorized_keys`.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and confirm it stays within the base directory "
        "(path.resolve(base, p).startsWith(base + path.sep)), or keep only "
        "path.basename(p).",
    ),
    Sink(
        id="ast-code-injection",
        # Prefix is required (not optional): eval/Function must be the whole name
        # or a real member access (.eval). The old optional `(^|\.)?` also matched
        # names merely ending in the word -- retrieval, myFunction, medieval.
        fn=re.compile(r"(^|\.)(eval|Function)$"),
        cwe=["CWE-95"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="Code injection (tainted value reaches eval/Function/vm)",
        why="Untrusted input flows into eval, the Function constructor or a vm.run* "
        "call, which execute it as code.",
        attack="Provide a JavaScript expression in the tainted value.",
        impact="Remote code execution in the JS runtime.",
        fix="Never evaluate untrusted input; use JSON.parse or an explicit dispatch "
        "table. vm is not a security boundary.",
    ),
    Sink(
        id="ast-xss",
        fn=re.compile(r"(^|\.)(write|insertAdjacentHTML)$"),
        cwe=["CWE-79"],
        owasp=_INJECTION,
        severity=Severity.MEDIUM,
        title="Cross-site scripting (tainted value written as HTML)",
        why="Untrusted input is written to the document or the HTTP response as HTML, "
        "so an attacker's markup or script executes in the victim's browser.",
        attack="Get the app to render an attacker-controlled string containing "
        "`<script>` or an event handler.",
        impact="Session theft and actions performed as the victim.",
        fix="Use textContent, a framework-escaped binding, or escape/sanitize the value "
        "(an HTML escaper, DOMPurify) before it is written as HTML.",
        args="rest",  # insertAdjacentHTML(position, html): the payload is not first
    ),
    Sink(
        id="ast-ssrf",
        fn=re.compile(r"^(fetch|axios|got)$"),
        cwe=["CWE-918"],
        owasp=["A10:2021-Server-Side Request Forgery"],
        severity=Severity.MEDIUM,
        title="Server-side request forgery (tainted value is the request URL)",
        why="The server sends an HTTP request to a URL or host taken from untrusted "
        "input, so an attacker chooses where it connects.",
        attack="Point the URL at http://169.254.169.254/ or an internal service.",
        impact="Access to internal services and cloud metadata credentials.",
        fix="Build the URL from a fixed origin and only put encoded values in its path, "
        "or check the parsed hostname against an allowlist before the request.",
    ),
    Sink(
        id="ast-open-redirect",
        fn=re.compile(r"(^|\.)redirect$"),
        cwe=["CWE-601"],
        owasp=["A01:2021-Broken Access Control"],
        severity=Severity.MEDIUM,
        title="Open redirect (tainted value is the redirect target)",
        why="The response redirects to a location taken from untrusted input.",
        attack="Send victims a trusted link that bounces to a phishing page, or use "
        "`javascript:` in a client-side redirect.",
        impact="Phishing and token leakage through redirect chains.",
        fix="Redirect only to relative paths (starting with `/` but not `//`) or to "
        "hosts on an allowlist.",
    ),
    Sink(
        id="ast-template-injection",
        fn=re.compile(r"(^|\.)(render|compile|template|renderString)$"),
        cwe=["CWE-1336"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="Server-side template injection (tainted template source)",
        why="Untrusted input is compiled as a template, and template engines such as "
        "EJS, Pug, Handlebars, Nunjucks and lodash.template compile to JavaScript.",
        attack="Submit a template expression that reaches process or require.",
        impact="Remote code execution on the server.",
        fix="Pass user input as template data, never as the template text.",
    ),
]
_BY_ID = {s.id: s for s in CALL_SINKS}
_KIND_SINK = {
    "sql": "ast-sql-injection",
    "shell": "ast-command-injection",
    "file": "ast-path-traversal",
    "code": "ast-code-injection",
    "html": "ast-xss",
    "ssrf": "ast-ssrf",
    "redirect": "ast-open-redirect",
    "template": "ast-template-injection",
}
_PREFIX_CHECK = Sink(
    id="ast-path-prefix-check",
    fn=re.compile(""),
    cwe=["CWE-22"],
    owasp=["A01:2021-Broken Access Control"],
    severity=Severity.MEDIUM,
    title="Incomplete path containment check (startsWith without a separator)",
    why="A resolved path is checked with startsWith(baseDir) where baseDir has no "
    "trailing separator, so a sibling such as `/srv/data-evil` passes a check for "
    "`/srv/data`.",
    attack="Use a path that resolves into a sibling directory whose name starts with "
    "the base directory's name.",
    impact="Reading or writing files outside the intended directory.",
    fix="Compare against base + path.sep (and allow p === base), or use "
    "path.relative(base, p) and reject results starting with `..` or absolute ones.",
)
_AUTOESCAPE_OFF = Sink(
    id="ast-template-autoescape-off",
    fn=re.compile(""),
    cwe=["CWE-79"],
    owasp=_INJECTION,
    severity=Severity.MEDIUM,
    title="Template engine configured without HTML escaping",
    why="The template engine is set up with escaping turned off (Nunjucks "
    "`autoescape: false`, Handlebars `noEscape: true`), so every interpolated value is "
    "written as raw HTML and any user-controlled value in a template is XSS.",
    attack="Get a value containing `<script>` into any variable a template renders.",
    impact="Stored or reflected cross-site scripting across every page the engine renders.",
    fix="Keep autoescaping on and mark the few trusted HTML values safe one by one.",
)
_RULE_SPECS = {
    "ast-path-prefix-check": _PREFIX_CHECK,
    "ast-template-autoescape-off": _AUTOESCAPE_OFF,
}
_FLAVOR_NOTE = {
    "request": "",
    "dom": "",
    "archive": "",
    "env": " (an environment value or command-line argument, which the operator controls)",
    "param": " (a function parameter built into the command or code string; whoever "
    "calls this function with user input gets the injection)",
}


@scanner
class ASTJsScanner(Scanner):
    name = "ast-js"
    category = "sast"
    file_local = True
    description = (
        "Data-flow (taint) analysis for JavaScript/TypeScript via "
        "tree-sitter; multi-hop injection, XSS, SSRF and path traversal the regex "
        "tier misses. Needs the [ast] extra."
    )

    def applies_to(self, project) -> bool:
        return is_available() and bool(project.files_matching(*_JS_PATTERNS))

    def unavailable_reason(self, project) -> str | None:
        if is_available() or not project.files_matching(*_JS_PATTERNS):
            return None
        return 'needs the [ast] extra: pip install "nephilex[ast]"'

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        parsers = _load_parsers()
        if not parsers:
            return
        context = language_context(ctx, "javascript")
        source = getattr(getattr(ctx.config, "context", None), "source", "") or ""
        for f in ctx.project.files():
            lang = _lang_for(f.suffix)
            if lang is None or lang not in parsers or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            # Per-file isolation: one hostile file is skipped and noted, it does
            # not take the findings for every other file down with it.
            in_test = _is_test_file(f.rel_path)
            in_example = not in_test and bool(_EXAMPLE_PATH.search(f.rel_path))
            try:
                tree = parsers[lang].parse(src)
                findings = run_with_context(
                    lambda c, src=src, path=f.rel_path, t=in_test, e=in_example: _JsAnalyzer(
                        src, path, t, context=c, in_example=e
                    ),
                    tree.root_node,
                    f.text(),
                    context,
                    scanner_name=self.name,
                    source=source,
                )
            except Exception as exc:
                yield analysis_skipped_finding(self.name, f.rel_path, exc)
                continue
            yield from findings


class _JsAnalyzer:
    """Runs the engine on one file and turns its reports into findings."""

    def __init__(
        self,
        src: bytes,
        path: str,
        in_test: bool,
        *,
        context: LanguageContext | None = None,
        in_example: bool = False,
    ) -> None:
        self._src = src
        self._path = path
        self._in_test = in_test
        self._in_example = in_example
        self._ctx = context
        self._lines: list[bytes] | None = None

    def run(self, root) -> Iterable[Finding]:
        for report in JsFlow(self._src, root, context=self._ctx).run():
            yield self._finding(report)

    def _location(self, node) -> Location:
        if self._lines is None:  # split once per file, not once per finding
            self._lines = self._src.splitlines()
        return node_location(self._path, self._src, node, self._lines)

    def _finding(self, report: Report) -> Finding:
        sink = _RULE_SPECS[report.rule] if report.rule else _BY_ID[_KIND_SINK[report.kind]]
        line = report.node.start_point[0] + 1
        t = report.taint
        severity = sink.severity
        confidence = (
            Confidence.HIGH if t.flavor in ("request", "dom", "archive") else Confidence.MEDIUM
        )
        tags = ["sast", "ast", "taint"]
        if self._in_test or self._in_example:
            # Still reported, one severity step down and at low confidence: the code
            # is not part of what the package runs, though readers copy examples.
            severity = Severity(max(Severity.INFO, sink.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context" if self._in_test else "example-context")
        if report.rule:
            description = sink.why
            metadata: dict[str, object] = {"analysis": "configuration", "check": report.label}
        else:
            via = (
                f" through a helper call (sink on line {report.sink_line})"
                if report.sink_line != line
                else ""
            )
            description = (
                f"{t.origin[:1].upper()}{t.origin[1:]} (line {t.line}){_FLAVOR_NOTE[t.flavor]} "
                f"reaches {report.label}{via}. {sink.why}"
            )
            metadata = {
                "analysis": "taint-dataflow",
                "source": t.origin,
                "source_line": t.line,
                "source_kind": t.flavor,
                "sink": report.label,
                "sink_line": report.sink_line,
            }
        cwe = list(sink.cwe) if report.rule else [KIND_CWE[report.kind]]
        return Finding(
            id=f"{ASTJsScanner.name}:{sink.id}:{self._path}:{line}",
            rule_id=f"{ASTJsScanner.name}.{sink.id}",
            scanner=ASTJsScanner.name,
            title=sink.title,
            description=description,
            location=self._location(report.node),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.LIKELY if t.flavor in ("request", "dom") else Likelihood.POSSIBLE,
            cwe=cwe,
            owasp=sink.owasp,
            why_vulnerable=sink.why,
            attacker_perspective=sink.attack,
            business_impact=sink.impact,
            remediation=Remediation(
                summary=sink.fix,
                guidance=sink.fix,
                references=sink.references
                or [f"https://cwe.mitre.org/data/definitions/{cwe[0].split('-')[1]}.html"],
            ),
            tags=tags,
            metadata=metadata,
        )
