"""Static analysis via language-aware source patterns.

This is a lightweight, regex-based SAST pass. Coverage is deepest for Python and
JavaScript/TypeScript, plus a few language-agnostic checks (weak hashing, disabled
TLS verification, path traversal). It is intentionally rule-driven: each rule is a
small dataclass, and adding coverage, including new languages, means appending a
rule, not touching the scanner. A plugin can register a more precise, AST-based
scanner for a specific language and coexist with this one.

Every rule carries the reasoning fields (why / attacker view / impact) and a CWE
and OWASP mapping so findings are actionable without an AI provider present.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import MAX_SCAN_LINE, iter_scan_windows, match_columns, snippet_line


@dataclass
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: list[str]
    owasp: list[str]
    why: str
    attack: str
    impact: str
    fix: str
    # Restrict to files of these languages; empty means all.
    languages: set[str] = field(default_factory=set)
    confidence: Confidence = Confidence.MEDIUM
    references: list[str] = field(default_factory=list)
    # If this pattern also matches the line, the finding is suppressed. Used to
    # encode safe idioms that would otherwise be false positives (e.g. a hash
    # marked usedforsecurity=False, or a pickle round-trip of the app's own data).
    suppress: re.Pattern[str] | None = None
    # Python rules whose verdict the AST tier can refine with data flow. "shell"
    # and "deser" drop the finding when the payload is built only from literals;
    # "yaml" keeps it (an unsafe loader is still wrong) but grades severity and
    # confidence by whether the input is tainted. See _grade().
    grade: str | None = None
    # A regex fallback for a class the AST tier reports with data flow. Skipped
    # on Python files when that tier is active, so it cannot add noise there.
    ast_owned: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# The rule set. Kept readable and grouped by weakness class.
RULES: list[Rule] = [
    # --- SQL injection ---
    Rule(
        id="python-sql-fstring",
        title="Possible SQL injection via f-string query",
        # An f-string that builds SELECT/INSERT/... with FROM/WHERE/... and an
        # interpolation is almost always SQL injection, wherever it is run,
        # including when assigned to a variable first and passed to execute() later
        # (which line-anchored, execute()-only patterns miss).
        # Each step is an atomic `(?=(?P<x>...))(?P=x)` group: it takes the first
        # keyword / brace and never retries later ones. The earliest choice is
        # always the best one here, and without it a failed search on a long
        # line backtracked over every combination (cubic time).
        pattern=_rx(
            r"(?i)f['\"]"
            r"(?=(?P<dml>[^\n]*?\b(?:select|insert|update|delete)\b))(?P=dml)"
            r"(?=(?P<cl>[^\n]*?\b(?:from|where|into|set|values)\b))(?P=cl)"
            r"(?=(?P<br>[^\n]*?\{))(?P=br)[^\n]*\}"
        ),
        severity=Severity.HIGH,
        cwe=["CWE-89"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        why="A SQL statement is built from an f-string that interpolates a variable, "
        "so input can alter the query structure.",
        attack="Pass a value like `' OR '1'='1` or a stacked query in the tainted "
        "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, potentially full database compromise.",
        fix="Use parameterized queries / bound parameters (e.g. cursor.execute(sql, "
        "params)) and never interpolate user input into SQL text.",
    ),
    Rule(
        id="python-sql-format",
        title="Possible SQL injection via string formatting",
        # execute() with %-formatting, concatenation, or .format() on a SQL string.
        # Distinct from the f-string rule above (no `f` prefix here) so the two
        # never both fire on the same statement.
        pattern=_rx(
            r"(?i)(execute|executemany)\s*\(\s*['\"]"
            r"(?=(?P<kw>.*?\b(?:select|insert|update|delete|drop)\b))(?P=kw)"
            r".*?['\"]\s*(%|\+|\.format\()"
        ),
        severity=Severity.HIGH,
        cwe=["CWE-89"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        why="A SQL statement passed to execute() is assembled with %-formatting, "
        "concatenation, or .format() from variables, so input can alter the "
        "query structure.",
        attack="Pass a value like `' OR '1'='1` or a stacked query in the tainted "
        "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, potentially full database compromise.",
        fix="Use parameterized queries / bound parameters (e.g. cursor.execute(sql, "
        "params)) and never interpolate user input into SQL text.",
    ),
    Rule(
        id="js-sql-concat",
        title="Possible SQL injection via string concatenation",
        pattern=_rx(
            r"(?i)(query|execute)\s*\(\s*[`'\"].*?(select|insert|update|delete).*?[`'\"]\s*\+|\$\{[^}]+\}.*?(from|where)"
        ),
        severity=Severity.HIGH,
        cwe=["CWE-89"],
        owasp=["A03:2021-Injection"],
        # Heuristic (no taint/parameterization awareness). The `ast-js` tier is the
        # authoritative, low-false-positive check when the [ast] extra is installed.
        languages={"JavaScript", "TypeScript"},
        confidence=Confidence.LOW,
        why="A SQL query is built by concatenating or interpolating variables into "
        "the query string.",
        attack="Inject SQL metacharacters through the interpolated value to change "
        "the executed statement.",
        impact="Unauthorized data access or modification.",
        fix="Use parameterized queries (placeholders + values array) or an ORM's "
        "safe query builder.",
    ),
    # --- Command injection ---
    Rule(
        id="python-shell-true",
        title="Command execution with shell=True",
        pattern=_rx(r"subprocess\.(?:call|run|Popen|check_output)\(.*shell\s*=\s*True"),
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        grade="shell",
        why="Running a subprocess through the shell lets shell metacharacters in any "
        "interpolated input execute additional commands.",
        attack="Provide input containing `; rm -rf /` or `$(...)` to run arbitrary "
        "commands as the app user.",
        impact="Remote code execution on the host.",
        fix="Pass the command as an argument list without shell=True, and validate/"
        "escape any external input.",
    ),
    Rule(
        id="python-os-system",
        title="Use of os.system with a dynamic argument",
        # Dynamic argument = string concatenation (+), %-format, or an f-string
        # prefix. The old `[+%f]` class also matched any literal 'f', so constant
        # commands like os.system("df -h") / os.system("find .") fired as false
        # positives. Anchor the f-string case to the quote to avoid that.
        pattern=_rx(r"os\.system\(\s*(?:[^)]*[+%]|f['\"])"),
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        grade="shell",
        why="os.system runs its argument through the shell; building it from "
        "variables enables command injection.",
        attack="Inject shell metacharacters via the concatenated value.",
        impact="Remote code execution on the host.",
        fix="Use subprocess with an argument list, or shlex.quote inputs.",
    ),
    Rule(
        id="js-child-process-exec",
        title="Command injection via child_process.exec",
        pattern=_rx(r"child_process\.exec\(|\bexec\(\s*[`'\"].*?\$\{"),
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        owasp=["A03:2021-Injection"],
        languages={"JavaScript", "TypeScript"},
        confidence=Confidence.MEDIUM,
        why="exec() runs a command string through the shell; interpolated input can "
        "inject commands.",
        attack="Supply shell metacharacters in the interpolated value.",
        impact="Remote code execution on the host.",
        fix="Use execFile/spawn with an argument array instead of exec with an "
        "interpolated string.",
    ),
    # --- Go ---
    Rule(
        id="go-sql-sprintf",
        title="Possible SQL injection via fmt.Sprintf in a query",
        # A query/exec call whose argument is built with fmt.Sprintf or string
        # concatenation, rather than passed as bound parameters.
        pattern=_rx(
            r"(?i)\.(Query|QueryRow|Exec|QueryContext|ExecContext)\w*\(\s*"
            r"(fmt\.Sprintf\(|[^,)]*\+)"
        ),
        severity=Severity.HIGH,
        cwe=["CWE-89"],
        owasp=["A03:2021-Injection"],
        languages={"Go"},
        confidence=Confidence.MEDIUM,
        why="A SQL statement is assembled with fmt.Sprintf or concatenation and then "
        "executed, so input can change the query structure.",
        attack="Supply SQL metacharacters in the interpolated value to alter the statement.",
        impact="Unauthorized data access or modification.",
        fix="Use parameter placeholders ($1, ?) with db.Query(query, args...); never "
        "build SQL with fmt.Sprintf or +.",
    ),
    Rule(
        id="go-command-injection",
        title="Command execution via a shell in Go",
        # exec.Command invoking a shell ("sh -c" / "bash -c" / cmd /C) is the
        # classic command-injection shape when the command string is dynamic.
        pattern=_rx(
            r'exec\.Command(?:Context)?\(\s*["`](?:/bin/)?(?:sh|bash|zsh)["`]\s*,\s*["`]-c["`]'
            r'|exec\.Command(?:Context)?\(\s*["`]cmd(?:\.exe)?["`]\s*,\s*["`]/[cC]["`]'
        ),
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        owasp=["A03:2021-Injection"],
        languages={"Go"},
        confidence=Confidence.MEDIUM,
        why="Running a command through `sh -c` (or `cmd /C`) sends the argument to a "
        "shell, so interpolated input can inject additional commands.",
        attack="Include shell metacharacters (`;`, `|`, backticks) in the command string.",
        impact="Remote code execution on the host.",
        fix="Call the target binary directly via exec.Command(bin, arg1, arg2, ...) "
        "with separate arguments; do not invoke a shell.",
    ),
    Rule(
        id="go-weak-hash",
        title="Weak hash algorithm (MD5/SHA1) in Go",
        pattern=_rx(r"\b(md5|sha1)\.(New|Sum)\("),
        severity=Severity.MEDIUM,
        cwe=["CWE-327"],
        owasp=["A02:2021-Cryptographic Failures"],
        languages={"Go"},
        confidence=Confidence.MEDIUM,
        why="MD5 and SHA-1 are cryptographically broken and must not be used for "
        "integrity or password hashing.",
        attack="Exploit collision weaknesses, or brute-force these fast hashes.",
        impact="Forged signatures/integrity checks or cracked password hashes.",
        fix="Use crypto/sha256 (or bcrypt/argon2 for passwords) instead.",
    ),
    Rule(
        id="go-ssrf-request",
        title="Possible SSRF: HTTP request to a dynamic URL",
        pattern=_rx(
            r"(?i)http\.(Get|Post|Head)\(\s*(?![\"`])[^),]*\b(r\.|req\.|"
            r"request\.|param|input|user|query)"
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-918"],
        owasp=["A10:2021-SSRF"],
        languages={"Go"},
        confidence=Confidence.LOW,
        why="An outbound HTTP request targets a URL derived from input, which can be "
        "pointed at internal services.",
        attack="Supply a URL like http://169.254.169.254/ to reach cloud metadata or "
        "internal endpoints.",
        impact="Server-side request forgery: access to internal services or metadata.",
        fix="Validate the URL against an allowlist of hosts/schemes before requesting it.",
    ),
    # --- Code evaluation / deserialization ---
    Rule(
        id="python-eval-exec",
        title="Use of eval/exec on dynamic input",
        # Match only the bare builtins eval()/exec(), never a method call like
        # ``session.exec(...)`` (SQLModel) or ``cursor.exec(...)``. The lookbehind
        # rejects a preceding ``.`` or word char so those safe APIs are not flagged.
        pattern=_rx(r"(?<![\w.])(eval|exec)\s*\(\s*(?!['\"]\s*\))"),
        severity=Severity.HIGH,
        cwe=["CWE-95"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.LOW,
        why="eval/exec execute their argument as code; if any part comes from input, "
        "that is arbitrary code execution.",
        attack="Provide a Python expression/statement in the evaluated value.",
        impact="Remote code execution within the interpreter.",
        fix="Avoid eval/exec. Use ast.literal_eval for data, or an explicit dispatch "
        "table for behavior.",
    ),
    Rule(
        id="python-yaml-load",
        title="Unsafe yaml.load without SafeLoader",
        pattern=_rx(r"yaml\.load\((?![^)]*Safe)"),
        severity=Severity.HIGH,
        cwe=["CWE-502"],
        owasp=["A08:2021-Software and Data Integrity Failures"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        grade="yaml",
        why="yaml.load with the default loader can construct arbitrary Python objects "
        "from the document.",
        attack="Feed a YAML payload using `!!python/object/apply` tags to execute code.",
        impact="Remote code execution.",
        fix="Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
    ),
    Rule(
        id="python-pickle-loads",
        title="Deserialization of untrusted data with pickle",
        pattern=_rx(r"\bpickle\.(loads|load)\("),
        severity=Severity.HIGH,
        cwe=["CWE-502"],
        owasp=["A08:2021-Software and Data Integrity Failures"],
        languages={"Python"},
        confidence=Confidence.LOW,
        grade="deser",
        # A round-trip of the app's own freshly-pickled data is not untrusted input.
        suppress=_rx(r"pickle\.loads\(\s*pickle\.dumps"),
        why="pickle executes code during deserialization; loading untrusted bytes is unsafe.",
        attack="Provide a crafted pickle stream whose __reduce__ runs a command.",
        impact="Remote code execution.",
        fix="Do not unpickle untrusted data. Use JSON or a schema-validated format.",
    ),
    # --- XSS ---
    Rule(
        id="js-innerhtml",
        title="Potential DOM XSS via innerHTML",
        pattern=_rx(r"\.innerHTML\s*=\s*[^'\"];?|dangerouslySetInnerHTML"),
        severity=Severity.MEDIUM,
        cwe=["CWE-79"],
        owasp=["A03:2021-Injection"],
        languages={"JavaScript", "TypeScript"},
        confidence=Confidence.LOW,
        why="Assigning untrusted data to innerHTML (or dangerouslySetInnerHTML) lets "
        "the browser execute embedded markup/script.",
        attack="Get the app to render an attacker-controlled string containing a script payload.",
        impact="Cross-site scripting: session theft and actions as the victim.",
        fix="Use textContent, framework-escaped bindings, or sanitize with a vetted "
        "library (e.g. DOMPurify) before inserting HTML.",
    ),
    Rule(
        id="python-markup-dynamic",
        title="Markup()/mark_safe() on a dynamically built string",
        # Marking a formatted string as safe HTML disables autoescaping for
        # whatever was interpolated. The AST tier reports the tainted case.
        pattern=_rx(
            r"(?<![\w.])(?:Markup|mark_safe)\(\s*"
            r"(?:[fF]['\"]|(['\"])[^'\"\n]*\1\s*(?:%|\+|\.format\())"
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-79"],
        owasp=["A03:2021-Injection"],
        languages={"Python"},
        confidence=Confidence.LOW,
        why="Markup()/mark_safe() tell the template engine a string is already safe "
        "HTML, so anything interpolated into it is rendered without escaping.",
        attack="Get user input into the interpolated value to inject script into the page.",
        impact="Cross-site scripting.",
        fix="Escape each interpolated value (markupsafe.escape) or use "
        "Markup('...{}').format(value), which escapes its arguments.",
    ),
    Rule(
        id="template-unescaped-output",
        title="Template output with autoescaping turned off",
        # Jinja/Django `{{ x|safe }}` and `{% autoescape false %}` blocks.
        pattern=_rx(r"\{\{[^}\n]*\|\s*safe\s*\}\}|\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}"),
        severity=Severity.LOW,
        cwe=["CWE-79"],
        owasp=["A03:2021-Injection"],
        languages={"HTML"},
        confidence=Confidence.LOW,
        why="The |safe filter and autoescape-off blocks render a value as raw HTML. "
        "If the value can contain user input, that is cross-site scripting.",
        attack="Store or reflect markup with a script payload in the rendered value.",
        impact="Cross-site scripting.",
        fix="Drop |safe and let the engine escape, or sanitize the HTML with a vetted "
        "library before marking it safe.",
    ),
    Rule(
        id="python-xml-resolve-entities",
        title="lxml parser with external entity resolution turned on",
        pattern=_rx(r"XMLParser\([^)\n]*resolve_entities\s*=\s*True"),
        severity=Severity.MEDIUM,
        cwe=["CWE-611"],
        owasp=["A05:2021-Security Misconfiguration"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        why="resolve_entities=True makes lxml expand external entities, so any XML "
        "this parser reads can pull in local files or remote URLs.",
        attack='Get a document with `<!ENTITY x SYSTEM "file:///etc/passwd">` parsed.',
        impact="Local file disclosure or SSRF through XML parsing.",
        fix="Drop resolve_entities=True (lxml 5 defaults to internal entities only) "
        "or parse untrusted XML with defusedxml.",
    ),
    Rule(
        id="python-open-redirect",
        title="Redirect to a URL taken from the request",
        pattern=_rx(
            r"(?<![\w.])(?:redirect|HttpResponseRedirect)\(\s*request\.(?:args|form|values|GET|POST)\b"
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-601"],
        owasp=["A01:2021-Broken Access Control"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        ast_owned=True,
        why="The redirect target comes straight from request data, so the app can be "
        "made to send users to any external site.",
        attack="Send a victim a link to this app that bounces to a phishing page.",
        impact="Credible phishing through the trusted domain.",
        fix="Redirect only to relative paths or allowlisted hosts, or use url_for().",
    ),
    Rule(
        id="python-weak-random-token",
        title="random module used for a security token",
        pattern=_rx(
            r"(?i)(?:token|secret|passw|nonce|otp|salt|session|csrf|api_?key)\w*\s*=[^=\n#][^\n#]*"
            r"(?<![\w.])random\.(?:random|randint|randrange|choice|choices|getrandbits|randbytes|sample)\("
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-330", "CWE-338"],
        owasp=["A02:2021-Cryptographic Failures"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        ast_owned=True,
        why="The random module is a predictable PRNG; values from it must not be used "
        "as tokens, passwords, salts or session identifiers.",
        attack="Recover the generator state from observed outputs and predict tokens.",
        impact="Token, session or password-reset forgery.",
        fix="Use secrets.token_urlsafe()/secrets.token_hex() or random.SystemRandom().",
    ),
    # --- Weak crypto ---
    Rule(
        id="weak-hash-md5-sha1",
        title="Weak hash algorithm (MD5/SHA1)",
        # hashlib.new("md5") is the same algorithm chosen by name, so it counts too.
        pattern=_rx(
            r"(?i)(hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)|createHash\(\s*['\"](md5|sha1)"
            r"|hashlib\.new\(\s*(?:name\s*=\s*)?['\"](?:md4|md5|sha1|md5-sha1)['\"])"
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-327"],
        owasp=["A02:2021-Cryptographic Failures"],
        confidence=Confidence.MEDIUM,
        # Python lets callers mark a hash as non-security (e.g. HTTP digest auth);
        # respect that intent rather than flagging it.
        suppress=_rx(r"usedforsecurity\s*=\s*False"),
        why="MD5 and SHA-1 are broken for security purposes (collisions, speed) and "
        "must not be used for integrity or password hashing.",
        attack="Exploit collision weaknesses, or brute-force fast hashes for stored passwords.",
        impact="Forged signatures/integrity checks, or recovered passwords.",
        fix="Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/Argon2) for passwords.",
    ),
    # --- TLS verification disabled ---
    Rule(
        id="tls-verify-disabled",
        title="TLS certificate verification disabled",
        pattern=_rx(
            r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))"
        ),
        severity=Severity.HIGH,
        cwe=["CWE-295"],
        owasp=["A07:2021-Identification and Authentication Failures"],
        confidence=Confidence.MEDIUM,
        why="Disabling certificate verification removes protection against "
        "man-in-the-middle attacks on TLS connections.",
        attack="Intercept the connection with a forged certificate; the client accepts it.",
        impact="Interception and modification of supposedly encrypted traffic, "
        "including credentials.",
        fix="Enable certificate verification and configure a proper trust store "
        "instead of turning verification off.",
    ),
    # --- Path traversal ---
    Rule(
        id="path-traversal-join",
        title="Possible path traversal in file access",
        pattern=_rx(
            r"(?i)(open|readFile|sendFile|File)\(\s*"
            r"(?=(?P<src>[^)]*?(?:request|req\.|params|input|argv)))(?P=src)[^)]*\)"
        ),
        severity=Severity.MEDIUM,
        cwe=["CWE-22"],
        owasp=["A01:2021-Broken Access Control"],
        confidence=Confidence.LOW,
        why="A filesystem path is built from request input without normalization, so "
        "`../` can escape the intended directory.",
        attack="Request a path such as `../../etc/passwd` to read files outside the intended root.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and verify it stays within an allowed base directory; "
        "reject paths containing traversal sequences.",
    ),
    # --- Debug / misconfig ---
    Rule(
        id="flask-debug-true",
        title="Flask app running with debug=True",
        pattern=_rx(r"app\.run\([^)]*debug\s*=\s*True"),
        severity=Severity.MEDIUM,
        cwe=["CWE-489"],
        owasp=["A05:2021-Security Misconfiguration"],
        languages={"Python"},
        confidence=Confidence.MEDIUM,
        why="Flask debug mode exposes an interactive debugger that allows arbitrary "
        "code execution if reachable.",
        attack="Reach the Werkzeug debugger and execute code through the console.",
        impact="Remote code execution and information disclosure in production.",
        fix="Never enable debug mode in production; gate it behind an environment "
        "variable defaulting to off.",
    ),
]


# Paths that are test/fixture code. Findings here are real but lower priority
# (e.g. a test deliberately using verify=False), so they are downgraded, not hidden.
_TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|testing|__tests__|fixtures?|specs?)/|"
    r"(^|/)(test_[^/]*|[^/]*_test|conftest)\.[a-z0-9]+$"
)


def _is_test_file(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


# --- weak-hash purpose ---------------------------------------------------------
# MD5 and SHA-1 are broken for collision resistance. That breaks signatures,
# integrity checks against an attacker and password storage, but a checksum,
# ETag or cache key that the program computes over content is weakened much
# less: a collision there means two inputs share a key (cache confusion), not a
# forged credential. Such uses are kept, at low severity; anything that names a
# password, secret, token, signature, salt or session stays at the rule's
# severity, with the KDF guidance.
_NON_SECURITY_HASH = re.compile(
    r"(?i)etag|checksum|fingerprint|cache|content_?hash|file_?hash|page_?hash|dedup"
    r"|md5sum|sha1sum|(?<![A-Za-z])digest(?![A-Za-z(])|hash_?key|content_?key|\bkey_for\b"
)
_SECURITY_HASH = re.compile(
    r"(?i)passw|pwd|secret|token|signat|\bsign|hmac|auth|credential|salt|nonce|session"
    r"|api_?key|private|\botp\b|\bpin\b|cookie|csrf|verify|integrity"
)
_DEF_LINE = re.compile(r"^\s*(?:async\s+)?(?:def|function)\s+(\w+)")
_USED_FOR_SECURITY_FALSE = re.compile(r"usedforsecurity\s*=\s*False")


def _hash_call_text(lines: list[str], lineno: int, start: int) -> str:
    """The hash call from its match to its closing parenthesis (up to 4 lines)."""
    text = lines[lineno - 1][start:]
    extra = lineno
    while text.count("(") > text.count(")") and extra < min(len(lines), lineno + 3):
        text += "\n" + lines[extra]
        extra += 1
    return text


def _hash_purpose(lines: list[str], lineno: int) -> str | None:
    """``"checksum"`` when a weak hash is evidently a content key, else None.

    Looks at the line (the variable it is assigned to, the call) and at the
    name of the enclosing function.
    """
    context = lines[lineno - 1]
    for back in range(lineno - 1, max(0, lineno - 40), -1):
        m = _DEF_LINE.match(lines[back - 1])
        if m:
            context += " " + m.group(1)
            break
    if _SECURITY_HASH.search(context):
        return None
    return "checksum" if _NON_SECURITY_HASH.search(context) else None


@dataclass(frozen=True)
class _Grade:
    """How the AST data-flow verdict changes a graded regex finding."""

    verdict: str  # "tainted" | "literal" | "unknown"
    drop: bool = False
    severity: Severity | None = None
    confidence: Confidence | None = None


def _grade(rule: Rule, verdicts: dict[tuple[str, int], str], lineno: int) -> _Grade | None:
    kind = "shell" if rule.grade == "shell" else "deser"
    verdict = verdicts.get((kind, lineno))
    if verdict is None:
        return None  # no call the AST tier understood on this line: keep as is
    if rule.grade == "yaml":
        # An unsafe loader is always reported, graded by what it loads: request
        # data raises confidence, a document built from literals lowers both
        # severity and confidence, an unknown origin keeps the rule's defaults.
        if verdict == "tainted":
            return _Grade(verdict, confidence=Confidence.HIGH)
        if verdict == "literal":
            return _Grade(verdict, severity=Severity.LOW, confidence=Confidence.LOW)
        return _Grade(verdict)
    # shell=True / os.system / pickle: a payload built only from literals
    # cannot carry attacker input, so there is nothing to report.
    return _Grade(verdict, drop=verdict == "literal")


def _ast_parser():
    """A private tree-sitter parser for grading, or None without the [ast] extra."""
    from nephilex.scanners.ast_python import new_parser

    return new_parser()


def _ast_scanner_selected(ctx: ScannerContext) -> bool:
    """Whether the ``ast-python`` tier runs in this scan (it owns some classes)."""
    cfg = ctx.config
    chosen = list(getattr(cfg, "scanners", None) or [])
    excluded = set(getattr(cfg, "exclude_scanners", None) or [])
    return ("ast-python" in chosen if chosen else True) and "ast-python" not in excluded


def _line_verdicts(text: str, parser) -> dict[tuple[str, int], str]:
    from nephilex.scanners.ast_python import line_verdicts

    try:
        return line_verdicts(text.encode("utf-8", "replace"), parser)
    except Exception:  # an unparseable or hostile file: grade nothing
        return {}


# --- lightweight taint tracking (path traversal) ---------------------------
# Full data-flow analysis needs an AST (a planned milestone). This deliberately
# narrow heuristic catches the common, high-value case the line-anchored rules
# miss: a filesystem path taken straight from untrusted input into a file
# operation, even when the value passes through a variable across lines. It only
# fires when BOTH a source and a sink are present, and backs off on sanitizers,
# so it stays low-noise rather than flagging every open() of a variable.
_TAINT_SOURCE = re.compile(
    r"request\.(args|form|values|json|data|files|cookies|headers|query_params|GET|POST)\b"
    r"|\binput\s*\(|\bsys\.argv\b"
)
_TAINT_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
_PATH_SINK = re.compile(
    r"\b(open|os\.open|io\.open|send_file|send_from_directory|os\.remove|os\.unlink)\s*\("
)
# Presence of a sanitizer on the assignment or sink line clears the finding.
_PATH_SANITIZER = re.compile(r"secure_filename|os\.path\.basename|werkzeug|safe_join")


@scanner
class PatternScanner(Scanner):
    name = "patterns"
    category = "sast"
    file_local = True
    description = "Regex-based static analysis for common injection and misuse classes."

    # Only source-y files; skip data/asset languages entirely.
    _SKIP_LANGS = {"JSON", "CSS", "HTML", "YAML", None}
    # Markup that only the rules naming it (template autoescape checks) see.
    _MARKUP_LANGS = {"HTML"}

    def applies_to(self, project) -> bool:
        # Nothing to do on a project with no scannable source (e.g. pure IaC/docs).
        return any(f.language not in self._SKIP_LANGS for f in project.files())

    def cacheable(self, ctx: ScannerContext) -> bool:
        # Custom rules can change on disk without any scanned file changing, so a
        # run that loads them opts out of the per-file cache to stay correct.
        rules_opt = ctx.config.options_for(self.name).get("rules")
        trust = getattr(ctx.config, "trust_project_config", False)
        from nephilex.scanners.custom_rules import config_signature

        return self.file_local and not config_signature(ctx.project.root, rules_opt, trust)

    def _effective_rules(self, ctx: ScannerContext) -> list[Rule]:
        rules_opt = ctx.config.options_for(self.name).get("rules")
        # A cloned, untrusted repo must not be able to inject rules via its own
        # .nephilex/rules convention directory (rule injection / ReDoS).
        trust = getattr(ctx.config, "trust_project_config", False)
        from nephilex.scanners.custom_rules import load_custom_rules

        return [*RULES, *load_custom_rules(ctx.project.root, rules_opt, trust)]

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        rules = self._effective_rules(ctx)
        parser = _ast_parser()
        ast_running = parser is not None and _ast_scanner_selected(ctx)
        for f in ctx.project.files():
            if f.is_probably_binary():
                continue
            markup = f.language in self._MARKUP_LANGS
            if f.language in self._SKIP_LANGS and not markup:
                continue
            in_test = _is_test_file(f.rel_path)
            lines = f.lines()
            verdicts: dict[tuple[str, int], str] | None = None
            for rule in rules:
                if rule.languages and f.language not in rule.languages:
                    continue
                if markup and not rule.languages:
                    continue  # templates only get the rules written for them
                if rule.ast_owned and ast_running and f.language == "Python":
                    continue
                reported: set[int] = set()
                for lineno, offset, segment in iter_scan_windows(lines):
                    if lineno in reported:
                        continue
                    m = rule.pattern.search(segment)
                    if m is None:
                        continue
                    if rule.suppress and rule.suppress.search(segment):
                        continue  # a known-safe idiom on this line
                    purpose: str | None = None
                    if rule.id == "weak-hash-md5-sha1":
                        call = _hash_call_text(lines, lineno, offset + m.start())
                        if _USED_FOR_SECURITY_FALSE.search(call):
                            continue  # declared non-security (Python 3.9+), even across lines
                        purpose = _hash_purpose(lines, lineno)
                    grade: _Grade | None = None
                    if rule.grade and parser is not None and f.language == "Python":
                        if verdicts is None:
                            verdicts = _line_verdicts(f.text(), parser)
                        grade = _grade(rule, verdicts, lineno)
                        if grade is not None and grade.drop:
                            continue  # data flow proves the payload is a constant
                    reported.add(lineno)
                    counter += 1
                    yield self._finding(
                        rule,
                        counter,
                        f.rel_path,
                        lineno,
                        lines[lineno - 1],
                        in_test=in_test,
                        columns=match_columns(m, offset),
                        grade=grade,
                        purpose=purpose,
                    )
            # Cross-line path-traversal heuristic (Python only).
            if f.language == "Python":
                yield from self._scan_path_traversal(f, in_test)

    def _scan_path_traversal(self, f, in_test: bool) -> Iterable[Finding]:
        """Flag a file path that flows from untrusted input into a file operation.

        Two-pass, single-file: collect variables assigned directly from a request/
        input source (skipping sanitized ones), then report file-operation sinks
        that use one of those tainted variables.
        """
        lines = f.lines()
        tainted: set[str] = set()
        for line in lines:
            if len(line) > MAX_SCAN_LINE:
                continue
            m = _TAINT_ASSIGN.match(line)
            if m and _TAINT_SOURCE.search(m.group(2)) and not _PATH_SANITIZER.search(m.group(2)):
                tainted.add(m.group(1))
        if not tainted:
            return
        for lineno, line in enumerate(lines, start=1):
            if len(line) > MAX_SCAN_LINE or _PATH_SANITIZER.search(line):
                continue
            sink = _PATH_SINK.search(line)
            if not sink:
                continue
            rest = line[sink.start() :]
            used = next((v for v in tainted if re.search(rf"\b{re.escape(v)}\b", rest)), None)
            if used:
                yield self._path_traversal_finding(f.rel_path, lineno, line, in_test, sink)

    def _path_traversal_finding(
        self, path: str, lineno: int, line: str, in_test: bool, sink: re.Match[str]
    ) -> Finding:
        severity = Severity.LOW if in_test else Severity.MEDIUM
        confidence = Confidence.LOW if in_test else Confidence.MEDIUM
        tags = ["sast", "taint"] + (["test-context"] if in_test else [])
        return Finding(
            id=f"{self.name}:path-traversal-taint:{path}:{lineno}",
            rule_id=f"{self.name}.path-traversal-taint",
            scanner=self.name,
            title="Possible path traversal from untrusted input",
            description="A filesystem path derived from user input reaches a file "
            "operation without normalization.",
            location=_location(path, lineno, line, match_columns(sink)),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-22"],
            owasp=["A01:2021-Broken Access Control"],
            why_vulnerable="User-controlled input is used to build a filesystem path "
            "without validation, so `../` sequences can escape the "
            "intended directory.",
            attacker_perspective="Request a path such as `../../etc/passwd` to read or "
            "write files outside the intended location.",
            business_impact="Disclosure of sensitive files, or writing outside the intended area.",
            remediation=Remediation(
                summary="Confirm the resolved path stays within an allowed base "
                "directory; reject inputs containing traversal sequences.",
                guidance="Normalize with os.path.realpath and verify the result is "
                "under an allowed root, or use a vetted helper such as "
                "werkzeug.utils.secure_filename / safe_join.",
                references=["https://cwe.mitre.org/data/definitions/22.html"],
            ),
            tags=tags,
        )

    def _finding(
        self,
        rule: Rule,
        index: int,
        path: str,
        lineno: int,
        line: str,
        *,
        in_test: bool = False,
        columns: tuple[int, int] | None = None,
        grade: _Grade | None = None,
        purpose: str | None = None,
    ) -> Finding:
        severity = rule.severity
        confidence = rule.confidence
        tags = ["sast"]
        metadata: dict[str, str] = {}
        description = rule.why
        if grade is not None:
            severity = grade.severity if grade.severity is not None else severity
            confidence = grade.confidence if grade.confidence is not None else confidence
            metadata["dataflow"] = grade.verdict
        if purpose == "checksum":
            severity = min(severity, Severity.LOW)
            confidence = Confidence.LOW
            tags.append("non-security-hash")
            metadata["hash_purpose"] = "checksum"
            description = (
                f"{rule.why} Here the hash looks like a checksum, ETag or cache key "
                "rather than a password, signature or token, so it is reported at low "
                "severity: a collision lets two inputs share a key. If it protects "
                "integrity against an attacker or stores a secret, treat it as medium. "
                "Pass usedforsecurity=False (Python 3.9+) to mark a non-security use."
            )
        # Test/fixture code is lower risk: downgrade a level and mark it, rather
        # than hiding it. Keeps the signal without drowning real production issues.
        if in_test:
            severity = Severity(max(Severity.INFO, severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        return Finding(
            id=f"{self.name}:{rule.id}:{index}",
            rule_id=f"{self.name}.{rule.id}",
            scanner=self.name,
            title=rule.title,
            description=description,
            location=_location(path, lineno, line, columns),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.POSSIBLE,
            cwe=rule.cwe,
            owasp=rule.owasp,
            why_vulnerable=rule.why,
            attacker_perspective=rule.attack,
            business_impact=rule.impact,
            remediation=Remediation(
                summary=rule.fix,
                guidance=rule.fix,
                references=rule.references
                or [
                    f"https://cwe.mitre.org/data/definitions/{rule.cwe[0].split('-')[1]}.html"
                    if rule.cwe
                    else "",
                ],
            ),
            tags=tags,
            metadata=metadata,
        )


def _location(path: str, lineno: int, line: str, columns: tuple[int, int] | None) -> Location:
    start, end = columns if columns is not None else (None, None)
    return Location(
        path=path,
        start_line=lineno,
        end_line=lineno,
        start_column=start,
        end_column=end,
        snippet=snippet_line(line),
    )
