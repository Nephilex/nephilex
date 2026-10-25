"""Evidence for each finding: why it was reported and how to check it.

Every finding leaves the engine with an :class:`~nephilex.core.models.Evidence`
block. It explains a finding; it never changes what is detected or the
finding's severity and confidence.

Grades are defined here and only here (``docs/evidence.md`` has the same
table). They are assigned conservatively: when a rule does not clearly apply,
the weaker grade wins.

``confirmed``
    The tool proved it without guessing: a secret in a provider's exact key
    format that the provider accepted as live (secret validation on); a
    dependency whose exact installed version (from a lock file or an ``==``
    pin) is inside an advisory's affected range; a finding that an active
    check (the dynamic scan, an image or file integrity inspection) marked
    ``verified`` or ``confirmed``.
``likely``
    Taint data flow from an attacker-controlled source (request data,
    browser input, an archive entry name) to a sink with no recognized
    sanitizer on the recorded path, including a finding that took over such
    a path when two scanners reported the same weakness; or a
    high-confidence rule of a precise scanner (patterns, secrets,
    configuration files) that matched the exact code; or a version required
    in ``go.mod``.
``possible``
    Everything else: heuristic and pattern matches, low confidence, operator
    input (command line, environment), library-mode (``public-api``)
    findings, test and example code, imported SARIF results, and data-flow
    findings whose source was not recorded.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from nephilex.core.models import (
    PUBLIC_API_TAG,
    Confidence,
    Evidence,
    EvidenceGrade,
    EvidenceStep,
    Finding,
    Severity,
)

#: Longest evidence path; longer ones keep the source, the newest steps and the sink.
MAX_PATH_STEPS = 12

#: Scanners whose findings carry a recorded taint path.
TAINT_SCANNERS = frozenset({"ast-python", "ast-python-xfile", "ast-js"})
#: Rules of those scanners that do not follow data from a source (weak
#: randomness, query text built from any non-constant, template settings).
NON_TAINT_RULES = frozenset(
    {"ast-sql-string-building", "ast-weak-random", "ast-jinja-autoescape-off"}
)
#: Scanners whose rules match exact code or configuration (not behaviour
#: heuristics), so a high-confidence match of theirs is graded ``likely``.
PRECISE_SCANNERS = frozenset(
    {"patterns", "lang-sast", "secrets", "iac", "cicd", "agent-config", "container", "cloud"}
)
#: Scanners and checks that observe an issue directly (not by reading code).
VERIFIER_SCANNERS = frozenset({"dast", "container-image", "fim", "secret_verify"})
#: Manifests that record the exact version that gets installed.
EXACT_MANIFESTS = frozenset(
    {
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
    }
)

#: Prefixes the taint scanners use for step notes; the text after them is the
#: short label shown in a compact path (``query``, ``cursor.execute``).
_NOTE_PREFIXES = (
    "assigned to ",
    "stored in ",
    "passed to ",
    "returned by ",
    "received as parameter ",
    "reaches ",
)
#: Phrases that end the expression at the start of a source note.
_SOURCE_SUFFIXES = (
    " is attacker-controlled",
    " is filled from the request",
    " is a member name",
    " comes from",
    " is a parameter",
    " is browser input",
    " is received",
)

#: What a sink of each weakness is, in words.
_SINK_LABEL = {
    "CWE-89": "the SQL call",
    "CWE-78": "the shell command",
    "CWE-22": "a file system path",
    "CWE-94": "code evaluation",
    "CWE-95": "code evaluation",
    "CWE-1336": "a template",
    "CWE-502": "a deserializer",
    "CWE-79": "the HTML output",
    "CWE-601": "a redirect",
    "CWE-918": "an outgoing request",
    "CWE-611": "an XML parser",
    "CWE-90": "an LDAP query",
    "CWE-643": "an XPath query",
    "CWE-501": "the session",
}

#: A harmless input that shows the weakness, to try only in a test environment
#: the developer owns. Described in words where the literal text would be a
#: working payload.
_TRY = {
    "CWE-89": "In a test environment you own, pass a value containing a single quote "
    "(for example ' OR '1'='1) and check whether the query fails or returns other rows.",
    "CWE-78": "In a test environment you own, pass a value that adds a harmless second "
    "command after a semicolon and check whether it runs.",
    "CWE-22": "In a test environment you own, pass a name with ../ segments and check "
    "whether a file outside the intended directory is read or written.",
    "CWE-95": "In a test environment you own, pass a harmless expression such as 1+1 and "
    "check whether it is evaluated.",
    "CWE-94": "In a test environment you own, pass a harmless expression such as 1+1 and "
    "check whether it is evaluated.",
    "CWE-1336": "In a test environment you own, pass a template expression such as {{7*7}} "
    "and check whether 49 appears in the output.",
    "CWE-79": "In a test environment you own, pass a value with an HTML tag such as <b>x</b> "
    "and check whether it renders as markup instead of text.",
    "CWE-601": "In a test environment you own, pass an absolute URL to another site and "
    "check whether the response redirects there.",
    "CWE-918": "In a test environment you own, pass the address of a server you control and "
    "check whether the application connects to it.",
    "CWE-90": "In a test environment you own, pass a value containing * or ) and check "
    "whether the directory query changes.",
    "CWE-643": "In a test environment you own, pass a value containing a single quote and "
    "check whether the XPath query fails or matches other nodes.",
    "CWE-502": "Check whether the serialized data can come from outside; never load "
    "untrusted samples outside a sandbox.",
    "CWE-611": "Check whether the XML can come from outside; in a test environment you own, "
    "a document that declares an external entity shows whether it is resolved.",
}

#: Where the data comes from, in words, by origin key.
_ORIGIN_NOUN = {
    "request": "Request data",
    "dom": "Browser input",
    "archive-entry": "An archive entry name",
    "archive": "An archive entry name",
}
_ORIGIN_CHECK = {
    "request": "comes from the request",
    "dom": "comes from the browser (URL, cookie or message data)",
    "archive-entry": "is a name read from an archive",
    "archive": "is a name read from an archive",
    "operator": "comes from the command line, the environment or console input",
    "env": "comes from the environment or the command line",
    "public-api": "is passed in by callers of this public function",
    "param": "is passed in by callers of this function",
}


# --- grading -----------------------------------------------------------------------


def grade_finding(f: Finding, path: list[EvidenceStep]) -> tuple[EvidenceGrade, str]:
    """The evidence grade of ``f`` and the one sentence it rests on.

    Proof (``confirmed``) is checked first: a live secret in a test file is
    still a live secret. Anything that weakens a finding (test code, operator
    input, library mode, low confidence, a missing source) then caps it at
    ``possible`` before ``likely`` is considered.
    """
    proof = _confirmed(f)
    if proof:
        return "confirmed", proof
    weak = _possible_reason(f, path)
    if weak:
        return "possible", weak
    strong = _likely(f, path)
    if strong:
        return "likely", strong
    return "possible", (
        "A pattern or heuristic match; the tool did not show that attacker-controlled "
        "data reaches this code."
    )


def _confirmed(f: Finding) -> str | None:
    state = f.metadata.get("verification")
    if f.scanner == "secrets" and state == "live":
        return "The value matches the provider's key format and the provider accepted it as live."
    if f.scanner == "dependencies":
        manifest = PurePosixPath(f.location.path.replace("\\", "/")).name
        version = f.metadata.get("installed_version")
        if manifest in EXACT_MANIFESTS and version:
            advisory = f.metadata.get("cve") or f.rule_id.split(".", 1)[-1]
            return (
                f"Version {version} recorded in {manifest} is inside the affected range "
                f"of {advisory}."
            )
    observed = f.scanner in VERIFIER_SCANNERS or f.metadata.get("finding_kind") == "dynamic"
    if observed and state in ("verified", "confirmed"):
        return f"An active check observed this directly (verification: {state})."
    return None


def _origin(f: Finding) -> str:
    """Where a taint finding's data comes from (an origin key)."""
    if f.scanner == "ast-js":
        return str(f.metadata.get("source_kind") or "request")
    return str(f.metadata.get("source") or "request")


def _is_taint(f: Finding) -> bool:
    """A finding the taint engines report for data that flowed from a source."""
    return (
        f.scanner in TAINT_SCANNERS
        and str(f.metadata.get("analysis", "")).startswith("taint-dataflow")
        and f.rule_id.split(".", 1)[-1] not in NON_TAINT_RULES
    )


def _possible_reason(f: Finding, path: list[EvidenceStep]) -> str | None:
    if f.scanner.startswith("sarif:"):
        return "Imported from another tool's SARIF; Nephilex did not analyze this code itself."
    if "test-context" in f.tags or "example-context" in f.tags:
        return "The code is in a test or example file, which normally does not run in production."
    if PUBLIC_API_TAG in f.tags:
        return (
            "The value is a parameter of a public library function; it is a risk only if "
            "a caller passes untrusted data."
        )
    origin = _origin(f) if _is_taint(f) else ""
    if "operator-input" in f.tags or origin in ("operator", "env"):
        return (
            "The value comes from the command line, the environment or console input, "
            "which whoever runs the program controls."
        )
    if origin == "param":
        return (
            "The value is a function parameter; it is a risk only if a caller passes "
            "untrusted data."
        )
    if f.confidence <= Confidence.LOW:
        return "The rule is a low-confidence or heuristic match; read the code to decide."
    if f.severity <= Severity.INFO:
        return "An informational note, not a reported weakness."
    if _is_taint(f) and not any(s.role == "source" for s in path):
        return "A data flow was found but its source was not recorded; trace it by hand."
    if f.scanner == "dependencies":
        manifest = PurePosixPath(f.location.path.replace("\\", "/")).name
        if manifest not in EXACT_MANIFESTS and manifest != "go.mod":
            return (
                f"The version comes from a range in {manifest}, not a lock file, so the "
                "installed version may differ."
            )
    return None


def _likely(f: Finding, path: list[EvidenceStep]) -> str | None:
    if _is_taint(f):
        noun = _ORIGIN_NOUN.get(_origin(f))
        if noun is None or f.confidence < Confidence.MEDIUM:
            return None
        sink = next((_SINK_LABEL[c] for c in f.cwe if c in _SINK_LABEL), "the sink")
        return f"{noun} reaches {sink} with no recognized sanitizer on the path."
    if (
        f.scanner == "dependencies"
        and PurePosixPath(f.location.path.replace("\\", "/")).name == "go.mod"
    ):
        return (
            "The version required in go.mod is inside the affected range; the build "
            "can select a newer one."
        )
    if any(s.role == "source" for s in path) and f.confidence >= Confidence.MEDIUM:
        # A path taken over from a taint finding merged into this one (carry_path).
        sink = next((_SINK_LABEL[c] for c in f.cwe if c in _SINK_LABEL), "the sink")
        return (
            f"The data-flow tier traced attacker-controlled data to {sink} here with no "
            "recognized sanitizer on the path."
        )
    if f.confidence >= Confidence.HIGH and (
        f.scanner in PRECISE_SCANNERS or f.scanner in TAINT_SCANNERS
    ):
        if f.scanner == "secrets":
            return (
                "The value matches a provider's exact key format; it was not checked "
                "with the provider."
            )
        return (
            "A high-confidence rule matched this exact code; the tool did not trace "
            "where the data comes from."
        )
    return None


# --- paths -------------------------------------------------------------------------


def carry_path(winner: Finding, loser: Finding) -> None:
    """Let ``winner`` show the data-flow path ``loser`` recorded, if it has none.

    Used when two scanners report one weakness and the engine keeps one of
    the findings (for example the pattern finding, because it has a
    deterministic fix). Only a path that earns ``likely`` on its own, an
    attacker-controlled source reaching the sink, is carried over.
    """
    if winner.evidence is not None and winner.evidence.path:
        return
    ev = loser.evidence
    if ev is None or not any(s.role == "source" for s in ev.path):
        return
    if grade_finding(loser, ev.path)[0] != "likely":
        return
    winner.evidence = Evidence(path=list(ev.path))


def cap_path(steps: list[EvidenceStep], limit: int = MAX_PATH_STEPS) -> list[EvidenceStep]:
    """``steps`` cut to ``limit``: the first, an "elided" marker, then the newest ones.

    The first step is the source and the last the sink, so both survive.
    """
    if len(steps) <= limit:
        return steps
    first = steps[0]
    tail = steps[-(limit - 2) :]
    marker = EvidenceStep(
        path=first.path,
        role="elided",
        note=f"{len(steps) - len(tail) - 1} intermediate step(s) left out",
    )
    return [first, marker, *tail]


def _one_step(f: Finding) -> list[EvidenceStep]:
    loc = f.location
    if not loc.path:
        return []
    return [
        EvidenceStep(
            path=loc.path,
            line=loc.start_line,
            column=loc.start_column,
            role="sink",
            code=loc.snippet or "",
            note=f"matched by {f.rule_id}",
        )
    ]


def step_label(step: EvidenceStep) -> str:
    """A short name for one step in a compact path (``query``, ``cursor.execute``)."""
    note = step.note
    if step.role == "source":
        for suffix in _SOURCE_SUFFIXES:
            if suffix in note:
                return note.split(suffix, 1)[0]
    for prefix in _NOTE_PREFIXES:
        if note.startswith(prefix):
            return note[len(prefix) :]
    return note or step.role


def compact_path(evidence: Evidence, limit: int = 6) -> str:
    """``request.args['q'] (app.py:12) -> query (app.py:13) -> cursor.execute (app.py:15)``.

    Long paths show their first step, ``...`` and the last ones.
    """
    steps = [s for s in evidence.path if s.role != "elided"]
    parts = [f"{step_label(s)} ({s.as_ref()})" for s in steps]
    if len(parts) > limit:
        parts = [parts[0], "...", *parts[-(limit - 2) :]]
    return " -> ".join(parts)


# --- verification steps ------------------------------------------------------------


def _where(step: EvidenceStep, sink: EvidenceStep | None) -> str:
    if step.line is None:
        return step.path
    if sink is not None and step.path == sink.path:
        return f"line {step.line}"
    return f"{step.path} line {step.line}"


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _lines_ref(steps: list[EvidenceStep], sink: EvidenceStep | None) -> str:
    """``lines 7 and 8`` or ``routes.py line 7, then db.py lines 3 and 4``."""
    groups: list[tuple[str, list[str]]] = []
    for s in steps:
        if s.line is None:
            continue
        if groups and groups[-1][0] == s.path:
            if str(s.line) not in groups[-1][1]:
                groups[-1][1].append(str(s.line))
        else:
            groups.append((s.path, [str(s.line)]))
    single = len(groups) == 1 and sink is not None and groups[0][0] == sink.path
    parts = []
    for path, lines in groups:
        word = "line" if len(lines) == 1 else "lines"
        parts.append(f"{word} {_and(lines)}" if single else f"{path} {word} {_and(lines)}")
    return ", then ".join(parts)


def _taint_verify(f: Finding, path: list[EvidenceStep]) -> list[str]:
    source = next(s for s in path if s.role == "source")
    sink = next((s for s in reversed(path) if s.role == "sink"), None)
    origin = _origin(f) if _is_taint(f) else ""
    if PUBLIC_API_TAG in f.tags:
        origin = "public-api"
    elif "operator-input" in f.tags:
        origin = "operator"
    out = [
        f"Open {source.path} line {source.line} and confirm the value read there "
        f"{_ORIGIN_CHECK.get(origin, 'can be controlled from outside the program')}."
    ]
    middle = [s for s in path if s.role == "step"]
    guards = [s for s in path if s.role == "guard"]
    target = f"before {_where(sink, None)}" if sink is not None else "before it is used"
    if middle:
        out.append(
            f"Follow it through {_lines_ref(middle[:8], sink)} and check that nothing "
            f"validates, escapes or converts it {target}."
        )
    if guards:
        out.append(
            f"The check at {_where(guards[0], sink)} does not cover this kind of sink; "
            "confirm whether it really blocks harmful input."
        )
    out.append(f"Check whether any caller, decorator or middleware validates the value {target}.")
    try_it = next((_TRY[c] for c in f.cwe if c in _TRY), None)
    if try_it:
        out.append(try_it)
    return out[:4]


def _scanner_verify(f: Finding, grade: EvidenceGrade) -> list[str]:
    s = f.scanner
    if s == "secrets":
        if grade == "confirmed":
            return [
                "The provider reported this credential as live: rotate it now and review "
                "its recent use in the provider's logs.",
                "Remove it from the repository and its history; deleting the line is not enough.",
            ]
        return [
            "Check whether the value is a real credential or a placeholder, sample or test value.",
            "If it is real, rotate it with the provider and remove it from the repository history.",
        ]
    if s == "dependencies":
        snippet = f.location.snippet or ""
        pkg = snippet.split("==", 1)[0] or "the package"
        version = f.metadata.get("installed_version") or "the reported version"
        advisory = f.metadata.get("cve") or f.rule_id.split(".", 1)[-1]
        fixed = f.metadata.get("fixed_version")
        out = [
            f"Check that the installed version of {pkg} is {version} (your lock file or "
            "the package manager's list command).",
            f"Read {advisory} and check whether your code uses the affected feature.",
        ]
        if fixed:
            out.append(f"Upgrade to {fixed} or later and run your tests.")
        return out
    if s in ("iac", "cicd", "container", "cloud", "agent-config"):
        return [
            "Confirm this setting is what actually gets deployed or run: look for "
            "overrides in other files, environments or defaults.",
        ]
    if s == "malware":
        return [
            "Check whether this file runs on install or import (install scripts, package "
            "entry points).",
            "Read what it sends or executes; do not run it outside a sandbox.",
        ]
    if s == "authz":
        return [
            "Check whether a decorator, middleware or router-level dependency enforces "
            "authentication and authorization for this route.",
        ]
    if s.startswith("llm") or s == "ai-instructions":
        return [
            "Check what untrusted text can reach the prompt or tool call, and whether the "
            "model's output is validated before it is used.",
        ]
    out = [
        "Check where the values used on that line come from; it is a risk only if an "
        "attacker can influence them.",
    ]
    try_it = next((_TRY[c] for c in f.cwe if c in _TRY), None)
    if try_it:
        out.append(try_it)
    return out


def verify_steps(f: Finding, path: list[EvidenceStep], grade: EvidenceGrade) -> list[str]:
    """Two to four plain steps a developer can follow to confirm or rule out ``f``."""
    if any(s.role == "source" for s in path):
        return _taint_verify(f, path)
    loc = f.location
    out = [
        f"Open {loc.path} line {loc.start_line} and read the flagged code."
        if loc.start_line
        else f"Open {loc.path} and find what the finding describes."
    ]
    out += _scanner_verify(f, grade)
    why = (f.why_vulnerable or "").strip()
    if len(out) < 4 and why:
        short = why if len(why) <= 200 else why[:197] + "..."
        out.append(f"Confirm the reason given applies here: {short}")
    if len(out) < 2:
        out.append("If the code is reachable with outside input, treat it as a real issue.")
    return out[:4]


# --- entry points ------------------------------------------------------------------


def build_evidence(f: Finding) -> Evidence:
    """The full evidence block for ``f``, keeping a path a scanner recorded."""
    recorded = f.evidence.path if f.evidence is not None else []
    path = cap_path(list(recorded) if recorded else _one_step(f))
    grade, basis = grade_finding(f, path)
    return Evidence(grade=grade, basis=basis, path=path, verify=verify_steps(f, path, grade))


def attach_evidence(findings: Iterable[Finding]) -> None:
    """Give every finding its evidence block. Changes nothing else on the finding."""
    for f in findings:
        f.evidence = build_evidence(f)
