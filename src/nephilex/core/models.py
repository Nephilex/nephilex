"""Core data models shared across scanners, agents, and reporters.

Everything Nephilex produces flows through :class:`Finding`. Keeping a single,
well-defined finding shape is what lets plugins interoperate: a scanner emits
findings, an agent enriches them, and a reporter serializes them without any of
those components knowing about each other.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, Field, computed_field, field_validator

# Documentation home. Every finding links back to the relevant scanner page, so a
# report is a jumping-off point into the docs (and, incidentally, good SEO).
_DOCS_BASE = "https://nephilex.github.io/nephilex"
_SCANNER_DOC_ANCHOR = {
    "secrets": "secrets",
    "dependencies": "dependencies-sca",
    "patterns": "sast-pattern-rules",
    "ast-python": "taint-data-flow-ast",
    "ast-js": "taint-data-flow-ast",
    "iac": "infrastructure-as-code",
    "llm": "llm-ai-application-security",
    "agent-config": "agent-config",
    "custom_rules": "custom-rules",
}


def docs_url_for(scanner: str) -> str:
    """The docs URL for a scanner's page (used on every finding).

    Findings imported from another tool's SARIF (scanner ``sarif:<tool>``)
    link to the import guide, which explains how they were mapped.
    """
    if scanner.startswith("sarif:"):
        return f"{_DOCS_BASE}/importing/"
    anchor = _SCANNER_DOC_ANCHOR.get(scanner)
    return f"{_DOCS_BASE}/scanners/" + (f"#{anchor}" if anchor else "")


# The importer's digest of a SARIF result (see nephilex.importers.sarif).
_SARIF_DIGEST = re.compile(r"[0-9a-f]{8,64}")

#: Tag on findings whose input is a public function's parameter (library mode).
#: They are reported for review but do not count toward a ``--fail-on`` gate.
PUBLIC_API_TAG = "public-api"


def counts_toward_gate(finding: Finding) -> bool:
    """Whether ``finding`` can fail a ``--fail-on`` / ``fail_on`` severity gate.

    Library-mode findings (tagged :data:`PUBLIC_API_TAG`) are excluded: their
    input is whatever a caller of the library passes, so whether they are
    exploitable depends on code outside the scanned project.
    """
    return PUBLIC_API_TAG not in finding.tags


_E = TypeVar("_E", bound="_LabeledIntEnum")


class _LabeledIntEnum(IntEnum):
    """Ordered enum with a human label and tolerant parsing.

    Integer ordering allows sorting and threshold comparisons; the shared
    ``parse``/``label`` avoids repeating the same boilerplate on every enum.
    """

    @classmethod
    def parse(cls: type[_E], value: str | int | _E) -> _E:
        """Parse a name (case-insensitive) or integer value.

        Raises ``ValueError`` (never ``KeyError``) on unknown input so callers
        can report a bad setting as a usage error instead of a crash.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError:
                pass
        else:
            key = str(value).strip().upper().replace(" ", "_")
            if key in cls.__members__:
                return cls.__members__[key]
        choices = ", ".join(m.name.lower() for m in cls)
        raise ValueError(f"invalid {cls.__name__.lower()} {value!r} (choose from: {choices})")

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").title()


class Severity(_LabeledIntEnum):
    """Ordered severity levels. Integer ordering allows sorting and thresholds."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def to_cvss_band(self) -> str:
        """Rough mapping to a CVSS v3 qualitative band, for report headers."""
        return {
            Severity.INFO: "None",
            Severity.LOW: "Low",
            Severity.MEDIUM: "Medium",
            Severity.HIGH: "High",
            Severity.CRITICAL: "Critical",
        }[self]


class Confidence(_LabeledIntEnum):
    """How sure Nephilex is that a finding is a true positive."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2


class Likelihood(_LabeledIntEnum):
    """Estimated likelihood that a weakness is exploited in practice."""

    RARE = 0
    UNLIKELY = 1
    POSSIBLE = 2
    LIKELY = 3
    ALMOST_CERTAIN = 4


class Location(BaseModel):
    """Where a finding lives. Line/column are 1-indexed; None means file-level."""

    path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None

    def as_ref(self) -> str:
        if self.start_line is None:
            return self.path
        return f"{self.path}:{self.start_line}"


class Remediation(BaseModel):
    """Guidance for fixing a finding, optionally with a concrete patch."""

    summary: str
    guidance: str = ""
    # A unified diff that resolves the finding, when Nephilex can generate one.
    patch: str | None = None
    # Free-form references (docs, CWE pages, framework advisories).
    references: list[str] = Field(default_factory=list)
    # True once a generated fix has been re-scanned and confirmed to close the issue.
    verified: bool = False


class ExploitScenario(BaseModel):
    """Output of Attack Simulation Mode for a single finding.

    Everything here is generated in an isolated context and is intended to be
    read, not run against production. ``sandbox_ok`` records whether the
    demonstration was executed in a sandbox or produced statically.
    """

    discovery: str = ""  # how an attacker finds the weakness
    exploit_walkthrough: str = ""  # step-by-step, safe to read
    data_at_risk: str = ""  # what could be exposed
    business_impact: str = ""  # plain-language impact
    fix_blocks_attack: str = ""  # why the proposed fix stops it
    before_after: str = ""  # before/after comparison
    sandbox_ok: bool = False


#: Evidence grades, strongest first. See :mod:`nephilex.core.evidence` for the rules.
EVIDENCE_GRADES = ("confirmed", "likely", "possible")
EvidenceGrade = Literal["confirmed", "likely", "possible"]
#: Roles of one evidence step: where the data comes from (``source``), how it
#: moves (``step``), a check that was seen but does not cover this sink
#: (``guard``), where it is used (``sink``), and a marker for steps left out.
EvidenceRole = Literal["source", "step", "guard", "sink", "elided"]
#: Longest code excerpt and note kept on one step.
EVIDENCE_CODE_LIMIT = 160
EVIDENCE_TEXT_LIMIT = 300


def _safe_text(value: str, limit: int) -> str:
    """Untrusted text made safe to show: one line, controls escaped, secrets masked."""
    if not value:
        return ""
    from nephilex.scanners.ai_instructions import safe_excerpt

    return safe_excerpt(value, limit)


class EvidenceStep(BaseModel):
    """One step of an evidence path: a line of code and what happens there.

    ``code`` and ``note`` can quote the scanned repository, so both are
    reduced to one line with control, bidirectional and zero-width characters
    shown as ``<U+XXXX>`` and secret-looking values masked. Reporters still
    escape them for their own format.
    """

    path: str
    line: int | None = None
    column: int | None = None
    role: EvidenceRole = "step"
    code: str = ""
    note: str = ""

    @field_validator("code")
    @classmethod
    def _clean_code(cls, value: str) -> str:
        return _safe_text(value.strip(), EVIDENCE_CODE_LIMIT)

    @field_validator("note")
    @classmethod
    def _clean_note(cls, value: str) -> str:
        return _safe_text(value, EVIDENCE_TEXT_LIMIT)

    def as_ref(self) -> str:
        return self.path if self.line is None else f"{self.path}:{self.line}"


class Evidence(BaseModel):
    """Why a finding was reported, and how to check it by reading the code.

    ``grade`` says how strong the proof is (``confirmed``, ``likely``,
    ``possible``), ``basis`` says in one sentence what the grade rests on,
    ``path`` lists the lines from the source of the data to where it is used,
    and ``verify`` gives a few steps a developer can follow to confirm or rule
    out the finding. Evidence only explains a finding; it never changes its
    severity or confidence.
    """

    grade: EvidenceGrade = "possible"
    basis: str = ""
    path: list[EvidenceStep] = Field(default_factory=list)
    verify: list[str] = Field(default_factory=list)

    @field_validator("basis")
    @classmethod
    def _clean_basis(cls, value: str) -> str:
        return _safe_text(value, EVIDENCE_TEXT_LIMIT)

    @field_validator("verify")
    @classmethod
    def _clean_verify(cls, value: list[str]) -> list[str]:
        return [_safe_text(v, EVIDENCE_TEXT_LIMIT) for v in value if v and v.strip()]


class Finding(BaseModel):
    """A single security finding.

    A finding is more than "line X is vulnerable". It carries the reasoning a
    reviewer needs: why it matters, how it is exploited, its impact, and how to
    fix it, plus the taxonomy mappings tools downstream expect.
    """

    # Identity
    id: str  # stable within a scan, e.g. "secrets:aws-key:3"
    rule_id: str  # the rule/check that produced it
    scanner: str  # scanner plugin name

    # What & where
    title: str
    description: str
    location: Location

    # Assessment
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    likelihood: Likelihood = Likelihood.POSSIBLE

    # Taxonomy
    cwe: list[str] = Field(default_factory=list)  # e.g. ["CWE-89"]
    owasp: list[str] = Field(default_factory=list)  # e.g. ["A03:2021-Injection"]

    # The reasoning an AI Security Engineer would give (may be filled by an agent)
    why_vulnerable: str = ""
    attacker_perspective: str = ""
    business_impact: str = ""

    # Remediation & simulation
    remediation: Remediation | None = None
    exploit: ExploitScenario | None = None

    # Provenance / extra data for reporters
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Why it was reported and how to check it (see nephilex.core.evidence).
    # Optional and additive: older reports have no such field.
    evidence: Evidence | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def docs_url(self) -> str:
        return docs_url_for(self.scanner)

    def fingerprint(self) -> str:
        """A stable identifier used to de-duplicate and track findings over time.

        Keyed on the *content* of the offending code (whitespace-normalized) rather
        than the raw line number, so a finding keeps its identity when unrelated
        edits shift it up or down the file. This is what makes baseline/diff-aware
        scanning and cross-commit tracking reliable. Falls back to the line number
        for file-level findings that have no snippet.

        A finding imported from SARIF whose tool supplied its own fingerprints
        (``fingerprints`` / ``partialFingerprints``) uses the importer's digest
        of them instead (``metadata["sarif"]["fingerprint"]``): the tool built
        them to survive edits, and they do not depend on Nephilex being able to
        read the file. Without tool fingerprints that digest includes the line
        number, so the content fingerprint above is the more stable one.
        """
        imported = self._sarif_fingerprint()
        if imported:
            return f"{self.rule_id}|{self.location.path}|{imported}"
        basis = re.sub(r"\s+", "", self.location.snippet or "")
        if basis:
            # Non-security digest: a stable content fingerprint for de-duplication,
            # never an integrity/auth check, so SHA-1 is fine here.
            digest = hashlib.sha1(basis.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
            return f"{self.rule_id}|{self.location.path}|{digest}"
        return f"{self.rule_id}|{self.location.path}|L{self.location.start_line}"

    def _sarif_fingerprint(self) -> str | None:
        sarif = self.metadata.get("sarif")
        if not isinstance(sarif, dict) or not sarif.get("fingerprints"):
            return None
        value = sarif.get("fingerprint")
        if isinstance(value, str) and _SARIF_DIGEST.fullmatch(value):
            return value
        return None

    def risk_score(self) -> float:
        """A 0 to 100 score combining severity, confidence, and likelihood.

        Used for ranking and for the aggregate risk number. The weighting favors
        severity while letting confidence and likelihood modulate.
        """
        sev = self.severity / Severity.CRITICAL  # 0..1
        conf = (self.confidence + 1) / len(Confidence)  # 0.33..1
        like = (self.likelihood + 1) / len(Likelihood)  # 0.2..1
        return round(100 * sev * (0.6 + 0.25 * conf + 0.15 * like), 1)


class ScanResult(BaseModel):
    """The complete output of a scan: metadata plus every finding."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    nephilex_version: str = ""
    scanners_run: list[str] = Field(default_factory=list)
    scanners_failed: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    # Snapshot of the project model (languages, frameworks, etc.) for the report.
    project_summary: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most to least important."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity, f.confidence, f.risk_score()),
            reverse=True,
        )

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def aggregate_risk(self) -> float:
        """A single 0 to 100 risk number for the whole target.

        Not a mean, a single critical should dominate a pile of lows. We take a
        softmax-ish blend: the worst finding sets the floor, volume nudges it up.
        """
        if not self.findings:
            return 0.0
        scores = sorted((f.risk_score() for f in self.findings), reverse=True)
        top = scores[0]
        tail = sum(scores[1:]) / (len(scores) * 20) if len(scores) > 1 else 0
        return round(min(100.0, top + tail), 1)

    def highest_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def gating_severity(self) -> Severity:
        """Highest severity among the findings that count toward a fail-on gate."""
        return max(
            (f.severity for f in self.findings if counts_toward_gate(f)), default=Severity.INFO
        )
