"""Evidence for findings: the model and its sanitizing, grades, capping.

Evidence only explains a finding. These tests also pin that it never changes
what is detected: equality of analysis values ignores the recorded history,
and fingerprints and severities are the same with or without evidence.
"""

from __future__ import annotations

import json

import pytest

from nephilex.core.evidence import (
    MAX_PATH_STEPS,
    attach_evidence,
    build_evidence,
    cap_path,
    grade_finding,
)
from nephilex.core.models import (
    PUBLIC_API_TAG,
    Confidence,
    Evidence,
    EvidenceStep,
    Finding,
    Location,
    Severity,
)

BIDI = "\u202e"


def _finding(**kw) -> Finding:
    base = {
        "id": "x:1",
        "rule_id": "patterns.python-yaml-load",
        "scanner": "patterns",
        "title": "t",
        "description": "d",
        "location": Location(path="app.py", start_line=3, snippet="yaml.load(data)"),
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "cwe": ["CWE-502"],
    }
    base.update(kw)
    return Finding(**base)


# --- model ---------------------------------------------------------------------------


def test_evidence_is_optional_and_old_reports_still_load():
    f = _finding()
    assert f.evidence is None
    old = json.loads(f.model_dump_json())
    old.pop("evidence")
    assert Finding.model_validate(old).evidence is None


def test_evidence_round_trips_through_json():
    f = _finding(evidence=Evidence(grade="likely", basis="b", path=[EvidenceStep(path="a.py")]))
    again = Finding.model_validate_json(f.model_dump_json())
    assert again.evidence == f.evidence


def test_step_code_is_one_line_with_controls_escaped_and_capped():
    step = EvidenceStep(
        path="a.py", line=1, code="  x = 1\x1b[31m" + BIDI + "y\r\n  z" + "q" * 400, note=BIDI
    )
    assert BIDI not in step.code and "\x1b" not in step.code and "\n" not in step.code
    assert "<U+202E>" in step.code and "<U+001B>" in step.code
    assert len(step.code) <= 160
    assert BIDI not in step.note


def test_step_code_masks_secrets():
    step = EvidenceStep(path="a.py", code='key = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in step.code


# --- grading -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kw", "grade"),
    [
        ({}, "likely"),  # a high-confidence rule of a precise scanner
        ({"confidence": Confidence.MEDIUM}, "possible"),
        ({"confidence": Confidence.LOW}, "possible"),
        ({"tags": ["test-context"]}, "possible"),
        ({"scanner": "malware"}, "possible"),
        ({"scanner": "sarif:semgrep"}, "possible"),
        ({"scanner": "git-security", "metadata": {"verification": "confirmed"}}, "possible"),
        ({"scanner": "dast", "metadata": {"verification": "verified"}}, "confirmed"),
        ({"scanner": "secrets", "metadata": {"verification": "live"}}, "confirmed"),
        ({"scanner": "secrets", "metadata": {"verification": "invalid"}}, "likely"),
        ({"scanner": "secrets", "confidence": Confidence.MEDIUM}, "possible"),
    ],
)
def test_grades_for_rule_findings(kw, grade):
    f = _finding(**kw)
    assert grade_finding(f, [])[0] == grade


@pytest.mark.parametrize(
    ("manifest", "grade"),
    [
        ("requirements.txt", "confirmed"),
        ("web/package-lock.json", "confirmed"),
        ("package.json", "possible"),
        ("go.mod", "likely"),
    ],
)
def test_dependency_grades_depend_on_whether_the_version_is_exact(manifest, grade):
    f = _finding(
        scanner="dependencies",
        rule_id="dependencies.GHSA-x",
        location=Location(path=manifest, snippet="pkg==1.0.0"),
        metadata={"cve": "CVE-2024-1", "installed_version": "1.0.0", "fixed_version": "1.0.1"},
    )
    grade_got, basis = grade_finding(f, [])
    assert grade_got == grade and basis


def _taint(**kw) -> Finding:
    path = [
        EvidenceStep(path="app.py", line=7, role="source", note="request.args['q'] is x"),
        EvidenceStep(path="app.py", line=10, role="sink", note="passed to cursor.execute"),
    ]
    base = {
        "scanner": "ast-python",
        "rule_id": "ast-python.ast-sql-injection",
        "cwe": ["CWE-89"],
        "metadata": {"analysis": "taint-dataflow"},
        "evidence": Evidence(path=path),
    }
    base.update(kw)
    return _finding(**base)


@pytest.mark.parametrize(
    ("kw", "grade"),
    [
        ({}, "likely"),
        ({"tags": ["operator-input"], "confidence": Confidence.LOW}, "possible"),
        ({"tags": [PUBLIC_API_TAG]}, "possible"),
        ({"tags": ["test-context"]}, "possible"),
        ({"evidence": None}, "possible"),  # no recorded source
        # not a flow from a source: graded like any exact rule match
        ({"evidence": None, "rule_id": "ast-python.ast-weak-random"}, "likely"),
        ({"metadata": {"analysis": "taint-dataflow", "source": "archive-entry"}}, "likely"),
        (
            {"scanner": "ast-js", "metadata": {"analysis": "taint-dataflow", "source_kind": "env"}},
            "possible",
        ),
    ],
)
def test_grades_for_taint_findings(kw, grade):
    f = _taint(**kw)
    ev = build_evidence(f)
    assert ev.grade == grade
    if grade == "likely" and "rule_id" not in kw:
        assert "no recognized sanitizer" in ev.basis


def test_grading_never_changes_severity_confidence_or_fingerprint():
    findings = [
        _finding(),
        _taint(),
        _finding(scanner="secrets", metadata={"verification": "live"}),
    ]
    before = [(f.severity, f.confidence, f.likelihood, f.fingerprint()) for f in findings]
    attach_evidence(findings)
    assert all(f.evidence is not None for f in findings)
    assert [(f.severity, f.confidence, f.likelihood, f.fingerprint()) for f in findings] == before


def test_every_finding_gets_two_to_four_verify_steps():
    for f in (_finding(), _taint(), _finding(scanner="malware", why_vulnerable="")):
        ev = build_evidence(f)
        assert 2 <= len(ev.verify) <= 4
        assert all("you own" in v for v in ev.verify if "test environment" in v)


def test_rule_findings_get_a_one_step_path():
    ev = build_evidence(_finding())
    assert [(s.role, s.path, s.line, s.code) for s in ev.path] == [
        ("sink", "app.py", 3, "yaml.load(data)")
    ]


def test_cap_keeps_source_and_sink():
    steps = [EvidenceStep(path="a.py", line=i, role="step") for i in range(30)]
    steps[0] = EvidenceStep(path="a.py", line=0, role="source")
    steps[-1] = EvidenceStep(path="a.py", line=29, role="sink")
    capped = cap_path(steps)
    assert len(capped) == MAX_PATH_STEPS
    assert capped[0].role == "source" and capped[-1].role == "sink"
    assert capped[1].role == "elided"
