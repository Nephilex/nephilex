"""How reports show evidence, and that hostile code in it stays inert."""

from __future__ import annotations

import json

import pytest

from nephilex.core.evidence import (
    attach_evidence,
)
from nephilex.core.models import (
    Confidence,
    Evidence,
    EvidenceStep,
    Finding,
    Location,
    ScanResult,
    Severity,
)

BIDI = "\u202e"


_FLASK_SQL = (
    "import sqlite3\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.route('/search')\n"
    "def search():\n"
    "    q = request.args['q']\n"
    '    query = "SELECT * FROM items WHERE name = \'" + q + "\'"\n'
    "    cursor = sqlite3.connect('db').cursor()\n"
    "    cursor.execute(query)\n"
    "    return 'ok'\n"
)


def _hostile_result() -> ScanResult:
    """A SQL injection finding whose recorded path quotes hostile code."""
    from datetime import datetime, timezone

    code = "<script>alert(1)</script> " + BIDI + "x"
    f = Finding(
        id="x:1",
        rule_id="ast-python.ast-sql-injection",
        scanner="ast-python",
        title="t",
        description="d",
        location=Location(path="app.py", start_line=10, snippet="cursor.execute(q)"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=["CWE-89"],
        metadata={"analysis": "taint-dataflow"},
        evidence=Evidence(
            path=[
                EvidenceStep(path="app.py", line=7, role="source", code=code, note=code),
                EvidenceStep(path="app.py", line=10, role="sink", code="cursor.execute(q)"),
            ]
        ),
    )
    attach_evidence([f])
    return ScanResult(target=".", started_at=datetime.now(timezone.utc), findings=[f])


def test_html_report_escapes_hostile_evidence():
    from nephilex.reporting.html import HTMLReporter

    out = HTMLReporter().render(_hostile_result())
    assert '<details class="evidence">' in out and ">likely<" in out
    assert "<script>alert" not in out and "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert BIDI not in out and "&lt;U+202E&gt;" in out
    assert "How to verify" in out


def test_markdown_report_escapes_hostile_evidence():
    from nephilex.reporting.markdown import MarkdownReporter

    out = MarkdownReporter().render(_hostile_result())
    assert "Evidence: likely" in out and BIDI not in out
    # Code renders literally inside a code span; the note is escaped prose.
    assert "`<script>alert(1)</script> <U+202E>x`" in out
    assert out.count("<script>") == 1 and "&lt;script" in out


def test_sarif_has_code_flows_grade_and_unchanged_fingerprints():
    from nephilex.reporting.sarif import SARIFReporter

    result = _hostile_result()
    f = result.findings[0]
    doc = json.loads(SARIFReporter().render(result))
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["grade"] == "likely"
    flow = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [loc["properties"]["role"] for loc in flow] == ["source", "sink"]
    first = flow[0]["location"]
    assert first["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert first["physicalLocation"]["region"]["startLine"] == 7
    assert first["message"]["text"].startswith("source: ")
    assert res["partialFingerprints"]["nephilexFingerprint"] == f.fingerprint()
    bare = f.model_copy(update={"evidence": None})
    assert bare.fingerprint() == f.fingerprint()
    plain = json.loads(SARIFReporter().render(result.model_copy(update={"findings": [bare]})))[
        "runs"
    ][0]["results"][0]
    assert "codeFlows" not in plain
    assert plain["partialFingerprints"] == res["partialFingerprints"]


def test_sarif_import_of_our_own_report_ignores_evidence(tmp_path):
    from nephilex.importers.sarif import parse_sarif
    from nephilex.reporting.sarif import SARIFReporter

    result = _hostile_result()
    doc = json.loads(SARIFReporter().render(result))
    bare = result.model_copy(
        update={"findings": [result.findings[0].model_copy(update={"evidence": None})]}
    )
    doc_bare = json.loads(SARIFReporter().render(bare))
    (tmp_path / "app.py").write_text("x\n" * 12, encoding="utf-8")
    a = parse_sarif(doc, project_root=tmp_path, source="a.sarif").findings
    b = parse_sarif(doc_bare, project_root=tmp_path, source="a.sarif").findings
    assert a and [f.fingerprint() for f in a] == [f.fingerprint() for f in b]


def test_json_report_carries_evidence():
    from nephilex.reporting.json_reporter import JSONReporter

    doc = json.loads(JSONReporter().render(_hostile_result()))
    ev = doc["findings"][0]["evidence"]
    assert ev["grade"] == "likely" and ev["path"][0]["role"] == "source"
    assert BIDI not in json.dumps(ev, ensure_ascii=False)


def test_mcp_scan_returns_evidence():
    from nephilex.mcp.server import evidence_dict

    data = evidence_dict(_hostile_result().findings[0])
    assert data is not None and data["grade"] == "likely"
    assert data["path"][0]["role"] == "source" and len(data["verify"]) >= 2


def test_scan_table_shows_grade_and_compact_path(tmp_path):
    pytest.importorskip("tree_sitter_python")
    from typer.testing import CliRunner

    from nephilex.cli.main import app

    (tmp_path / "app.py").write_text(_FLASK_SQL, encoding="utf-8")
    res = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "-s", "ast-python", "--no-ai", "--no-cache"],
        env={"COLUMNS": "250"},
    )
    assert "likely" in res.output
    assert "request.args['q'] (app.py:7) -> q (app.py:7)" in res.output
