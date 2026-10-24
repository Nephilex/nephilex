"""``nephilex import`` and ``nephilex scan --import-sarif``."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.models import ScanResult

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "sarif"
TOOLS = ("semgrep", "codeql", "gitleaks", "trivy", "bandit")
# CI terminals get colored help, and the escape codes can split an option name.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _files(*names: str) -> list[str]:
    return [str(FIXTURES / f"{n}.sarif") for n in names]


def _import(project, *args: str):
    return runner.invoke(app, ["import", *args, "--project", str(project.root), "--no-ai", "-q"])


def _json(output: str) -> ScanResult:
    return ScanResult.model_validate_json(output[output.index("{") :])


def test_import_is_registered():
    res = runner.invoke(app, ["--help"])
    assert "import" in res.output
    res = runner.invoke(app, ["import", "--help"])
    assert res.exit_code == 0 and "--project" in _ANSI.sub("", res.output)


def test_import_json_report(vulnerable_project):
    res = _import(vulnerable_project, *_files(*TOOLS), "-f", "json")
    assert res.exit_code == 0, res.output
    result = _json(res.stdout)
    assert result.scanners_run == [
        "sarif:semgrep-oss",
        "sarif:codeql",
        "sarif:gitleaks",
        "sarif:trivy",
        "sarif:bandit",
    ]
    assert result.findings and all(f.scanner.startswith("sarif:") for f in result.findings)
    summary = result.project_summary["imported_sarif"]
    assert summary["results"] == 13 and summary["imported"] == 12
    # Semgrep/CodeQL SQL injection, Semgrep/Bandit shell, CodeQL/Bandit MD5.
    assert summary["merged"] == 3
    assert len(result.findings) == 9
    assert "AKIAIOSFODNN7EXAMPLE" not in res.stdout


def test_import_cross_tool_duplicate_keeps_stronger(vulnerable_project):
    res = _import(vulnerable_project, *_files("semgrep", "codeql"), "-f", "json")
    result = _json(res.stdout)
    sql = [f for f in result.findings if "CWE-89" in f.cwe]
    assert len(sql) == 1
    assert sql[0].scanner == "sarif:codeql"  # HIGH beats Semgrep's MEDIUM
    assert sql[0].metadata["also_reported_by"][0]["scanner"] == "sarif:semgrep-oss"


@pytest.mark.parametrize(("threshold", "code"), [("critical", 1), ("high", 1)])
def test_import_fail_on_gates(vulnerable_project, threshold, code):
    res = _import(vulnerable_project, *_files(*TOOLS), "--fail-on", threshold)
    assert res.exit_code == code, res.output


def test_import_fail_on_passes_below_threshold(vulnerable_project):
    res = _import(vulnerable_project, *_files("bandit"), "--fail-on", "critical")
    assert res.exit_code == 0, res.output


def test_import_min_severity(vulnerable_project):
    res = _import(vulnerable_project, *_files(*TOOLS), "-f", "json", "--min-severity", "critical")
    result = _json(res.stdout)
    assert [f.rule_id for f in result.findings] == ["trivy.CVE-2020-14343"]


@pytest.mark.parametrize("fmt", ["sarif", "markdown", "html", "csv", "junit", "gitlab"])
def test_import_other_formats(vulnerable_project, tmp_path, fmt):
    out = tmp_path / f"report.{fmt}"
    res = _import(vulnerable_project, *_files("codeql"), "-f", fmt, "-o", str(out))
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "sql-injection" in text
    if fmt == "sarif":
        doc = json.loads(text)
        ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
        assert "codeql.py/sql-injection" in ids


def test_import_baseline_suppresses_known(vulnerable_project, tmp_path):
    base = tmp_path / "baseline.json"
    res = _import(vulnerable_project, *_files(*TOOLS), "-f", "json", "-o", str(base))
    assert res.exit_code == 0, res.output
    res = _import(
        vulnerable_project,
        *_files(*TOOLS),
        "-f",
        "json",
        "--baseline",
        str(base),
        "--fail-on",
        "low",
    )
    assert res.exit_code == 0, res.output
    assert _json(res.stdout).findings == []


def test_import_honors_allowlist_and_exclude_paths(vulnerable_project):
    (vulnerable_project.root / ".nephilex.yml").write_text(
        "allow:\n"
        "  - rule: py/sql-injection\n"
        "    reason: accepted for the test\n"
        "exclude_paths:\n"
        "  - Dockerfile\n",
        encoding="utf-8",
    )
    res = _import(vulnerable_project, *_files("codeql", "trivy"), "-f", "json")
    assert res.exit_code == 0, res.output
    rules = {f.rule_id for f in _json(res.stdout).findings}
    assert "codeql.py/sql-injection" not in rules
    assert "trivy.DS001" not in rules
    assert "trivy.CVE-2020-14343" in rules


def test_import_enrichment_fills_reasoning(vulnerable_project):
    res = runner.invoke(
        app,
        ["import", *_files("bandit"), "--project", str(vulnerable_project.root), "-f", "json"],
    )
    assert res.exit_code == 0, res.output
    shell = [f for f in _json(res.stdout).findings if f.rule_id == "bandit.B602"][0]
    assert shell.attacker_perspective and shell.business_impact


@pytest.mark.parametrize(
    "args",
    [
        ["does-not-exist.sarif"],
        [str(FIXTURES / "deep-nesting.sarif")],
        [str(FIXTURES / "semgrep.sarif"), "--fail-on", "hgih"],
        [str(FIXTURES / "semgrep.sarif"), "--project", "no/such/dir"],
    ],
)
def test_import_usage_errors_exit_2(tmp_path, args):
    if "--project" not in args:
        args = [*args, "--project", str(tmp_path)]
    res = runner.invoke(app, ["import", *args, "-q"])
    assert res.exit_code == 2, res.output


def test_import_warns_about_dropped_paths(tmp_path):
    res = runner.invoke(
        app, ["import", *_files("edge-cases"), "--project", str(tmp_path), "--no-ai", "-f", "json"]
    )
    assert res.exit_code == 0, res.output
    # The console wraps at its width, and the fixture path in each warning is
    # as long as the checkout path, so compare with whitespace collapsed.
    err = " ".join(res.stderr.split())
    assert "(EC001) dropped: path escapes the project root" in err


def test_scan_import_sarif_merges_duplicates(vulnerable_project):
    args = ["scan", str(vulnerable_project.root), "--no-ai", "--no-cache", "-q", "-f", "json"]
    for f in _files(*TOOLS):
        args += ["--import-sarif", f]
    res = runner.invoke(app, args)
    assert res.exit_code == 0, res.output
    result = _json(res.stdout)
    assert "sarif:codeql" in result.scanners_run and "ast-python" in result.scanners_run
    sql = [f for f in result.findings if "CWE-89" in f.cwe and f.location.path == "app.py"]
    assert [f.scanner for f in sql] == ["ast-python"]
    reporters = {e["scanner"] for e in sql[0].metadata["also_reported_by"]}
    assert reporters == {"sarif:semgrep-oss", "sarif:codeql"}
    line4 = [
        f
        for f in result.findings
        if "CWE-798" in f.cwe and f.location.path == "app.py" and f.scanner != "chains"
    ]
    assert [f.scanner for f in line4] == ["secrets"]
    assert line4[0].metadata["also_reported_by"][0]["scanner"] == "sarif:gitleaks"
    # Imported findings nothing native matched stay in the report.
    assert any(f.rule_id == "gitleaks.generic-api-key" for f in result.findings)
    assert result.project_summary["imported_sarif"]["merged"] >= 5


def test_scan_import_sarif_bad_file_exits_2(vulnerable_project, tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{", encoding="utf-8")
    res = runner.invoke(
        app, ["scan", str(vulnerable_project.root), "--no-ai", "-q", "--import-sarif", str(bad)]
    )
    assert res.exit_code == 2, res.output


def test_scan_import_sarif_rejects_url_target():
    res = runner.invoke(
        app, ["scan", "https://example.com", "-q", "--import-sarif", _files("semgrep")[0]]
    )
    assert res.exit_code == 2, res.output
