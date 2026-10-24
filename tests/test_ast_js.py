"""Tests for the JavaScript/TypeScript AST taint scanner.

Emphasis on the false-positive guards, parameterized queries, sanitizers, and
constants must NOT be flagged, since that noise is exactly what regex tiers get
wrong on real Node/TS code. Skips cleanly if the [ast] extra is absent.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from nephilex.core.config import Config  # noqa: E402
from nephilex.core.models import Confidence, Severity  # noqa: E402
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.scanners import ast_js  # noqa: E402


def _run(tmp_path, filename: str, code: str):
    from nephilex.analysis.repository import RepositoryAnalyzer
    from nephilex.core.project import Project

    (tmp_path / filename).write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("ast-js")().scan(ctx))


def _cwes(findings):
    return {c for f in findings for c in f.cwe}


def test_available_and_registered():
    assert ast_js.is_available() is True
    assert "ast-js" in registry.scanners()


# --- true positives ---------------------------------------------------------
def test_multi_hop_sql_injection(tmp_path):
    findings = _run(
        tmp_path,
        "app.js",
        "app.get('/u',(req,res)=>{\n"
        "  const name = req.query.user;\n"
        "  const a = name;\n"
        "  const q = a;\n"
        "  db.query('SELECT * FROM u WHERE n=' + q);\n"
        "});\n",
    )
    assert "CWE-89" in _cwes(findings)
    assert findings[0].confidence.label == "High"


def test_xss_innerhtml_assignment(tmp_path):
    findings = _run(
        tmp_path,
        "ui.js",
        "app.get('/p',(req,res)=>{\n"
        "  const c = req.query.c;\n"
        "  document.getElementById('x').innerHTML = c;\n"
        "});\n",
    )
    assert "CWE-79" in _cwes(findings)


def test_command_injection_typescript(tmp_path):
    findings = _run(
        tmp_path,
        "svc.ts",
        "app.get('/p',(req: any, res: any) => {\n"
        "  const host = req.query.host;\n"
        "  cp.exec('ping ' + host);\n"
        "});\n",
    )
    assert "CWE-78" in _cwes(findings)


def test_path_traversal_and_eval(tmp_path):
    findings = _run(
        tmp_path,
        "f.js",
        "app.get('/r',(req,res)=>{\n"
        "  const p = req.query.file;\n"
        "  fs.readFileSync(p);\n"
        "  const e = req.body.expr;\n"
        "  eval(e);\n"
        "});\n",
    )
    assert "CWE-22" in _cwes(findings)
    assert "CWE-95" in _cwes(findings)


# --- false-positive guards (the whole point) --------------------------------
def test_parameterized_query_is_safe(tmp_path):
    """Taint in the bound-params array, not the query string -> NOT SQLi."""
    findings = _run(
        tmp_path,
        "db.js",
        "app.get('/u',(req,res)=>{\n"
        "  const id = req.query.id;\n"
        "  db.query('SELECT * FROM u WHERE id = ?', [id]);\n"
        "});\n",
    )
    assert "CWE-89" not in _cwes(findings)


def test_sanitized_html_is_safe(tmp_path):
    findings = _run(
        tmp_path,
        "ui.js",
        "app.get('/p',(req,res)=>{\n"
        "  const c = req.query.c;\n"
        "  el.innerHTML = DOMPurify.sanitize(c);\n"
        "});\n",
    )
    assert "CWE-79" not in _cwes(findings)


def test_numeric_coercion_is_safe(tmp_path):
    findings = _run(
        tmp_path,
        "db.js",
        "app.get('/u',(req,res)=>{\n"
        "  const id = Number(req.query.id);\n"
        "  db.query('SELECT * FROM u WHERE id=' + id);\n"
        "});\n",
    )
    assert "CWE-89" not in _cwes(findings)


def test_constant_is_safe(tmp_path):
    findings = _run(
        tmp_path, "db.js", "const table = 'users';\ndb.query('SELECT * FROM ' + table);\n"
    )
    assert "CWE-89" not in _cwes(findings)


def test_taint_scoped_per_function(tmp_path):
    findings = _run(
        tmp_path,
        "s.js",
        "function a(){ const x = req.query.q; }\n"
        "function b(){ const x = 'safe'; db.query('SELECT ' + x); }\n",
    )
    assert "CWE-89" not in _cwes(findings)


def test_ast_beats_regex_via_dedupe(tmp_path):
    """On a real SQLi, the AST (High) finding wins over the regex (Low) one."""
    from nephilex.core.engine import ScanEngine
    from nephilex.core.project import Project

    (tmp_path / "app.js").write_text(
        "app.get('/u',(req,res)=>{\n"
        "  const n = req.query.user;\n"
        "  db.query('SELECT * FROM u WHERE n=' + n);\n"
        "});\n",
        encoding="utf-8",
    )
    result = ScanEngine(Config(scanners=["patterns", "ast-js"])).scan(Project.from_path(tmp_path))
    sqli = [f for f in result.findings if "CWE-89" in f.cwe]
    assert len(sqli) == 1
    assert sqli[0].scanner == "ast-js"


def test_ast_suppresses_regex_false_positive_on_sanitized_html(tmp_path):
    """When ast-js ran, the regex innerHTML guess is dropped for JS/TS files, so a
    sanitized assignment produces no finding at all (the key FP fix)."""
    from nephilex.core.engine import ScanEngine
    from nephilex.core.project import Project

    (tmp_path / "ui.js").write_text(
        "app.get('/p',(req,res)=>{\n"
        "  const bio = req.query.bio;\n"
        "  el.innerHTML = DOMPurify.sanitize(bio);\n"
        "});\n",
        encoding="utf-8",
    )
    result = ScanEngine(Config(scanners=["patterns", "ast-js"])).scan(Project.from_path(tmp_path))
    assert not [f for f in result.findings if "CWE-79" in f.cwe]


def test_example_code_is_reported_at_low_confidence(tmp_path):
    """Example and demo code is still reported, one severity step down and at low
    confidence, as test code is; the same code elsewhere keeps its rating."""
    code = "app.post('/upload', (req, res) => {\n  res.send('Uploaded ' + req.files.f.name);\n});\n"
    (tmp_path / "example").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "example" / "server.js").write_text(code, encoding="utf-8")
    (tmp_path / "lib" / "server.js").write_text(code, encoding="utf-8")
    findings = _run(tmp_path, "unrelated.js", "const x = 1;\n")
    by_path = {f.location.path: f for f in findings if "CWE-79" in f.cwe}
    example, lib = by_path["example/server.js"], by_path["lib/server.js"]
    assert example.confidence == Confidence.LOW
    assert example.severity == Severity(lib.severity - 1)
    assert "example-context" in example.tags
    assert lib.confidence == Confidence.HIGH
    assert "example-context" not in lib.tags
