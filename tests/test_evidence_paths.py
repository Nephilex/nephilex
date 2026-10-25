"""Evidence paths recorded by the Python and JavaScript taint engines."""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.core.config import AIConfig, Config
from nephilex.core.engine import ScanEngine
from nephilex.core.evidence import (
    MAX_PATH_STEPS,
    compact_path,
)
from nephilex.core.models import (
    Finding,
    ScanResult,
    Severity,
)
from nephilex.core.project import Project


def _scan(tmp_path: Path, files: dict[str, str], scanners: list[str]) -> ScanResult:
    for name, code in files.items():
        (tmp_path / name).write_text(code, encoding="utf-8")
    cfg = Config(
        scanners=scanners,
        cache=False,
        ai=AIConfig(enabled=False),
        audit_log=False,
        min_severity=Severity.INFO,
    )
    return ScanEngine(cfg).scan(Project.from_path(tmp_path))


# --- analysis values: history never takes part in equality -------------------------


def test_python_values_compare_and_hash_without_their_trail():
    from nephilex.scanners._pyflow import TAINT, Val, extend_trail, join

    hop = (0, 1, 1, "source", "request.args", None)
    with_trail = Val(taint=True, trail=(hop,))
    assert with_trail == TAINT and hash(with_trail) == hash(TAINT)
    assert join(with_trail, TAINT) == TAINT
    long = ()
    for i in range(40):
        long = extend_trail(long, (i, i, 1, "step", f"assigned to v{i}", None))
    assert len(long) == 16 and long[0][0] == 0 and long[1][3] == "elided"


def test_js_taints_compare_without_their_steps():
    from nephilex.scanners._jsflow import ALL_KINDS, Taint, add_step

    t = Taint("request", "req.query.q", 3, ALL_KINDS)
    moved = add_step(t, (4, 1, "assigned to q"))
    assert moved == t and hash(moved) == hash(t) and moved.steps


# --- recorded paths ------------------------------------------------------------------

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


def _one(result: ScanResult, rule_id: str) -> Finding:
    found = [f for f in result.findings if f.rule_id == rule_id]
    assert len(found) == 1, [f.rule_id for f in result.findings]
    return found[0]


def test_python_taint_records_source_steps_and_sink(tmp_path):
    pytest.importorskip("tree_sitter_python")
    f = _one(
        _scan(tmp_path, {"app.py": _FLASK_SQL}, ["ast-python"]), "ast-python.ast-sql-injection"
    )
    ev = f.evidence
    assert ev is not None and ev.grade == "likely"
    assert [(s.role, s.line) for s in ev.path] == [
        ("source", 7),
        ("step", 7),
        ("step", 8),
        ("sink", 10),
    ]
    assert ev.path[0].note == "request.args['q'] is attacker-controlled"
    assert ev.path[0].code == "q = request.args['q']"
    assert ev.path[2].note == "assigned to query"
    assert ev.path[-1].note == "passed to cursor.execute"
    assert compact_path(ev) == (
        "request.args['q'] (app.py:7) -> q (app.py:7) -> query (app.py:8) "
        "-> cursor.execute (app.py:10)"
    )
    assert any("app.py line 7" in v for v in ev.verify)


def test_python_long_flow_is_capped(tmp_path):
    pytest.importorskip("tree_sitter_python")
    hops = "".join(f"    v{i + 1} = v{i}\n" for i in range(25))
    code = (
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/r')\ndef r():\n    v0 = request.args['c']\n"
        + hops
        + "    os.system(v25)\n    return 'ok'\n"
    )
    f = _one(_scan(tmp_path, {"app.py": code}, ["ast-python"]), "ast-python.ast-command-injection")
    path = f.evidence.path
    assert len(path) <= MAX_PATH_STEPS
    assert path[0].role == "source" and path[0].line == 6
    assert path[-1].role == "sink" and path[-1].note == "passed to os.system"
    assert any(s.role == "elided" for s in path)


def test_python_guard_that_does_not_cover_the_sink_is_shown(tmp_path):
    pytest.importorskip("tree_sitter_python")
    code = (
        "import sqlite3, os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/r')\ndef r():\n    name = request.args['n']\n"
        "    p = os.path.realpath(os.path.join('/srv', name))\n"
        "    if not p.startswith('/srv/'):\n        return 'no'\n"
        "    sqlite3.connect('x').execute('SELECT ' + p)\n    return 'ok'\n"
    )
    result = _scan(tmp_path, {"app.py": code}, ["ast-python"])
    f = _one(result, "ast-python.ast-sql-injection")
    roles = [s.role for s in f.evidence.path]
    assert roles[0] == "source" and roles[-1] == "sink"
    assert "guard" in roles


def test_cross_file_records_caller_source_call_site_and_callee_sink(tmp_path):
    pytest.importorskip("tree_sitter_python")
    files = {
        "routes.py": (
            "from flask import Flask, request\nfrom db import run_query\n"
            "app = Flask(__name__)\n\n@app.route('/u')\ndef handler():\n"
            "    run_query(request.args.get('id'))\n    return 'ok'\n"
        ),
        "db.py": (
            "import sqlite3\n\ndef run_query(uid):\n"
            "    sql = 'SELECT * FROM users WHERE id = ' + uid\n"
            "    cur = sqlite3.connect('x').cursor()\n    return cur.execute(sql)\n"
        ),
    }
    result = _scan(tmp_path, files, ["ast-python", "ast-python-xfile"])
    f = _one(result, "ast-python-xfile.ast-sql-injection")
    steps = [(s.role, s.path, s.line) for s in f.evidence.path]
    assert steps[0] == ("source", "routes.py", 7)
    assert ("step", "routes.py", 7) in steps
    assert ("step", "db.py", 3) in steps  # the parameter
    assert steps[-1] == ("sink", "db.py", 6)
    assert f.evidence.grade == "likely"


_JS = (
    "const express = require('express');\n"
    "const db = require('./db');\n"
    "const app = express();\n"
    "function lookup(term) {\n"
    '  const sql = "SELECT * FROM t WHERE name = \'" + term + "\'";\n'
    "  return db.query(sql);\n"
    "}\n"
    "app.get('/search', (req, res) => {\n"
    "  const q = req.query.q;\n"
    "  const term = q.trim();\n"
    '  const query = "SELECT * FROM items WHERE name = \'" + term + "\'";\n'
    "  db.query(query);\n"
    "  lookup(req.query.other);\n"
    "  res.send('ok');\n"
    "});\n"
)


def test_js_taint_records_source_steps_and_sink(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    result = _scan(tmp_path, {"server.js": _JS}, ["ast-js"])
    by_line = {f.location.start_line: f for f in result.findings if "sql" in f.rule_id}
    direct = by_line[12].evidence
    assert [(s.role, s.line) for s in direct.path] == [
        ("source", 9),
        ("step", 9),
        ("step", 10),
        ("step", 11),
        ("sink", 12),
    ]
    assert direct.path[0].note == "req.query.q is attacker-controlled"
    assert direct.grade == "likely"
    helper = by_line[13].evidence  # reported at the call into lookup()
    assert [(s.role, s.line) for s in helper.path] == [
        ("source", 13),
        ("step", 13),
        ("step", 5),
        ("sink", 6),
    ]
    assert helper.path[1].note == "passed to lookup() as term"


def test_kept_finding_takes_over_the_path_of_the_merged_taint_finding(tmp_path):
    pytest.importorskip("tree_sitter_python")
    code = (
        "import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/c')\ndef c():\n    raw = request.args.get('data')\n"
        "    return str(yaml.load(raw))\n"
    )
    result = _scan(tmp_path, {"app.py": code}, ["patterns", "ast-python"])
    f = _one(result, "patterns.python-yaml-load")  # kept: it has a deterministic fix
    ev = f.evidence
    assert [(s.role, s.line) for s in ev.path] == [("source", 6), ("step", 6), ("sink", 7)]
    assert ev.grade == "likely" and "data-flow tier traced" in ev.basis
