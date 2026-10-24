"""Library mode: public function parameters as taint sources.

Covers the auto detection (package manifest, web entry points), the
``library_mode`` config key, the shape rules that keep by-design pass-through
APIs quiet, the low-confidence ``public-api`` findings and the ``--fail-on``
exclusion.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from datetime import datetime, timezone  # noqa: E402

from nephilex.analysis.library import (  # noqa: E402
    module_is_public,
    resolve_library_mode,
)
from nephilex.analysis.repository import RepositoryAnalyzer  # noqa: E402
from nephilex.core.config import Config, ConfigError  # noqa: E402
from nephilex.core.engine import ScanEngine  # noqa: E402
from nephilex.core.models import (  # noqa: E402
    PUBLIC_API_TAG,
    Confidence,
    Finding,
    Location,
    ScanResult,
    Severity,
)
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.core.project import Project  # noqa: E402

PYPROJECT = '[project]\nname = "pkg"\nversion = "1.0"\n'


def _write(tmp_path, files: dict[str, str]) -> Project:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    return project


def _scan(tmp_path, files: dict[str, str], mode: str = "on") -> list[Finding]:
    project = _write(tmp_path, files)
    cfg = Config()
    cfg.library_mode = mode
    ctx = ScannerContext(project=project, config=cfg, ai=None)
    return list(registry.get_scanner("ast-python")().scan(ctx))


def _rules(tmp_path, code: str, mode: str = "on", name: str = "pkg/core.py") -> set[str]:
    return {f.rule_id.split(".", 1)[1] for f in _scan(tmp_path, {name: code}, mode)}


# --- detection ------------------------------------------------------------------
def test_auto_is_on_for_a_package_without_a_web_app(tmp_path):
    project = _write(
        tmp_path, {"pyproject.toml": PYPROJECT, "pkg/core.py": "def f(x):\n    return x\n"}
    )
    mode = resolve_library_mode(project, "auto")
    assert mode.active and "pyproject.toml" in mode.reason


@pytest.mark.parametrize(
    "app",
    [
        "from flask import Flask\napp = Flask(__name__)\n",
        "import fastapi\napp = fastapi.FastAPI()\n",
        "from aiohttp import web\napp = web.Application()\n",
        "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n",
    ],
)
def test_auto_is_off_for_a_web_application(tmp_path, app):
    project = _write(
        tmp_path, {"setup.py": "from setuptools import setup\nsetup()\n", "pkg/app.py": app}
    )
    mode = resolve_library_mode(project, "auto")
    assert not mode.active and "entry point" in mode.reason


def test_auto_ignores_framework_names_in_docstrings_and_example_apps(tmp_path):
    project = _write(
        tmp_path,
        {
            "setup.cfg": "[metadata]\nname = pkg\n",
            "pkg/ext.py": '"""Use it like this::\n\n    app = Flask(__name__)\n"""\n',
            "examples/demo.py": "from flask import Flask\napp = Flask(__name__)\n",
        },
    )
    assert resolve_library_mode(project, "auto").active


def test_auto_is_off_without_a_package_manifest(tmp_path):
    project = _write(tmp_path, {"tool.py": "def f(x):\n    return x\n"})
    mode = resolve_library_mode(project, "auto")
    assert not mode.active and "manifest" in mode.reason


def test_explicit_settings_override_detection(tmp_path):
    project = _write(tmp_path, {"tool.py": "def f(x):\n    return x\n"})
    assert resolve_library_mode(project, "on").active
    app = _write(tmp_path / "app", {"pyproject.toml": PYPROJECT, "pkg/core.py": "x = 1\n"})
    assert not resolve_library_mode(app, "off").active


@pytest.mark.parametrize(
    "path,public",
    [
        ("pkg/core.py", True),
        ("pkg/__init__.py", True),
        ("pkg/_internal/core.py", False),
        ("pkg/_compat.py", False),
        ("pkg/__main__.py", False),
        ("tests/test_core.py", False),
        ("docs/conf.py", False),
        ("setup.py", False),
    ],
)
def test_module_is_public(path, public):
    assert module_is_public(path) is public


# --- config ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected",
    [
        ("library_mode: auto\n", "auto"),
        ("library_mode: 'on'\n", "on"),
        ("library_mode: on\n", "on"),  # YAML 1.1 boolean
        ("library_mode: off\n", "off"),
        ("library_mode: OFF\n", "off"),
        ("{}\n", "auto"),
    ],
)
def test_library_mode_config_key(text, expected):
    assert Config.from_yaml(text).library_mode == expected


@pytest.mark.parametrize(
    "text", ["library_mode: yes-please\n", "library_mode: 3\n", "library_mode: []\n"]
)
def test_library_mode_rejects_other_values(text):
    with pytest.raises(ConfigError, match="library_mode"):
        Config.from_yaml(text)


# --- sources and shapes ------------------------------------------------------------
def test_public_parameter_embedded_in_eval_is_reported_low_confidence(tmp_path):
    code = "def parse_vector(data):\n    return eval('[' + data + ']')\n"
    (f,) = [x for x in _scan(tmp_path, {"pkg/core.py": code}) if "code-injection" in x.rule_id]
    assert f.confidence == Confidence.LOW
    assert PUBLIC_API_TAG in f.tags and "library-mode" in f.tags
    assert f.metadata["source"] == "public-api"
    assert f.metadata["public_function"] == "parse_vector"
    assert "public function `parse_vector()`" in f.description


def test_library_mode_off_reports_nothing(tmp_path):
    code = "def parse_vector(data):\n    return eval('[' + data + ']')\n"
    assert "ast-code-injection" not in _rules(tmp_path, code, mode="off")


def test_method_of_public_class_and_field_of_caller_data(tmp_path):
    code = (
        "class Field:\n"
        "    @classmethod\n"
        "    def from_dict(cls, data):\n"
        "        return cls(kind=eval(data['field_type']))\n"
    )
    findings = _scan(tmp_path, {"pkg/core.py": code})
    assert [f.metadata.get("public_function") for f in findings] == ["Field.from_dict"]


@pytest.mark.parametrize(
    "code",
    [
        "def _helper(expr):\n    return eval('(' + expr + ')')\n",
        "class _Impl:\n    def run(self, expr):\n        return eval('(' + expr + ')')\n",
        "__all__ = ['other']\ndef run(expr):\n    return eval('(' + expr + ')')\n",
        "def outer():\n    def run(expr):\n        return eval('(' + expr + ')')\n    return run\n",
    ],
)
def test_private_or_unexported_functions_are_not_sources(tmp_path, code):
    assert "ast-code-injection" not in _rules(tmp_path, code)


def test_private_module_is_not_a_source(tmp_path):
    code = "def run(expr):\n    return eval('(' + expr + ')')\n"
    assert "ast-code-injection" not in _rules(tmp_path, code, name="pkg/_internal/core.py")


@pytest.mark.parametrize(
    "code,rule",
    [
        ("def read(path):\n    return open(path).read()\n", "ast-path-traversal"),
        ("def evaluate(expr):\n    return eval(expr)\n", "ast-code-injection"),
        (
            "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
            "ast-command-injection",
        ),
        ("import requests\ndef fetch(url):\n    return requests.get(url)\n", "ast-ssrf"),
        ("from markupsafe import Markup\ndef safe(html):\n    return Markup(html)\n", "ast-xss"),
        (
            "import subprocess\ndef clone(url):\n    subprocess.run(['git', 'clone', url])\n",
            "ast-command-injection",
        ),
    ],
)
def test_by_design_pass_through_apis_are_not_reported(tmp_path, code, rule):
    """A function whose job is the operation on its argument is not an injection."""
    assert rule not in _rules(tmp_path, code)


@pytest.mark.parametrize(
    "code,rule",
    [
        (
            "import os\ndef load(name):\n    return open(os.path.join(ROOT, name)).read()\n",
            "ast-path-traversal",
        ),
        (
            "from pathlib import Path\ndef save(root, prompt):\n"
            "    (root / f'{prompt.name}.jinja').write_text(prompt.text)\n",
            "ast-path-traversal",
        ),
        (
            "import os\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n",
            "ast-command-injection",
        ),
        (
            "from django.utils.safestring import mark_safe\n"
            "def cell(value):\n    return mark_safe(f'<td class=\"{value}\">')\n",
            "ast-xss",
        ),
        ("def badge(label):\n    return f'<span class=\"badge\">{label}</span>'\n", "ast-xss"),
        (
            "def rows(cur, table):\n    cur.execute(f'SELECT * FROM {table}')\n",
            "ast-sql-injection",
        ),
        (
            "import tarfile\ndef unpack(archive, dest):\n    tarfile.open(archive).extractall(dest)\n",
            "ast-archive-extraction",
        ),
    ],
)
def test_caller_value_placed_inside_library_built_text_is_reported(tmp_path, code, rule):
    assert rule in _rules(tmp_path, code)


def test_sanitized_public_parameter_is_not_reported(tmp_path):
    code = (
        "import os\nfrom markupsafe import escape\n"
        "def load(name):\n    return open(os.path.join(ROOT, os.path.basename(name))).read()\n"
        "def badge(label):\n    return f'<span>{escape(label)}</span>'\n"
        "import tarfile\ndef unpack(archive, dest):\n"
        "    tarfile.open(archive).extractall(dest, filter='data')\n"
    )
    assert _rules(tmp_path, code) == set()


def test_request_flow_outranks_public_api_flow_at_the_same_sink(tmp_path):
    code = (
        "import os\nfrom flask import request\n"
        "def load(name):\n    extra = request.args['x']\n"
        "    return open(os.path.join(ROOT, name, extra)).read()\n"
    )
    (f,) = [x for x in _scan(tmp_path, {"pkg/core.py": code}) if "path-traversal" in x.rule_id]
    assert PUBLIC_API_TAG not in f.tags and f.confidence == Confidence.HIGH


# --- gate ------------------------------------------------------------------------
def _finding(tags: list[str]) -> Finding:
    return Finding(
        id="x",
        rule_id="ast-python.ast-code-injection",
        scanner="ast-python",
        title="t",
        description="d",
        location=Location(path="pkg/core.py", start_line=1),
        severity=Severity.HIGH,
        tags=tags,
    )


def test_public_api_findings_do_not_fail_the_gate():
    cfg = Config()
    cfg.fail_on = Severity.HIGH
    engine = ScanEngine(cfg)
    lib_only = ScanResult(
        target=".",
        started_at=datetime.now(timezone.utc),
        findings=[_finding(["taint", PUBLIC_API_TAG])],
    )
    assert lib_only.gating_severity() == Severity.INFO
    assert not engine.should_fail(lib_only)
    mixed = ScanResult(
        target=".",
        started_at=datetime.now(timezone.utc),
        findings=[_finding(["taint", PUBLIC_API_TAG]), _finding(["taint"])],
    )
    assert engine.should_fail(mixed)


def test_scan_records_the_library_mode_decision(tmp_path):
    project = _write(
        tmp_path, {"pyproject.toml": PYPROJECT, "pkg/core.py": "def f(x):\n    return x\n"}
    )
    cfg = Config(scanners=["ast-python"], cache=False)
    cfg.ai.enabled = False
    result = ScanEngine(cfg).scan(project)
    assert result.project_summary["library_mode"]["active"] is True
    assert result.project_summary["library_mode"]["setting"] == "auto"


# --- precision refinements found on real libraries ---------------------------------
def test_compile_filename_is_not_code(tmp_path):
    """compile(source, filename, mode): a caller's file name does not become code."""
    code = (
        "import os\ndef load(root, name):\n"
        "    path = os.path.join(root, name)\n"
        "    exec(compile('x = 1', path, 'exec'), {})\n"
    )
    assert "ast-code-injection" not in _rules(tmp_path, code)
    assert "ast-code-injection" in _rules(tmp_path, code.replace("'x = 1'", "'x = ' + name"))


def test_isinstance_number_guard_makes_a_value_numeric(tmp_path):
    code = (
        "def show(obj):\n"
        "    if isinstance(obj, (int, float)):\n"
        "        return f'<span class=\"n\">{obj!r}</span>'\n"
        "    return ''\n"
    )
    assert "ast-xss" not in _rules(tmp_path, code)
    assert "ast-xss" in _rules(tmp_path, code.replace("(int, float)", "(int, str)"))


def test_returned_html_is_reported_where_it_is_built_only(tmp_path):
    code = (
        "class Renderer:\n"
        "    def label(self, text):\n"
        "        return f'<b>{text}</b>'\n"
        "    def render(self, text):\n"
        "        return self.label(text)\n"
    )
    lines = [
        f.location.start_line
        for f in _scan(tmp_path, {"pkg/core.py": code})
        if "ast-xss" in f.rule_id
    ]
    assert lines == [3]
