"""Command injection without a shell, and operator-controlled sources.

An argv list run without a shell has no metacharacters to inject: a tainted
value matters only as the program (argv[0]) or as code after an interpreter's
``-c``. ``sys.argv``, ``os.environ`` and ``input()`` are controlled by whoever
runs the program and are reported at low confidence.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from nephilex.analysis.repository import RepositoryAnalyzer  # noqa: E402
from nephilex.core.config import Config  # noqa: E402
from nephilex.core.models import Confidence  # noqa: E402
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.core.project import Project  # noqa: E402

FLASK = "import os, subprocess, sys\nfrom flask import Flask, request\napp = Flask(__name__)\n"


def _findings(tmp_path, files: dict[str, str], scanner: str = "ast-python") -> list:
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return [
        f
        for f in registry.get_scanner(scanner)().scan(ctx)
        if f.rule_id.endswith("ast-command-injection")
    ]


def _view(body: str) -> str:
    lines = "".join(f"    {line}\n" for line in body.strip("\n").splitlines())
    return FLASK + "@app.route('/x')\ndef view():\n    v = request.args['v']\n" + lines


@pytest.mark.parametrize(
    "call,reported",
    [
        ("subprocess.run(['git', 'log', v])", False),
        ("subprocess.run([sys.executable, '-m', 'pip', 'wheel', v], check=True)", False),
        ("subprocess.run(['convert', *args, v])", False),
        ("subprocess.run([v, '--version'])", True),
        ("subprocess.run(['python', '-c', v])", True),
        ("subprocess.run(['bash', '-c', 'echo ' + v])", True),
        ("subprocess.run('ls ' + v, shell=True)", True),
        ("os.system('ping ' + v)", True),
        ("subprocess.run(v)", True),
        ("os.execv(v, [v])", True),
        ("os.execv('/usr/bin/git', ['git', v])", False),
    ],
)
def test_argv_lists_report_only_the_program_or_interpreter_code(tmp_path, call, reported):
    code = _view(f"args = ['-strip']\n{call}")
    assert bool(_findings(tmp_path, {"app.py": code})) is reported


def test_no_shell_finding_describes_choosing_the_program(tmp_path):
    (f,) = _findings(tmp_path, {"app.py": _view("subprocess.run([v, '--version'])")})
    assert "argv[0]" in f.why_vulnerable and "No shell" in f.why_vulnerable
    assert "rm -rf" not in f.attacker_perspective
    (shell,) = _findings(tmp_path, {"app.py": _view("os.system('ping ' + v)")})
    assert "rm -rf" in shell.attacker_perspective


def test_tracked_argv_variable(tmp_path):
    code = _view("cmd = ['git', 'clone']\ncmd.append(v)\nsubprocess.run(cmd)")
    assert not _findings(tmp_path, {"app.py": code})


def test_cross_file_argv_list_from_the_command_line_is_not_reported(tmp_path):
    files = {
        "build.py": (
            "import subprocess, sys\n"
            "def build(source, destination):\n"
            "    subprocess.run([sys.executable, '-m', 'pip', 'wheel', str(source),\n"
            "                    '-w', str(destination)], check=True)\n"
        ),
        "main.py": (
            "import sys\nfrom pathlib import Path\nfrom build import build\n"
            "build(Path(sys.argv[1]), Path(sys.argv[2]))\n"
        ),
    }
    assert not _findings(tmp_path, files, scanner="ast-python-xfile")


@pytest.mark.parametrize("source", ["sys.argv[1]", "os.environ['CMD']", "input()"])
def test_operator_input_is_low_confidence(tmp_path, source):
    code = f"import os, sys\ndef main():\n    os.system('run ' + {source})\n"
    (f,) = _findings(tmp_path, {"cli.py": code})
    assert f.confidence == Confidence.LOW
    assert "operator-input" in f.tags and f.metadata["source"] == "operator"


def test_request_input_outranks_operator_input(tmp_path):
    code = _view("os.system('run ' + v + sys.argv[1])")
    (f,) = _findings(tmp_path, {"app.py": code})
    assert f.confidence == Confidence.HIGH and "operator-input" not in f.tags
