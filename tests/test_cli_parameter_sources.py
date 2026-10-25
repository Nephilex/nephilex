"""Parameters of command-line commands are not request input.

Typer and Click fill a command's parameters from the command line, so the
person running the command chooses them, on a machine they already control.
Passing a path or a command to a command-line tool is its purpose, so these
parameters are not taint sources and are not reported. FastAPI parameters stay
request sources, and a ``pathlib.Path`` default is not FastAPI's ``Path()``
marker.
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

TYPER = "import typer\nfrom typing import Annotated\nfrom pathlib import Path\n"
TYPER += "app = typer.Typer()\n"


def _findings(tmp_path, code: str, rule: str = "ast-path-traversal") -> list:
    (tmp_path / "mod.py").write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return [f for f in registry.get_scanner("ast-python")().scan(ctx) if f.rule_id.endswith(rule)]


def _not_reported(findings: list) -> bool:
    return not findings


@pytest.mark.parametrize(
    "code",
    [
        # Typer, Annotated Argument with a pathlib default (the gradio shape)
        TYPER + "def build(path: Annotated[Path, typer.Argument(help='dir')] = Path('.')):\n"
        "    open(path / 'pyproject.toml').read()\n",
        # Typer, Annotated Argument and Option on a decorated command
        TYPER + "@app.command()\n"
        "def build(name: Annotated[str, typer.Argument()], out: Annotated[str, typer.Option()]):\n"
        "    open(name).read()\n    open(out, 'w')\n",
        # Typer, Option as the default value
        TYPER + "@app.command()\ndef build(name: str = typer.Option('x')):\n"
        "    open(name).read()\n",
        # Typer, plain parameters of a decorated command
        TYPER + "@app.command()\ndef build(name: str):\n    open(name).read()\n",
        # Typer, a function registered without a decorator
        TYPER + "def _build(name: str):\n    open(name).read()\n"
        "app.command('build', help='Build it.')(_build)\n",
        # Typer, typer.run(main)
        "import typer\ndef main(name: str):\n    open(name).read()\n"
        "if __name__ == '__main__':\n    typer.run(main)\n",
        # Click argument and option
        "import click\n@click.command()\n@click.argument('name')\n@click.option('--out')\n"
        "def build(name, out):\n    open(name).read()\n",
        "import click\n@click.group()\ndef cli():\n    pass\n"
        "@cli.command()\n@click.option('--name')\ndef build(name):\n    open(name).read()\n",
    ],
    ids=[
        "typer-annotated-pathlib-default",
        "typer-annotated",
        "typer-option-default",
        "typer-plain",
        "typer-registered",
        "typer-run",
        "click-command",
        "click-group-command",
    ],
)
def test_cli_parameters_are_not_reported(tmp_path, code):
    assert _not_reported(_findings(tmp_path, code))


@pytest.mark.parametrize(
    "code",
    [
        TYPER + "import requests\n@app.command()\n"
        "def fetch(url: Annotated[str, typer.Option()]):\n    requests.get(url)\n",
        "import click, requests\n@click.command()\n@click.option('--url')\n"
        "def fetch(url):\n    requests.get(url)\n",
    ],
    ids=["typer", "click"],
)
def test_cli_option_as_url_is_configuration(tmp_path, code):
    assert not _findings(tmp_path, code, "ast-ssrf")


def test_numeric_and_context_cli_parameters_are_not_sources(tmp_path):
    code = (
        "import click\n@click.command()\n@click.pass_context\n@click.option('--n', type=int)\n"
        "def build(ctx: click.Context, n: int):\n    open(ctx.obj).read()\n"
        "    open(str(n)).read()\n"
    )
    assert not _findings(tmp_path, code)
    typer_bool = TYPER + "@app.command()\n"
    typer_bool += "def build(flag: Annotated[bool, typer.Option()] = False):\n"
    typer_bool += "    open(str(flag)).read()\n"
    assert not _findings(tmp_path, typer_bool)


def test_pathlib_default_is_not_a_fastapi_path_marker(tmp_path):
    plain = "from pathlib import Path\ndef build(path: Path = Path('.')):\n"
    plain += "    open(path / 'x').read()\n"
    assert not _findings(tmp_path, plain)
    in_fastapi_app = "from pathlib import Path\nfrom fastapi import FastAPI\napp = FastAPI()\n"
    in_fastapi_app += "def build(path: Path = Path('.')):\n    open(path / 'x').read()\n"
    assert not _findings(tmp_path, in_fastapi_app)


@pytest.mark.parametrize(
    "code",
    [
        "from typing import Annotated\nfrom fastapi import FastAPI, Query\napp = FastAPI()\n"
        "@app.get('/x')\ndef read(q: Annotated[str, Query()]):\n    return open(q).read()\n",
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/x/{name}')\ndef read(name: str):\n    return open(name).read()\n",
        # a dependency with a FastAPI marker default, also through an alias
        "from fastapi import FastAPI, Path\napp = FastAPI()\n"
        "def dep(name: str = Path(...)):\n    open(name).read()\n",
        "from fastapi import FastAPI, Query as Q\napp = FastAPI()\n"
        "def dep(name: str = Q(None)):\n    open(name).read()\n",
        "import fastapi\ndef dep(name: str = fastapi.Query(None)):\n    open(name).read()\n",
        # a FastAPI route in a file that also has a Typer command
        "import typer\nfrom typing import Annotated\nfrom fastapi import FastAPI, Query\n"
        "app = FastAPI()\ncli = typer.Typer()\n"
        "@app.get('/x')\ndef read(q: Annotated[str, Query()]):\n    return open(q).read()\n"
        "@cli.command()\ndef serve(port: int = typer.Option(8000)):\n    pass\n",
    ],
    ids=["annotated-query", "path-operation", "path-marker", "alias", "dotted", "with-typer"],
)
def test_fastapi_parameters_stay_request_sources(tmp_path, code):
    (f,) = _findings(tmp_path, code)
    assert f.confidence != Confidence.LOW and "operator-input" not in f.tags
    assert f.metadata.get("source", "request") == "request"


def test_annotated_type_alone_is_not_request_input(tmp_path):
    code = "from typing import Annotated\nfrom fastapi import FastAPI\napp = FastAPI()\n"
    code += "def helper(name: Annotated[str, 'doc']):\n    open(name).read()\n"
    assert not _findings(tmp_path, code)
