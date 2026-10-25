"""Helpers, validators and sanitizers imported from another project file.

The Python flow engine summarizes a helper defined in another module of the
same project exactly like a same-file helper: taint passes through or is
cleared per weakness, and a validator that raises or returns a boolean clears
the checked value on the success branch.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.engine import ScanEngine
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project
from nephilex.scanners._pyproject import PythonProject
from nephilex.scanners.ast_python import is_available

pytestmark = pytest.mark.skipif(
    not is_available(), reason="tree-sitter (the [ast] extra) is not installed"
)


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")


def _scan(root: Path, scanner: str = "ast-python") -> list:
    from nephilex.analysis.repository import RepositoryAnalyzer

    project = Project.from_path(root)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner(scanner)
    return list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))


def _lines(findings, path: str, rule: str = "ast-python.ast-path-traversal") -> list[int]:
    return sorted(
        f.location.start_line for f in findings if f.location.path == path and f.rule_id == rule
    )


def _project(files: dict[str, str]) -> PythonProject:
    return PythonProject((path, textwrap.dedent(text)) for path, text in files.items())


# --- import resolution --------------------------------------------------------
_HELPERS = """
    def clean(value):
        return value


    class Paths:
        @staticmethod
        def check(value):
            return value

        @classmethod
        def build(cls, value):
            return value

        def method(self, value):
            return value


    paths = Paths()
"""


def test_resolves_absolute_relative_and_aliased_imports():
    project = _project(
        {
            "pkg/__init__.py": "",
            "pkg/helpers.py": _HELPERS,
            "pkg/views.py": """
                import pkg.helpers
                import pkg.helpers as h
                from pkg.helpers import clean
                from .helpers import clean as tidy
                from . import helpers
            """,
        }
    )
    for dotted in ("clean", "tidy", "h.clean", "helpers.clean", "pkg.helpers.clean"):
        callee = project.resolve_call("pkg/views.py", dotted)
        assert callee is not None, dotted
        assert (callee.path, callee.qualname, callee.line) == ("pkg/helpers.py", "clean", 2)
    assert project.resolve_call("pkg/views.py", "missing") is None
    assert project.resolve_call("pkg/views.py", "h.missing") is None


def test_resolves_static_class_and_instance_methods_only():
    project = _project(
        {
            "pkg/__init__.py": "",
            "pkg/helpers.py": _HELPERS,
            "pkg/views.py": "from pkg.helpers import Paths, paths\nlocal = Paths()\n",
        }
    )
    resolve = project.resolve_call
    assert resolve("pkg/views.py", "Paths.check").qualname == "Paths.check"
    assert resolve("pkg/views.py", "Paths.build").qualname == "Paths.build"
    # An instance method needs an instance; on the class it stays opaque.
    assert resolve("pkg/views.py", "Paths.method") is None
    assert resolve("pkg/views.py", "paths.method").qualname == "Paths.method"
    # A module-level instance of an imported class in the caller's own file.
    assert resolve("pkg/views.py", "local.method").qualname == "Paths.method"


def test_follows_one_init_reexport_but_not_two():
    project = _project(
        {
            "pkg/__init__.py": "from .inner import clean\n",
            "pkg/inner/__init__.py": "from .impl import clean\n",
            "pkg/inner/impl.py": "def clean(v):\n    return v\n",
            "app.py": "from pkg.inner import clean\nfrom pkg import clean as deep\n",
        }
    )
    callee = project.resolve_call("app.py", "clean")
    assert callee is not None and callee.path == "pkg/inner/impl.py"
    # pkg -> pkg.inner -> pkg.inner.impl is two re-exports deep.
    assert project.resolve_call("app.py", "deep") is None


def test_src_layout_and_ambiguous_names():
    project = _project(
        {
            "src/lib/__init__.py": "",
            "src/lib/util.py": "def clean(v):\n    return v\n",
            "tests/test_x.py": "from lib.util import clean\nfrom util import clean as other\n",
            "a/util.py": "def clean(v):\n    return v\n",
            "b/util.py": "def clean(v):\n    return v\n",
        }
    )
    assert project.resolve_call("tests/test_x.py", "clean").path == "src/lib/util.py"
    # Two top-level modules called util: neither is assumed.
    assert project.resolve_call("tests/test_x.py", "other") is None
    project2 = _project(
        {
            "a/util.py": "def clean(v):\n    return v\n",
            "a/main.py": "from util import clean\n",
            "b/util.py": "def clean(v):\n    return v\n",
        }
    )
    # The copy next to the importing file is the one its directory puts first.
    assert project2.resolve_call("a/main.py", "clean").path == "a/util.py"


def test_local_definition_shadows_an_import():
    project = _project(
        {
            "helpers.py": "def clean(v):\n    return v\n",
            "app.py": "from helpers import clean\ndef clean(v):\n    return v\n",
        }
    )
    assert project.resolve_call("app.py", "clean") is None


# --- summaries across files ---------------------------------------------------
_VIEWS = """
    import os

    from flask import request

    from app.paths import {name}


    def view():
        name = request.args.get("name")
        return open({name}("/srv/data", name)).read()
"""


def test_imported_sanitizer_clears_taint(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/paths.py": """
                import os


                def contain(base, name):
                    full = os.path.realpath(os.path.join(base, name))
                    if not full.startswith(os.path.realpath(base) + os.sep):
                        raise ValueError("outside the base directory")
                    return full
            """,
            "app/views.py": _VIEWS.format(name="contain"),
        },
    )
    assert _lines(_scan(tmp_path), "app/views.py") == []


def test_imported_pass_through_keeps_taint_with_evidence(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/paths.py": """
                import os


                def under(base, name):
                    return os.path.join(base, name)
            """,
            "app/views.py": _VIEWS.format(name="under"),
        },
    )
    findings = _scan(tmp_path)
    assert _lines(findings, "app/views.py") == [11]
    finding = next(f for f in findings if f.location.path == "app/views.py")
    steps = [s for s in finding.evidence.path if s.role == "step"]
    helper = next(s for s in steps if "under()" in s.note)
    assert helper.path == "app/views.py" and helper.line == 11
    assert "defined in app/paths.py:5" in helper.note


def test_imported_validator_clears_on_the_success_branch(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/checks.py": """
                ALLOWED = ("a.txt", "b.txt")


                def is_allowed(name):
                    if name in ALLOWED:
                        return True
                    return False


                def require_allowed(name):
                    if name not in ALLOWED:
                        raise ValueError(name)
            """,
            "app/views.py": """
                import os

                from flask import request

                from app import checks
                from app.checks import is_allowed


                def boolean():
                    name = request.args.get("name")
                    if not is_allowed(name):
                        return "no"
                    return open(os.path.join("/srv", name)).read()


                def raising():
                    name = request.args.get("name")
                    checks.require_allowed(name)
                    return open(os.path.join("/srv", name)).read()


                def failure_branch():
                    name = request.args.get("name")
                    if is_allowed(name):
                        return "ok"
                    return open(os.path.join("/srv", name)).read()
            """,
        },
    )
    assert _lines(_scan(tmp_path), "app/views.py") == [27]


def test_methods_on_obvious_receivers(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/service.py": """
                import os


                class Store:
                    @staticmethod
                    def contain(name):
                        full = os.path.realpath(os.path.join("/srv", name))
                        if not full.startswith("/srv/"):
                            raise ValueError(name)
                        return full

                    def clean(self, name):
                        return self.contain(name)


                store = Store()
            """,
            "app/views.py": """
                from flask import request

                from app.service import Store, store


                def by_class():
                    return open(Store.contain(request.args["n"])).read()


                def by_instance():
                    return open(store.clean(request.args["n"])).read()
            """,
        },
    )
    assert _lines(_scan(tmp_path), "app/views.py") == []


def test_import_cycle_terminates(tmp_path):
    _write(
        tmp_path,
        {
            "a.py": """
                from b import g


                def f(x):
                    return g(x)
            """,
            "b.py": """
                from a import f


                def g(x):
                    return f(x)
            """,
            "views.py": """
                from flask import request

                from a import f


                def view():
                    return open(f(request.args["p"])).read()
            """,
        },
    )
    # A recursion with no base case: the summary stays unknown, so the call is
    # opaque and the taint is kept.
    assert _lines(_scan(tmp_path), "views.py") == [8]


def _chain(tmp_path: Path, hops: int) -> None:
    files = {
        "h0.py": """
            import os


            def step0(name):
                full = os.path.realpath(os.path.join("/srv", name))
                if not full.startswith("/srv/"):
                    raise ValueError(name)
                return full
        """,
        "views.py": f"""
            from flask import request

            from h{hops - 1} import step{hops - 1}


            def view():
                return open(step{hops - 1}(request.args["p"])).read()
        """,
    }
    for i in range(1, hops):
        files[f"h{i}.py"] = f"""
            from h{i - 1} import step{i - 1}


            def step{i}(name):
                return step{i - 1}(name)
        """
    _write(tmp_path, files)


def test_cross_file_depth_limit(tmp_path):
    two = tmp_path / "two"
    _chain(two, 2)  # views -> h1 -> h0: within the limit, cleared
    assert _lines(_scan(two), "views.py") == []
    three = tmp_path / "three"
    _chain(three, 3)  # views -> h2 -> h1 -> h0: past the limit, kept
    assert _lines(_scan(three), "views.py") == [8]


def test_cross_file_scanner_sees_imported_sanitizer(tmp_path):
    _write(
        tmp_path,
        {
            "lib/__init__.py": "",
            "lib/clean.py": """
                import shlex


                def quoted(value):
                    return shlex.quote(value)
            """,
            "lib/run.py": """
                import os

                from lib.clean import quoted


                def run(cmd):
                    os.system("echo " + quoted(cmd))


                def run_raw(cmd):
                    os.system("echo " + cmd)
            """,
            "views.py": """
                from flask import request

                from lib.run import run, run_raw


                def view():
                    run(request.args["c"])
                    run_raw(request.args["c"])
            """,
        },
    )
    findings = _scan(tmp_path, "ast-python-xfile")
    assert [f.location.start_line for f in findings if f.location.path == "views.py"] == [9]


def test_editing_an_imported_helper_invalidates_the_cache(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/paths.py": """
                import os


                def under(base, name):
                    return os.path.join(base, name)
            """,
            "app/views.py": _VIEWS.format(name="under"),
        },
    )
    config = Config(scanners=["ast-python"])

    def lines() -> list[int]:
        result = ScanEngine(config).scan(Project.from_path(tmp_path))
        return _lines(result.findings, "app/views.py")

    assert lines() == [11]
    assert lines() == [11]  # served from the cache
    _write(
        tmp_path,
        {
            "app/paths.py": """
                import os


                def under(base, name):
                    full = os.path.realpath(os.path.join(base, name))
                    if not full.startswith(os.path.realpath(base) + os.sep):
                        raise ValueError(name)
                    return full
            """,
        },
    )
    # views.py itself did not change, but the helper it imports did.
    assert lines() == []
