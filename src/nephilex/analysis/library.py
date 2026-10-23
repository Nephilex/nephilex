"""Library mode: is the scanned Python project a library or an application?

In an application the attacker's input arrives through a request, a command
line or the environment, and the taint engine starts from those sources. In a
library it arrives as an argument of a public function: the library cannot
know who calls it. Many advisories are in libraries, so Nephilex can treat the
parameters of public functions as sources ("library mode") and report flows
from them separately, at low confidence (see ``docs/scanners.md``).

The ``library_mode`` setting chooses: ``on``, ``off``, or ``auto`` (the
default), which turns it on for a project that has a package manifest
(``pyproject.toml``, ``setup.py`` or ``setup.cfg`` at its root) and no web
application entry point that Nephilex recognizes.
"""

from __future__ import annotations

import ast
import contextlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nephilex.core.project import Project

LIBRARY_MODES = ("auto", "on", "off")
MANIFESTS = ("pyproject.toml", "setup.py", "setup.cfg")

#: Calls that create (or serve) a web application: the project is an app.
_APP_CALLS = frozenset(
    {
        "Flask",
        "Quart",
        "FastAPI",
        "Starlette",
        "Sanic",
        "Bottle",
        "Litestar",
        "FastMCP",
        "get_wsgi_application",
        "get_asgi_application",
        "execute_from_command_line",
    }
)
_APP_DOTTED = frozenset(
    {
        "web.Application",
        "aiohttp.web.Application",
        "tornado.web.Application",
        "falcon.App",
        "falcon.API",
        "falcon.asgi.App",
        "uvicorn.run",
        "waitress.serve",
    }
)
#: Directories whose code is not the project's own (tests, docs, examples).
_NOT_SHIPPED = re.compile(r"(?i)(^|/)(tests?|testing|docs?|examples?|samples?|demos?|benchmarks?)/")
#: Path components that mark a module as outside the public API.
_NOT_API_DIRS = frozenset(
    {"tests", "test", "testing", "docs", "doc", "examples", "example"}
    | {"samples", "sample", "demos", "demo", "benchmarks", "benchmark"}
)
_NOT_API_FILES = frozenset({"setup.py", "conftest.py", "noxfile.py", "__main__.py", "manage.py"})
# Bounds on the entry-point search, for very large or hostile trees.
_MAX_FILES = 3000
_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class LibraryMode:
    """The resolved library-mode decision for one scan."""

    setting: str
    active: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"setting": self.setting, "active": self.active, "reason": self.reason}


def module_is_public(rel_path: str) -> bool:
    """Whether a module is part of a package's public API.

    Not when any directory or the module itself starts with an underscore
    (``_internal/``, ``_compat.py``; ``__init__.py`` is public), when it is a
    test, documentation or example file, or a setup or entry script
    (``setup.py``, ``__main__.py``, ``manage.py``).
    """
    parts = rel_path.replace("\\", "/").split("/")
    name = parts[-1]
    if name in _NOT_API_FILES or name.startswith("test_") or name.endswith("_test.py"):
        return False
    for part in parts[:-1]:
        if part.startswith("_") or part.lower() in _NOT_API_DIRS:
            return False
    stem = name[:-3] if name.endswith(".py") else name
    return not stem.startswith("_") or stem == "__init__"


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def find_app_entry_point(project: Project) -> str | None:
    """``path:line (call)`` of the first web application entry point, or None.

    Uses Python's own parser (no code is run), so a framework name in a
    docstring or comment does not count. Test, documentation and example
    directories are skipped: an example app does not make the package an app.
    """
    seen = 0
    for f in project.files():
        if f.language != "Python" or _NOT_SHIPPED.search(f.rel_path):
            continue
        seen += 1
        if seen > _MAX_FILES:
            break
        text = f.text()
        if len(text) > _MAX_BYTES:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if not name:
                continue
            if name.rsplit(".", 1)[-1] in _APP_CALLS or name in _APP_DOTTED:
                return f"{f.rel_path}:{getattr(node, 'lineno', 0)} ({name})"
    return None


def resolve_library_mode(project: Project, setting: str = "auto") -> LibraryMode:
    """Decide library mode for ``project`` under ``setting`` (auto, on or off)."""
    if setting == "on":
        return LibraryMode(setting, True, "library_mode: on")
    if setting == "off":
        return LibraryMode(setting, False, "library_mode: off")
    manifest = next((m for m in MANIFESTS if (project.root / m).is_file()), None)
    if manifest is None:
        return LibraryMode(
            setting, False, "no package manifest (pyproject.toml, setup.py, setup.cfg)"
        )
    entry = find_app_entry_point(project)
    if entry is not None:
        return LibraryMode(setting, False, f"web application entry point: {entry}")
    return LibraryMode(setting, True, f"{manifest} and no web application entry point")


def library_mode_for(project: Project, setting: str = "auto") -> LibraryMode:
    """The decision for ``project``, computed once per project object."""
    cached = getattr(project, "_library_mode", None)
    if isinstance(cached, LibraryMode) and cached.setting == setting:
        return cached
    mode = resolve_library_mode(project, setting)
    with contextlib.suppress(AttributeError):  # a project type without a __dict__
        project._library_mode = mode  # type: ignore[attr-defined]
    return mode
