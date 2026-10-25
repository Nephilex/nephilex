"""Project-wide index of Python modules, for cross-file helper summaries.

The flow engine (:mod:`nephilex.scanners._pyflow`) summarizes a helper defined
in the same file: what it returns when its arguments are tainted, and which
weaknesses it validates a parameter for. This module lets it find helpers that
are defined in another file of the same project and imported:

    from .utils import safe_join          # a function in another module
    from pkg import helper                # re-exported by pkg/__init__.py
    import pkg.paths as paths; paths.clean(x)
    from .service import Service; Service.check(x)   # static or class method
    from .service import service; service.check(x)   # module-level instance

Module names come from file paths and package roots (directories with an
``__init__.py``); a module is also reachable by the longer dotted names of the
directories above its package root, so namespace packages and ``src`` layouts
resolve. A name that maps to more than one file, and cannot be told apart by
which root contains the importing file, stays unresolved: an opaque call is
the safe default.

Every file is parsed at most once per scan, on first use, and the parses are
shared by the scanners that need them. Resolution records what it consulted,
so a file's cached findings can be keyed by the files they depend on.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

#: File boundaries a chain of helper summaries may cross from the analyzed file.
MAX_XFILE_DEPTH = 2
#: ``from pkg import f`` may follow one more import in ``pkg`` (a re-export).
REEXPORT_HOPS = 1

_SHARED_KEY = "python-project"
_LOCK = threading.Lock()


@dataclass(frozen=True)
class Callee:
    """A function in another project file that a call resolves to."""

    path: str
    #: ``f`` for a module function, ``Cls.m`` for a method.
    qualname: str
    node: Any
    #: 1-based line of the ``def``.
    line: int


@dataclass
class _Module:
    path: str
    src: bytes
    root: Any
    functions: dict[str, Any] = field(default_factory=dict)
    #: class name -> method name -> (node, "static" | "class" | "instance")
    classes: dict[str, dict[str, tuple[Any, str]]] = field(default_factory=dict)
    #: module-level ``name = Cls(...)``: name -> dotted constructor text
    instances: dict[str, str] = field(default_factory=dict)
    #: local name -> ("mod", level, dotted) | ("sym", level, dotted, name); None if
    #: the name is bound by more than one import
    imports: dict[str, tuple[Any, ...] | None] = field(default_factory=dict)
    #: names the file defines itself (they shadow an import of the same name)
    defined: set[str] = field(default_factory=set)


# A resolution result: ("mod", path) | ("func", Callee) | ("class", path, name)
# | ("inst", path, class name).
_Target = tuple[Any, ...]


class PythonProject:
    """Lazily parsed view of a project's Python files for one scan."""

    def __init__(self, files: Iterable[tuple[str, str]]) -> None:
        self._text: dict[str, str] = {}
        for path, text in files:
            self._text[path.replace("\\", "/")] = text
        self._dirs: set[str] = set()
        for path in self._text:
            d = posixpath.dirname(path)
            while d and d not in self._dirs:
                self._dirs.add(d)
                d = posixpath.dirname(d)
        #: dotted name -> [(file path or "dir/" marker, root directory)]
        self._names: dict[str, list[tuple[str, str]]] = {}
        self._index_names()
        self._parser: Any = None
        self._lock = threading.RLock()
        self._parsed: dict[str, tuple[bytes, Any] | None] = {}
        self._modules: dict[str, _Module | None] = {}
        self._resolved: dict[tuple[str, str], tuple[Callee | None, frozenset[str]]] = {}
        self._touched: dict[str, frozenset[str]] = {}
        self._digests: dict[str, str] = {}
        self._contents: dict[str, str] = {}

    # --- file and module names ---------------------------------------------
    @property
    def paths(self) -> list[str]:
        return list(self._text)

    def text(self, path: str) -> str | None:
        """The text of a project Python file, as read once for this scan."""
        return self._text.get(path)

    def _index_names(self) -> None:
        for path in self._text:
            parts = path.split("/")
            dirs, stem = parts[:-1], parts[-1][:-3] if parts[-1].endswith(".py") else ""
            if not stem:
                continue
            mod_parts = dirs if stem == "__init__" else [*dirs, stem]
            self._add_names(path, dirs, mod_parts)
        for d in self._dirs:
            if f"{d}/__init__.py" not in self._text:
                parts = d.split("/")
                self._add_names(d + "/", parts[:-1], parts)

    def _add_names(self, target: str, dirs: list[str], mod_parts: list[str]) -> None:
        # The package root: climb while the directory is a regular package.
        top = len(dirs)
        while top > 0 and "/".join(dirs[:top]) + "/__init__.py" in self._text:
            top -= 1
        for start in range(top + 1):
            name = ".".join(mod_parts[start:])
            if name and all(p.isidentifier() for p in mod_parts[start:]):
                self._names.setdefault(name, []).append((target, "/".join(dirs[:start])))

    def _absolute(self, from_path: str, dotted: str, rec: set[str]) -> str | None:
        """The file (or namespace ``dir/``) an absolute module name means here."""
        rec.add("n:" + dotted)
        found = self._names.get(dotted)
        if not found:
            return None
        if len(found) == 1:
            return found[0][0]
        here = posixpath.dirname(from_path)
        near = [
            (target, root)
            for target, root in found
            if not root or here == root or here.startswith(root + "/")
        ]
        if not near:
            return None
        deepest = max(len(root) for _, root in near)
        best = [target for target, root in near if len(root) == deepest]
        return best[0] if len(best) == 1 else None

    def _relative(self, from_path: str, level: int, dotted: str, rec: set[str]) -> str | None:
        base = posixpath.dirname(from_path)
        for _ in range(level - 1):
            if not base:
                return None
            base = posixpath.dirname(base)
        if not dotted:
            init = f"{base}/__init__.py" if base else "__init__.py"
            rec.add("x:" + init)
            if init in self._text:
                return init
            return base + "/" if base in self._dirs else None
        return self._under(base, dotted.split("."), rec)

    def _under(self, base: str, parts: list[str], rec: set[str]) -> str | None:
        stem = "/".join(parts)
        stem = f"{base}/{stem}" if base else stem
        for candidate in (stem + ".py", stem + "/__init__.py"):
            rec.add("x:" + candidate)
            if candidate in self._text:
                return candidate
        rec.add("x:" + stem + "/")
        return stem + "/" if stem in self._dirs else None

    def _find_module(self, from_path: str, level: int, dotted: str, rec: set[str]) -> str | None:
        if level:
            return self._relative(from_path, level, dotted, rec)
        return self._absolute(from_path, dotted, rec)

    def _submodule(self, target: str, name: str, rec: set[str]) -> str | None:
        if target.endswith("/"):
            base = target[:-1]
        elif target.endswith("/__init__.py") or target == "__init__.py":
            base = posixpath.dirname(target)
        else:
            return None
        return self._under(base, [name], rec)

    # --- parsing ------------------------------------------------------------
    def parsed(self, path: str) -> tuple[bytes, Any] | None:
        """``(source bytes, tree root)`` of a project file, parsed once."""
        with self._lock:
            if path in self._parsed:
                return self._parsed[path]
            text = self._text.get(path)
            result: tuple[bytes, Any] | None = None
            if text is not None:
                if self._parser is None:
                    from nephilex.scanners.ast_python import new_parser

                    self._parser = new_parser()
                if self._parser is not None:
                    src = text.encode("utf-8", "replace")
                    try:
                        result = (src, self._parser.parse(src).root_node)
                    except Exception:  # an unparseable file stays opaque
                        result = None
            self._parsed[path] = result
            return result

    def _module(self, path: str, rec: set[str] | None = None) -> _Module | None:
        if rec is not None:
            rec.add("m:" + path)
        if path.endswith("/"):
            return None
        with self._lock:
            if path in self._modules:
                return self._modules[path]
            got = self.parsed(path)
            mod = _build_module(path, *got) if got is not None else None
            self._modules[path] = mod
            return mod

    # --- resolution ---------------------------------------------------------
    def resolve_call(self, path: str, dotted: str) -> Callee | None:
        """The project function that the call target ``dotted`` in ``path`` names."""
        return self._resolve(path, dotted)[0]

    def _resolve(self, path: str, dotted: str) -> tuple[Callee | None, frozenset[str]]:
        key = (path, dotted)
        hit = self._resolved.get(key)
        if hit is not None:
            return hit
        rec: set[str] = set()
        callee = self._resolve_uncached(path, dotted, rec)
        out = (callee, frozenset(rec))
        self._resolved[key] = out
        return out

    def _resolve_uncached(self, path: str, dotted: str, rec: set[str]) -> Callee | None:
        mod = self._module(path, rec)
        if mod is None:
            return None
        parts = dotted.split(".")
        head = parts[0]
        cur: _Target | None
        if head in mod.instances:
            cur = self._instance(mod, head, rec)
        elif head in mod.defined:
            return None  # the file's own definition shadows any import
        elif head in mod.imports:
            entry = mod.imports[head]
            if entry is None:
                return None
            cur = self._import_target(path, entry, REEXPORT_HOPS, rec)
        else:
            return None
        for attr in parts[1:]:
            if cur is None:
                return None
            cur = self._attr(cur, attr, rec)
        if cur is not None and cur[0] == "func":
            callee: Callee = cur[1]
            return callee
        return None

    def _import_target(
        self, path: str, entry: tuple[Any, ...], hops: int, rec: set[str]
    ) -> _Target | None:
        target = self._find_module(path, entry[1], entry[2], rec)
        if target is None:
            return None
        if entry[0] == "mod":
            return ("mod", target)
        return self._symbol(target, entry[3], hops, rec)

    def _symbol(self, target: str, name: str, hops: int, rec: set[str]) -> _Target | None:
        mod = self._module(target, rec)
        if mod is not None:
            if name in mod.functions:
                node = mod.functions[name]
                return ("func", Callee(target, name, node, node.start_point[0] + 1))
            if name in mod.classes:
                return ("class", target, name)
            if name in mod.instances:
                return self._instance(mod, name, rec)
            if name in mod.imports:
                entry = mod.imports[name]
                if entry is None or hops <= 0:
                    return None
                return self._import_target(target, entry, hops - 1, rec)
        sub = self._submodule(target, name, rec)
        return ("mod", sub) if sub is not None else None

    def _instance(self, mod: _Module, name: str, rec: set[str]) -> _Target | None:
        """A module-level instance whose class is defined or imported in ``mod``."""
        ctor = mod.instances[name]
        parts = ctor.split(".")
        cur: _Target | None
        if len(parts) == 1 and parts[0] in mod.classes:
            cur = ("class", mod.path, parts[0])
        elif parts[0] in mod.imports and mod.imports[parts[0]] is not None:
            entry = mod.imports[parts[0]]
            assert entry is not None
            cur = self._import_target(mod.path, entry, REEXPORT_HOPS, rec)
            for attr in parts[1:]:
                if cur is None or cur[0] != "mod":
                    return None
                cur = self._symbol(cur[1], attr, REEXPORT_HOPS, rec)
        else:
            return None
        if cur is None or cur[0] != "class":
            return None
        return ("inst", cur[1], cur[2])

    def _attr(self, cur: _Target, attr: str, rec: set[str]) -> _Target | None:
        kind = cur[0]
        if kind == "mod":
            return self._symbol(cur[1], attr, REEXPORT_HOPS, rec)
        if kind in ("class", "inst"):
            mod = self._module(cur[1], rec)
            if mod is None:
                return None
            method = mod.classes.get(cur[2], {}).get(attr)
            if method is None:
                return None
            node, how = method
            # On the class itself only static and class methods are plain calls.
            if kind == "class" and how == "instance":
                return None
            qual = f"{cur[2]}.{attr}"
            return ("func", Callee(cur[1], qual, node, node.start_point[0] + 1))
        return None

    # --- dependencies (cache keys) ----------------------------------------------
    def _touched_by(self, path: str) -> frozenset[str]:
        """What resolving every call in ``path`` consulted."""
        hit = self._touched.get(path)
        if hit is not None:
            return hit
        rec: set[str] = {"m:" + path}
        mod = self._module(path)
        if mod is not None:
            for dotted in sorted(_call_targets(mod.src, mod.root)):
                rec |= self._resolve(path, dotted)[1]
        out = frozenset(rec)
        self._touched[path] = out
        return out

    def _content_digest(self, path: str) -> str:
        hit = self._contents.get(path)
        if hit is None:
            text = self._text.get(path)
            hit = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() if text else ""
            self._contents[path] = hit
        return hit

    def dependency_digest(self, path: str) -> str:
        """A digest of everything outside ``path`` that its summaries may read.

        Covers the files its calls resolve into and, one level further, the
        files their calls resolve into (:data:`MAX_XFILE_DEPTH`), together with
        the existence of the paths and names that resolution probed, so adding
        a module that changes a lookup changes the digest.
        """
        hit = self._digests.get(path)
        if hit is not None:
            return hit
        first = self._touched_by(path)
        entries = set(first)
        for item in first:
            if item.startswith("m:") and item[2:] != path:
                entries |= self._touched_by(item[2:])
        h = hashlib.sha256()
        for item in sorted(entries):
            kind, value = item[:2], item[2:]
            if kind == "m:":
                if value == path:
                    continue
                h.update(f"{item}={self._content_digest(value)}\n".encode())
            elif kind == "x:":
                there = value in self._text or value.rstrip("/") in self._dirs
                h.update(f"{item}={there}\n".encode())
            else:
                found = sorted(self._names.get(value, []))
                h.update(f"{item}={found}\n".encode())
        out = h.hexdigest()[:24]
        self._digests[path] = out
        return out


def _text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "ignore")


_DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")


def _dotted(src: bytes, node) -> str | None:
    if node is None or node.type not in ("identifier", "attribute"):
        return None
    text = re.sub(r"\s+", "", _text(src, node))
    return text if _DOTTED.match(text) else None


#: Nodes that can hold statements: imports and definitions are looked for
#: only below these, never inside expressions.
_STATEMENT_HOLDERS = frozenset(
    {
        "module",
        "block",
        "if_statement",
        "elif_clause",
        "else_clause",
        "for_statement",
        "while_statement",
        "try_statement",
        "except_clause",
        "except_group_clause",
        "finally_clause",
        "with_statement",
        "match_statement",
        "case_clause",
        "function_definition",
        "class_definition",
        "decorated_definition",
    }
)


def _call_targets(src: bytes, root) -> set[str]:
    """Dotted names of every call target in the file (for dependency digests)."""
    out: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "call":
            dotted = _dotted(src, node.child_by_field_name("function"))
            if dotted is not None and dotted.split(".", 1)[0] not in ("self", "cls"):
                out.add(dotted)
        stack.extend(node.children)
    return out


def _build_module(path: str, src: bytes, root) -> _Module:
    mod = _Module(path, src, root)
    assigned: dict[str, int] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type
        if t == "import_statement":
            _add_import(mod, src, node)
            continue
        if t == "import_from_statement":
            _add_from_import(mod, src, node)
            continue
        if t in ("function_definition", "class_definition") and not _is_method(node):
            name = node.child_by_field_name("name")
            if name is not None:
                mod.defined.add(_text(src, name))
        if t in _STATEMENT_HOLDERS:
            stack.extend(node.children)
    for stmt in root.named_children:
        inner = stmt
        if inner.type == "decorated_definition":
            inner = inner.child_by_field_name("definition") or inner
        if inner.type == "function_definition":
            name = inner.child_by_field_name("name")
            if name is not None:
                mod.functions[_text(src, name)] = inner
        elif inner.type == "class_definition":
            _add_class(mod, src, inner)
        elif inner.type == "expression_statement":
            for ch in inner.named_children:
                if ch.type not in ("assignment", "augmented_assignment"):
                    continue
                left = ch.child_by_field_name("left")
                if left is None or left.type != "identifier":
                    continue
                name = _text(src, left)
                assigned[name] = assigned.get(name, 0) + 1
                right = ch.child_by_field_name("right")
                if ch.type == "assignment" and right is not None and right.type == "call":
                    ctor = _dotted(src, right.child_by_field_name("function"))
                    if ctor is not None:
                        mod.instances[name] = ctor
    mod.defined |= set(assigned)
    for name, count in assigned.items():
        if count != 1 or name in mod.functions or name in mod.classes:
            mod.instances.pop(name, None)
    # A module-level name that is both imported and bound otherwise is ambiguous.
    for name in mod.defined:
        if name in mod.imports:
            mod.imports[name] = None
    return mod


def _is_method(node) -> bool:
    parent = node.parent
    if parent is not None and parent.type == "decorated_definition":
        parent = parent.parent
    return (
        parent is not None
        and parent.type == "block"
        and parent.parent is not None
        and parent.parent.type == "class_definition"
    )


def _bind(mod: _Module, name: str, entry: tuple[Any, ...]) -> None:
    if name in mod.imports and mod.imports[name] != entry:
        mod.imports[name] = None
    else:
        mod.imports[name] = entry


def _add_import(mod: _Module, src: bytes, node) -> None:
    for child in node.children_by_field_name("name"):
        if child.type == "aliased_import":
            target = child.child_by_field_name("name")
            alias = child.child_by_field_name("alias")
            if target is not None and alias is not None:
                _bind(mod, _text(src, alias), ("mod", 0, _text(src, target)))
        elif child.type == "dotted_name":
            dotted = _text(src, child)
            head = dotted.split(".", 1)[0]
            _bind(mod, head, ("mod", 0, head))


def _add_from_import(mod: _Module, src: bytes, node) -> None:
    module = node.child_by_field_name("module_name")
    if module is None:
        return
    level = 0
    dotted = ""
    if module.type == "relative_import":
        for ch in module.children:
            if ch.type == "import_prefix":
                level = len(_text(src, ch).strip())
            elif ch.type == "dotted_name":
                dotted = _text(src, ch)
    else:
        dotted = _text(src, module)
    for child in node.children_by_field_name("name"):
        if child.type == "aliased_import":
            target = child.child_by_field_name("name")
            alias = child.child_by_field_name("alias")
            if target is not None and alias is not None:
                _bind(mod, _text(src, alias), ("sym", level, dotted, _text(src, target)))
        elif child.type == "dotted_name":
            name = _text(src, child)
            _bind(mod, name, ("sym", level, dotted, name))


def _add_class(mod: _Module, src: bytes, node) -> None:
    name = node.child_by_field_name("name")
    body = node.child_by_field_name("body")
    if name is None or body is None:
        return
    methods: dict[str, tuple[Any, str]] = {}
    for stmt in body.named_children:
        how = "instance"
        fn = stmt
        if stmt.type == "decorated_definition":
            fn = stmt.child_by_field_name("definition") or stmt
            decorators = [
                re.sub(r"\s+", "", _text(src, d))
                for d in stmt.named_children
                if d.type == "decorator"
            ]
            if "@staticmethod" in decorators:
                how = "static"
            elif "@classmethod" in decorators:
                how = "class"
            elif decorators:
                continue  # a property or a wrapper: not a plain call
        if fn.type != "function_definition":
            continue
        fname = fn.child_by_field_name("name")
        if fname is not None:
            methods[_text(src, fname)] = (fn, how)
    mod.classes[_text(src, name)] = methods


def python_project(ctx: Any) -> PythonProject:
    """The scan's shared :class:`PythonProject`, built on first use.

    Built from the whole project (``ctx.scope`` when the scanner sees only the
    files that missed the cache), so helpers in unchanged files still resolve.
    """
    shared = getattr(ctx, "shared", None)
    with _LOCK:
        project = shared.get(_SHARED_KEY) if shared is not None else None
        if project is None:
            whole = getattr(ctx, "scope", None) or ctx.project
            project = PythonProject(
                (f.rel_path, f.text())
                for f in whole.files()
                if f.language == "Python" and not f.is_probably_binary()
            )
            if shared is not None:
                shared[_SHARED_KEY] = project
    return project
