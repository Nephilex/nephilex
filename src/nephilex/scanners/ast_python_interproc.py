"""Inter-procedural, cross-file taint for Python (depth-1, high precision).

The intra-file AST scanner (``ast-python``) follows taint through assignments
within one function. Real vulnerabilities routinely cross a function, and file,
boundary:

    # routes.py
    @app.route("/u")
    def handler():
        run_query(request.args.get("id"))   # untrusted source -> call

    # db.py
    def run_query(uid):
        cursor.execute("SELECT * FROM users WHERE id = " + uid)  # param -> sink

This scanner closes that one hop. It works in two passes over the whole project:

1. **Summarize** every function: for each parameter, seed it as tainted and reuse
   the intra-file taint engine to see whether it reaches a sink. That yields a map
   of *dangerous* ``function name -> {param position/name -> sink}``.
2. **Call sites**: for every call to a summarized dangerous function, if the
   argument in the dangerous position is a **direct untrusted source**
   (``request.args``, ``input()``, …), report the cross-function flow at the call
   site, naming the sink and the file/line where it lands.

Deliberately conservative to keep precision high (the project's guiding risk is
false positives, not misses): it is depth-1 (one call hop), and requires the
call-site argument to be a direct source rather than any variable, so a
name-collision alone never produces a finding. Because a call site's verdict
depends on another file, this scanner is **not** file-cacheable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from nephilex.core.models import (
    Confidence,
    Evidence,
    EvidenceStep,
    Finding,
    Likelihood,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._pyflow import OPERATOR_SOURCE_RE, REQUEST_SOURCE_RE, source_callables
from nephilex.scanners.ast_python import (
    _ARGV_ATTACK,
    _SOURCE_RE,
    SINKS,
    _Analyzer,
    analysis_skipped_finding,
    is_available,
    new_parser,
    node_location,
    sink_note,
    trail_steps,
)
from nephilex.scanners.patterns import _is_test_file

_SINK_BY_ID = {s.id: s for s in SINKS}


@dataclass
class _DangerousParam:
    func_name: str
    index: int
    name: str
    sink_id: str
    sink_line: int
    def_path: str
    detail: str | None = None
    #: The file the function is defined in, the sink node there and the taint
    #: trail from the parameter to the sink (for the finding's evidence).
    def_file: _FileParse | None = None
    sink_node: Any = None
    trail: tuple[Any, ...] = ()


class _SourceIndex:
    """Project-wide methods/functions that return request data, by name.

    A method only acts as a source when it is called on an object built from
    the request (``w = Wrapper(request); w.get_param()``), so a same-named
    method elsewhere does not. A plain function name must be defined exactly
    once in the project to be trusted as a source.
    """

    def __init__(self) -> None:
        self.methods: dict[str, set[str]] = {}
        self.functions: dict[str, set[str]] = {}

    def add(self, fp: _FileParse, methods: dict, functions: dict) -> None:
        for name, node in methods.items():
            self.methods.setdefault(name, set()).add(f"{fp.path}:{node.start_point[0] + 1}")
        for name, node in functions.items():
            self.functions.setdefault(name, set()).add(f"{fp.path}:{node.start_point[0] + 1}")

    @staticmethod
    def _foreign(where: set[str], path: str) -> str | None:
        """A definition site outside ``path`` (same-file ones ast-python handles)."""
        others = sorted(w for w in where if w.rsplit(":", 1)[0] != path)
        return others[0] if others and len(others) == len(where) else None

    def methods_used_in(self, path: str, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, where in self.methods.items():
            site = self._foreign(where, path)
            if site is not None and re.search(rf"\.{re.escape(name)}\s*\(", text):
                out[name] = site
        return out

    def functions_used_in(self, path: str, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, where in self.functions.items():
            if len(where) != 1:
                continue
            site = self._foreign(where, path)
            if site is not None and re.search(rf"(?<![\w.]){re.escape(name)}\s*\(", text):
                out[name] = site
        return out


class _FileParse:
    def __init__(self, path: str, src: bytes, root) -> None:
        self.path = path
        self.src = src
        self.root = root
        self._lines: list[bytes] | None = None

    @property
    def lines(self) -> list[bytes]:
        if self._lines is None:
            self._lines = self.src.splitlines()
        return self._lines

    def text(self, node) -> str:
        return self.src[node.start_byte : node.end_byte].decode("utf-8", "ignore")


@scanner
class ASTPythonInterprocScanner(Scanner):
    name = "ast-python-xfile"
    category = "sast"
    # Cross-file: a call site's verdict depends on another file, so per-file
    # caching would be unsound. Left non-file_local on purpose.
    file_local = False
    description = (
        "Cross-file/inter-procedural taint for Python (depth-1): "
        "untrusted input passed into a function whose parameter reaches "
        "a sink. Needs the [ast] extra."
    )

    def applies_to(self, project) -> bool:
        return is_available() and len(project.files_matching("*.py")) > 0

    def unavailable_reason(self, project) -> str | None:
        if is_available() or not project.files_matching("*.py"):
            return None
        return 'needs the [ast] extra: pip install "nephilex[ast]"'

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        # Own parser instance: this scanner runs on its own worker thread while
        # ast-python runs on another, and a tree-sitter Parser is not safe to
        # share across threads.
        parser = new_parser()
        if parser is None:
            return

        # Every per-file step is isolated: a file that breaks the parser or the
        # analysis is skipped and noted instead of failing the whole scanner.
        skipped: list[Finding] = []
        parses: list[_FileParse] = []
        for f in ctx.project.files():
            if f.language != "Python" or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            try:
                tree = parser.parse(src)
            except Exception as exc:
                skipped.append(analysis_skipped_finding(self.name, f.rel_path, exc))
                continue
            parses.append(_FileParse(f.rel_path, src, tree.root_node))

        # Pass 1: summarize dangerous parameters across every function, and
        # collect the methods/functions that return request data.
        dangerous: dict[str, list[_DangerousParam]] = {}
        sources = _SourceIndex()
        usable: list[_FileParse] = []
        for fp in parses:
            try:
                summaries = list(self._summarize_file(fp))
                methods, functions = source_callables(fp.src, fp.root)
            except Exception as exc:
                skipped.append(analysis_skipped_finding(self.name, fp.path, exc))
                continue
            usable.append(fp)
            for summary in summaries:
                dangerous.setdefault(summary.func_name, []).append(summary)
            sources.add(fp, methods, functions)
        yield from skipped

        # Pass 2: find call sites that pass a direct source into a dangerous param.
        seen: set[tuple[str, int, str]] = set()
        if dangerous:
            for fp in usable:
                try:
                    found = list(self._scan_calls(fp, dangerous, seen))
                except Exception as exc:
                    yield analysis_skipped_finding(self.name, fp.path, exc)
                    continue
                yield from found

        # Pass 3: request wrappers and helpers defined in another file.
        yield from self._wrapped_sources(usable, sources)

    # --- pass 3 -------------------------------------------------------------
    def _wrapped_sources(
        self, usable: list[_FileParse], sources: _SourceIndex
    ) -> Iterable[Finding]:
        """Flows whose source is a request wrapper or helper from another file.

        ``form = FormView(request); x = form.value("q")``
        is a source when ``FormView.value`` (defined elsewhere in the project)
        returns request data. Each file that calls such a method or function is
        analyzed with and without that knowledge, and only the flows the extra
        sources add are reported here; the rest belong to ``ast-python``.
        """
        if not sources.methods and not sources.functions:
            return
        for fp in usable:
            text = fp.src.decode("utf-8", "ignore")
            methods = sources.methods_used_in(fp.path, text)
            functions = sources.functions_used_in(fp.path, text)
            if not methods and not functions:
                continue
            in_test = _is_test_file(fp.path)
            try:
                plain = _Analyzer(fp.src, fp.path, in_test).run(fp.root)
                extended = _Analyzer(
                    fp.src,
                    fp.path,
                    in_test,
                    source_methods=frozenset(methods),
                    source_functions=frozenset(functions),
                ).run(fp.root)
            except Exception as exc:
                yield analysis_skipped_finding(self.name, fp.path, exc)
                continue
            known = {(f.rule_id, f.location.start_line) for f in plain}
            origins = sorted({*methods.values(), *functions.values()})
            for f in extended:
                if (f.rule_id, f.location.start_line) in known:
                    continue
                yield self._wrapped_finding(f, origins)

    def _wrapped_finding(self, f: Finding, origins: list[str]) -> Finding:
        sink_id = f.rule_id.split(".", 1)[-1]
        where = ", ".join(origins[:3])
        return f.model_copy(
            update={
                "id": f"{self.name}:{sink_id}:{f.location.path}:{f.location.start_line}",
                "rule_id": f"{self.name}.{sink_id}",
                "scanner": self.name,
                "title": f"Cross-file {f.title}",
                "description": (
                    f"{f.description} The untrusted value comes from a request wrapper "
                    f"or helper defined in another file ({where})."
                ),
                "confidence": min(f.confidence, Confidence.MEDIUM),
                "tags": [*f.tags, "cross-file"],
                "metadata": {
                    **f.metadata,
                    "analysis": "taint-dataflow-interprocedural",
                    "source_defined_at": origins[:3],
                },
            }
        )

    # --- pass 1 -------------------------------------------------------------
    def _summarize_file(self, fp: _FileParse) -> Iterable[_DangerousParam]:
        analyzer = _Analyzer(fp.src, fp.path, _is_test_file(fp.path))
        for fn in self._iter_functions(fp.root):
            name_node = fn.child_by_field_name("name")
            body = fn.child_by_field_name("body")
            params_node = fn.child_by_field_name("parameters")
            if name_node is None or body is None or params_node is None:
                continue
            func_name = fp.text(name_node)
            params = self._param_names(fp, params_node)
            for index, pname in params:
                if pname is None:
                    continue
                sinks = analyzer.seeded_sinks(body, {pname})
                if sinks:
                    sink_id, sink_line = sinks[0]
                    detail = analyzer.seed_details.get((sink_id, sink_line))
                    sink_node, trail = analyzer.seed_trails.get((sink_id, sink_line), (None, ()))
                    yield _DangerousParam(
                        func_name,
                        index,
                        pname,
                        sink_id,
                        sink_line,
                        fp.path,
                        detail,
                        def_file=fp,
                        sink_node=sink_node,
                        trail=trail,
                    )

    @staticmethod
    def _iter_nodes(root, node_type: str):
        """Pre-order walk yielding nodes of ``node_type``, without recursion."""
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == node_type:
                yield node
            stack.extend(reversed(node.children))

    def _iter_functions(self, node):
        return self._iter_nodes(node, "function_definition")

    def _param_names(self, fp: _FileParse, params_node):
        """Ordered (index, name) for positional params; stops at *args/**kwargs.

        Returns None as the name for a splat so positional indexing past it is not
        attempted (that mapping would be unreliable).
        """
        out: list[tuple[int, str | None]] = []
        idx = 0
        for child in params_node.named_children:
            t = child.type
            if t == "identifier":
                out.append((idx, fp.text(child)))
            elif t in ("typed_parameter", "typed_default_parameter", "default_parameter"):
                nm = child.child_by_field_name("name")
                # typed_parameter has no "name" field; its first identifier is it.
                if nm is None:
                    nm = next((c for c in child.children if c.type == "identifier"), None)
                out.append((idx, fp.text(nm) if nm is not None else None))
            elif t in ("list_splat_pattern", "dictionary_splat_pattern"):
                out.append((idx, None))
            else:
                continue
            idx += 1
        return out

    # --- pass 2 -------------------------------------------------------------
    def _scan_calls(self, fp: _FileParse, dangerous, seen) -> Iterable[Finding]:
        for call in self._iter_calls(fp.root):
            fn_node = call.child_by_field_name("function")
            args_node = call.child_by_field_name("arguments")
            if fn_node is None or args_node is None:
                continue
            callee = fp.text(fn_node).rsplit(".", 1)[-1]
            summaries = dangerous.get(callee)
            if not summaries:
                continue
            positional, keyword = self._call_args(fp, args_node)
            for summary in summaries:
                arg = None
                if summary.index < len(positional):
                    arg = positional[summary.index]
                elif summary.name in keyword:
                    arg = keyword[summary.name]
                if arg is None:
                    continue
                if not _SOURCE_RE.search(fp.text(arg)):
                    continue  # require a *direct* source for high precision
                line = call.start_point[0] + 1
                key = (fp.path, line, summary.sink_id)
                if key in seen:
                    continue
                seen.add(key)
                text = fp.text(arg)
                operator = bool(OPERATOR_SOURCE_RE.search(text)) and not REQUEST_SOURCE_RE.search(
                    text
                )
                yield self._finding(fp, call, line, summary, operator=operator, arg=arg)

    def _iter_calls(self, node):
        return self._iter_nodes(node, "call")

    def _call_args(self, fp: _FileParse, args_node):
        positional: list = []
        keyword: dict[str, object] = {}
        for child in args_node.named_children:
            if child.type == "keyword_argument":
                nm = child.child_by_field_name("name")
                val = child.child_by_field_name("value")
                if nm is not None and val is not None:
                    keyword[fp.text(nm)] = val
            elif child.type not in ("list_splat", "dictionary_splat"):
                positional.append(child)
        return positional, keyword

    # --- finding ------------------------------------------------------------
    def _finding(
        self,
        fp: _FileParse,
        call,
        line: int,
        summary: _DangerousParam,
        *,
        operator: bool = False,
        arg: Any = None,
    ) -> Finding:
        sink = _SINK_BY_ID.get(summary.sink_id)
        title = sink.title if sink else "Tainted input reaches a dangerous sink"
        cwe = sink.cwe if sink else []
        owasp = sink.owasp if sink else []
        severity = sink.severity if sink else Severity.HIGH
        in_test = _is_test_file(fp.path)
        confidence = Confidence.MEDIUM  # cross-file inference, one hop
        tags = ["sast", "ast", "taint", "cross-file"]
        if operator:
            # sys.argv / os.environ / input(): controlled by whoever runs the program.
            confidence = Confidence.LOW
            tags.append("operator-input")
        if in_test:
            severity = Severity(max(Severity.INFO, severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        where = (
            f"{summary.def_path}:{summary.sink_line}"
            if summary.def_path != fp.path
            else f"line {summary.sink_line}"
        )
        location = node_location(fp.path, fp.src, call)
        return Finding(
            id=f"{self.name}:{summary.sink_id}:{fp.path}:{line}",
            rule_id=f"{self.name}.{summary.sink_id}",
            scanner=self.name,
            title=f"Cross-file {title}",
            description=(
                f"Untrusted input is passed as `{summary.name}` to "
                f"`{summary.func_name}()`, whose body reaches a sink at {where}."
            ),
            location=location,
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.LIKELY,
            cwe=cwe,
            owasp=owasp,
            why_vulnerable=(
                f"A value from an untrusted source flows into `{summary.func_name}()` "
                f"via parameter `{summary.name}` and reaches a sink at {where}, one "
                "call hop away, so the intra-file scanners do not see it."
            ),
            attacker_perspective=(
                _ARGV_ATTACK
                if summary.detail == "argv"
                else sink.attack
                if sink
                else "Control the untrusted input to reach the sink."
            ),
            business_impact=(
                sink.impact if sink else "Depends on the sink; see the referenced weakness."
            ),
            remediation=Remediation(
                summary=(sink.fix if sink else "Validate input before the sink."),
                guidance=(
                    f"Validate or sanitize the value at the call site before passing "
                    f"it to `{summary.func_name}()`, or make `{summary.func_name}()` "
                    "treat its parameter as untrusted (parameterize/escape at the "
                    "sink)."
                ),
            ),
            tags=tags,
            metadata={
                "analysis": "taint-dataflow-interprocedural",
                "sink_location": where,
                "callee": summary.func_name,
            },
            evidence=self._evidence(fp, call, arg, summary, location, operator=operator),
        )

    @staticmethod
    def _evidence(
        fp: _FileParse,
        call,
        arg,
        summary: _DangerousParam,
        location,
        *,
        operator: bool,
    ) -> Evidence | None:
        """Caller source, the call site, the callee's steps and the sink in the callee."""
        if arg is None:
            return None
        arg_loc = node_location(fp.path, fp.src, arg, fp.lines)
        arg_text = re.sub(r"\s+", " ", fp.text(arg)).strip()[:80]
        if operator:
            note = f"{arg_text} comes from the command line, the environment or console input"
        else:
            note = f"{arg_text} is attacker-controlled"
        steps = [
            EvidenceStep(
                path=fp.path,
                line=arg_loc.start_line,
                column=arg_loc.start_column,
                role="source",
                code=arg_loc.snippet or "",
                note=note,
            ),
            EvidenceStep(
                path=fp.path,
                line=location.start_line,
                column=location.start_column,
                role="step",
                code=location.snippet or "",
                note=f"passed to {summary.func_name}() as {summary.name}",
            ),
        ]
        callee = summary.def_file
        if callee is not None:
            sink = _SINK_BY_ID.get(summary.sink_id)
            steps += trail_steps(
                callee.path,
                callee.lines,
                summary.trail,
                origin="operator" if operator else "request",
                owner=None,
                sink_cwes=frozenset(sink.cwe) if sink else frozenset(),
            )
            if summary.sink_node is not None:
                sink_loc = node_location(callee.path, callee.src, summary.sink_node, callee.lines)
                steps.append(
                    EvidenceStep(
                        path=callee.path,
                        line=sink_loc.start_line,
                        column=sink_loc.start_column,
                        role="sink",
                        code=sink_loc.snippet or "",
                        note=sink_note(callee.src, summary.sink_node),
                    )
                )
                return Evidence(path=steps)
        steps.append(
            EvidenceStep(
                path=summary.def_path,
                line=summary.sink_line,
                role="sink",
                note=f"reaches the sink in {summary.func_name}()",
            )
        )
        return Evidence(path=steps)
