"""What a regular-expression allowlist check proves about a value.

``if not re.fullmatch(r"^[a-zA-Z0-9_]+$", name): return`` is the most common
way Python code validates input. After it, ``name`` can only hold the
characters the pattern accepts, so it is safe in every context where none of
those characters is special: no ``<`` means no HTML injection, no ``/``,
``\\`` or ``.`` means no path traversal, and so on.

:func:`cleared_cwes` parses a constant pattern with the standard library's
own regex parser, computes the set of characters a match can contain, and
returns the CWEs that set cannot exploit. It only trusts a pattern that is
anchored at both ends for the call used (``fullmatch``; ``match`` with a
final ``$`` or ``\\Z``; ``search`` with ``^`` and ``$``/``\\Z``), without
``re.MULTILINE``. A ``$`` at the end of ``match``/``search`` also accepts a
trailing newline, which is added to the set. Anything the analysis does not
understand (negated classes, ``.``, huge ranges, back-references into
unanchored text) makes it return nothing, so a check is never over-trusted.
"""

from __future__ import annotations

import re
import string
import sys
from functools import lru_cache
from typing import Any

if sys.version_info >= (3, 11):
    import re._parser as _sre_parse
else:  # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse

_MAX_CHARS = 512
_WORD = frozenset(string.ascii_letters + string.digits + "_")
_DIGITS = frozenset(string.digits)
_SPACE = frozenset(" \t\n\r\f\v")


class _Unbounded(Exception):
    """The pattern can match characters the analysis cannot enumerate."""


def _name(op: Any) -> str:
    return getattr(op, "name", None) or str(op)


def _chars(items: Any, ignorecase: bool, depth: int = 0) -> set[str]:
    if depth > 40:
        raise _Unbounded
    out: set[str] = set()
    for op, av in items:
        n = _name(op)
        if n == "LITERAL":
            out.add(chr(av))
        elif n == "IN":
            out |= _class_chars(av)
        elif n == "BRANCH":
            for sub in av[1]:
                out |= _chars(sub, ignorecase, depth + 1)
        elif n == "SUBPATTERN":
            out |= _chars(av[-1], ignorecase, depth + 1)
        elif n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            out |= _chars(av[2], ignorecase, depth + 1)
        elif n == "ATOMIC_GROUP":
            out |= _chars(av, ignorecase, depth + 1)
        elif n == "GROUPREF_EXISTS":
            for sub in av[1:]:
                if sub is not None:
                    out |= _chars(sub, ignorecase, depth + 1)
        elif n in ("AT", "ASSERT", "ASSERT_NOT", "GROUPREF"):
            # Anchors and lookarounds consume nothing; a back-reference
            # repeats text an earlier group already matched.
            continue
        else:  # ANY, NOT_LITERAL, CATEGORY outside a class, ...
            raise _Unbounded
        if len(out) > _MAX_CHARS:
            raise _Unbounded
    if ignorecase:
        out |= {c.swapcase() for c in out if c.isalpha()}
    return out


def _class_chars(items: Any) -> set[str]:
    out: set[str] = set()
    for op, av in items:
        n = _name(op)
        if n == "NEGATE":
            raise _Unbounded
        if n == "LITERAL":
            out.add(chr(av))
        elif n == "RANGE":
            lo, hi = av
            if hi - lo > _MAX_CHARS:
                raise _Unbounded
            out |= {chr(c) for c in range(lo, hi + 1)}
        elif n == "CATEGORY":
            cat = _name(av)
            if cat == "CATEGORY_DIGIT":
                out |= _DIGITS
            elif cat == "CATEGORY_WORD":
                out |= _WORD
            elif cat == "CATEGORY_SPACE":
                out |= _SPACE
            else:
                raise _Unbounded
        else:
            raise _Unbounded
    return out


def _is_at(item: Any, *names: str) -> bool:
    op, av = item
    return _name(op) == "AT" and _name(av) in names


_START = ("AT_BEGINNING", "AT_BEGINNING_STRING")
_END_STRICT = ("AT_END_STRING",)
_END = ("AT_END",)


@lru_cache(maxsize=512)
def allowed_chars(pattern: str, kind: str, flags: int = 0) -> frozenset[str] | None:
    """The characters a value can hold after ``re.<kind>(pattern, value)`` succeeds.

    ``kind`` is ``fullmatch``, ``match`` or ``search``. None when the pattern
    is not anchored for that call or cannot be enumerated.
    """
    if kind not in ("fullmatch", "match", "search") or len(pattern) > 2000:
        return None
    try:
        parsed = _sre_parse.parse(pattern, flags)
    except Exception:
        return None
    all_flags = flags | getattr(parsed.state, "flags", 0)
    if all_flags & re.MULTILINE and kind != "fullmatch":
        return None
    items = [parsed[i] for i in range(len(parsed))]
    extra: set[str] = set()
    if kind != "fullmatch":
        if not items:
            return None
        if _is_at(items[-1], *_END_STRICT):
            pass
        elif _is_at(items[-1], *_END):
            extra.add("\n")  # "$" also matches before a final newline
        else:
            return None
        if kind == "search" and not _is_at(items[0], *_START):
            return None
    try:
        chars = _chars(items, bool(all_flags & re.IGNORECASE))
    except _Unbounded:
        return None
    return frozenset(chars | extra)


# For each class: the characters that must be absent (deny), or the only
# characters allowed (allow), for the value to be harmless at that sink.
_BASE = frozenset(string.ascii_letters + string.digits + "_")
_RULES: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("CWE-79", "deny", frozenset("<>\"'&`")),
    ("CWE-89", "allow", _BASE | frozenset(".@")),
    ("CWE-78", "deny", frozenset(";|&$`<>\n\r'\"\\(){}[]*?!~#\x00")),
    ("CWE-22", "deny", frozenset("/\\.:\x00")),
    ("CWE-90", "deny", frozenset("*()\\\x00&|!=<>~")),
    ("CWE-643", "deny", frozenset("'\"[]()=/|*@:")),
    ("CWE-95", "allow", _BASE | frozenset(" ")),
    ("CWE-1336", "deny", frozenset("{}%#$<>")),
    ("CWE-918", "deny", frozenset("/\\:@.?#%")),
    ("CWE-601", "deny", frozenset("/\\:")),
)


def cleared_cwes(pattern: str, kind: str, flags: int = 0) -> frozenset[str]:
    """The CWEs a successful ``re.<kind>(pattern, value)`` check clears on ``value``."""
    chars = allowed_chars(pattern, kind, flags)
    if chars is None:
        return frozenset()
    out = {"CWE-501"}  # a validated value is no longer raw input in the session
    for cwe, mode, ref in _RULES:
        if (mode == "deny" and not chars & ref) or (mode == "allow" and chars <= ref):
            out.add(cwe)
    return frozenset(out)
