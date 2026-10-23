"""AI-assistant instruction files and MCP tool descriptions (OWASP LLM01, LLM03).

Coding assistants load project instruction files into the model's context on
every session, and MCP clients put every tool's description in front of the
model before it picks a tool. Both are text a pull request, a dependency or a
server update can change, and the model treats them as instructions. The
``agent-config`` scanner calls this module for:

* ``instruction-hidden-unicode`` (LLM01): invisible or deceptive characters in
  an instruction file: Unicode tag characters (decoded so the reviewer sees the
  hidden text), bidirectional overrides and isolates, zero-width characters and
  other format characters, outside the uses real text needs (emoji ZWJ
  sequences, subdivision flags, ZWNJ in Persian and Indic scripts, direction
  marks next to right-to-left text, a leading byte order mark).
* ``instruction-directive`` (LLM01): text that turns the assistant against the
  user: ignore earlier instructions or the user, hide what it does, disable a
  security check, download and execute, read a secret and send it out, or push
  without review. Severity grows with the evidence: a hidden block (an HTML
  comment, text revealed from hidden characters, an ``<IMPORTANT>`` tag) and
  more than one kind of directive in the same passage each raise it a level.
* ``instruction-untrusted-dependency`` (LLM03): an instruction to install from
  an extra package index, a git URL or a tarball instead of the registry.
* ``instruction-encoded-blob`` (LLM01): a base64 or hex blob that decodes to
  text, reported at low confidence and graded by what the text says.
* ``mcp-tool-poisoning`` (LLM01): an MCP server's tool, parameter or server
  description (Python ``mcp`` / ``fastmcp``, TypeScript and JavaScript
  ``@modelcontextprotocol/sdk``) that carries hidden characters or instructions
  aimed at the model (read ``~/.ssh/id_rsa`` and pass it as an argument, do not
  tell the user, change how another tool behaves).

Phrase matching is deliberately narrow and negation-aware: "never pass
--no-verify" and "do not push to main" are guidance, not directives. Every
quoted excerpt is escaped (code points as ``U+XXXX``) and passed through the
secrets scanner's redaction, so a report never carries a raw control character
or a credential.

File names, verified against each tool's documentation (2026-10):

* ``AGENTS.md`` at the root and in subdirectories (https://agents.md/; Cursor,
  Windsurf, Copilot, Cline and Roo Code read it too); Roo Code falls back to
  ``AGENT.md`` at the root.
* ``CLAUDE.md`` and ``CLAUDE.local.md`` in any directory, ``.claude/CLAUDE.md``
  and ``.claude/rules/**/*.md``: https://code.claude.com/docs/en/memory
* ``GEMINI.md`` in the workspace and its subdirectories:
  https://geminicli.com/docs/cli/gemini-md/
* ``.cursor/rules/**/*.mdc`` (plain ``.md`` there is ignored) and the legacy
  ``.cursorrules``: https://cursor.com/docs/context/rules
* ``.windsurf/rules/*.md``, ``.devin/rules/*.md`` and the legacy
  ``.windsurfrules``: https://docs.devin.ai/desktop/cascade/memories
* ``.clinerules`` (a file or a directory) and ``.cline/rules/``:
  https://docs.cline.bot/features/cline-rules
* ``.github/copilot-instructions.md`` and
  ``.github/instructions/**/*.instructions.md``:
  https://code.visualstudio.com/docs/copilot/customization/custom-instructions
* ``.roo/rules/``, ``.roo/rules-{mode}/``, ``.roorules`` and
  ``.roorules-{mode}``: https://roocodeinc.github.io/Roo-Code/features/custom-instructions
"""

from __future__ import annotations

import ast
import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from nephilex.core.models import Confidence, Finding, Severity
from nephilex.scanners._text import CURL_PIPE_SHELL_RE
from nephilex.scanners.llm_ast import LLM01, LLM03, make_finding

SCANNER_NAME = "agent-config"
MAX_INSTRUCTION_BYTES = 512_000
MAX_SOURCE_BYTES = 1_000_000
#: Most findings of one rule in one file; a file past it is clearly hostile
#: or generated, and the first findings are enough to act on.
_MAX_PER_RULE = 25

# --- instruction file locations ---------------------------------------------

_NAMED_FILES = {
    "AGENTS.md": "coding assistants that read AGENTS.md (Codex, Cursor, Copilot and others)",
    "CLAUDE.md": "Claude Code",
    "CLAUDE.local.md": "Claude Code",
    "GEMINI.md": "Gemini CLI",
    ".cursorrules": "Cursor (legacy .cursorrules)",
    ".windsurfrules": "Windsurf (legacy .windsurfrules)",
    ".clinerules": "Cline",
    ".roorules": "Roo Code",
}
_RULE_DIR_SUFFIXES = ("", ".md", ".mdc", ".txt", ".markdown")


def instruction_tool(rel_path: str) -> str | None:
    """The assistant that loads ``rel_path`` as instructions, or None."""
    parts = rel_path.split("/")
    name, dirs = parts[-1], parts[:-1]
    if name in _NAMED_FILES:
        return _NAMED_FILES[name]
    if name == "AGENT.md" and not dirs:
        return "Roo Code"
    if name.startswith(".roorules-"):
        return "Roo Code"
    lower = name.lower()
    suffix = lower[lower.rfind(".") :] if "." in lower.lstrip(".") else ""
    for i, d in enumerate(dirs):
        nxt = dirs[i + 1] if i + 1 < len(dirs) else None
        if d == ".cursor" and nxt == "rules" and lower.endswith(".mdc"):
            return "Cursor"
        if d == ".claude":
            if nxt == "rules" and lower.endswith(".md"):
                return "Claude Code"
            if nxt is None and name == "CLAUDE.md":
                return "Claude Code"
        if d in (".windsurf", ".devin") and nxt == "rules" and lower.endswith(".md"):
            return "Windsurf"
        if (d == ".clinerules" or (d == ".cline" and nxt == "rules")) and (
            suffix in _RULE_DIR_SUFFIXES
        ):
            return "Cline"
        if d == ".github":
            if nxt is None and name == "copilot-instructions.md":
                return "GitHub Copilot"
            if nxt == "instructions" and lower.endswith(".instructions.md"):
                return "GitHub Copilot"
        if (
            d == ".roo"
            and nxt is not None
            and (nxt == "rules" or nxt.startswith("rules-"))
            and suffix in _RULE_DIR_SUFFIXES
        ):
            return "Roo Code"
    return None


# --- Unicode ------------------------------------------------------------------

_TAG_FIRST, _TAG_LAST = 0xE0000, 0xE007F
_TAG_CANCEL = 0xE007F
_BLACK_FLAG = 0x1F3F4
_BIDI_OPEN = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
}
_BIDI_CLOSE = {0x202C: "embedding", 0x2069: "isolate"}
_OVERRIDES = {0x202D, 0x202E}
_ISOLATES = {0x2066, 0x2067, 0x2068}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
_DIRECTION_MARKS = {0x200E, 0x200F, 0x061C}
_ARABIC_FORMAT = {0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x06DD, 0x070F, 0x0890}
_ARABIC_FORMAT |= {0x0891, 0x08E2}


def _is_vs(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _is_emoji(cp: int) -> bool:
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x2300 <= cp <= 0x23FF
        or 0x2B00 <= cp <= 0x2BFF
        or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D)
    )


def _emoji_part(cp: int) -> bool:
    """An emoji, or a modifier that may sit between an emoji and a ZWJ."""
    return _is_emoji(cp) or _is_vs(cp) or 0x1F3FB <= cp <= 0x1F3FF or cp == 0x20E3


def _rtl(ch: str) -> bool:
    return unicodedata.bidirectional(ch) in ("R", "AL")


def _joining_letter(ch: str) -> bool:
    """A letter or mark of a script that uses ZWJ/ZWNJ (Arabic, Hebrew, Indic, ...)."""
    return ord(ch) >= 0x0590 and unicodedata.category(ch)[0] in "LM"


def _zwsp_script(ch: str) -> bool:
    """Scripts written without spaces, where U+200B marks word breaks."""
    cp = ord(ch)
    return (
        0x0E00 <= cp <= 0x0FFF  # Thai, Lao, Tibetan
        or 0x1000 <= cp <= 0x109F  # Myanmar
        or 0x1780 <= cp <= 0x17FF  # Khmer
        or 0x2E80 <= cp <= 0x9FFF  # CJK
        or 0xF900 <= cp <= 0xFAFF
        or 0xAC00 <= cp <= 0xD7AF
    )


def _invisible(ch: str) -> bool:
    """Characters that must never be written raw into a report."""
    cp = ord(ch)
    if ch in ("\n", "\t"):
        return False
    cat = unicodedata.category(ch)
    if cat in ("Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"):
        return True
    if cat == "Zs" and ch != " ":
        return True
    return _is_vs(cp) or _TAG_FIRST <= cp <= _TAG_LAST


def escape_invisible(text: str) -> str:
    """``text`` with every invisible or control character shown as ``<U+XXXX>``."""
    return "".join(f"<U+{ord(ch):04X}>" if _invisible(ch) else ch for ch in text)


def _cp_name(cp: int) -> str:
    if _TAG_FIRST <= cp <= _TAG_LAST:
        return "TAG " + (chr(cp - _TAG_FIRST) if 0xE0020 <= cp <= 0xE007E else "CONTROL")
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "UNNAMED"


@dataclass
class Hidden:
    """A run of suspicious characters at ``start``..``end`` (offsets in the text)."""

    kind: str  # "tag", "variation-selector", "bidi", "zero-width", "format"
    start: int
    end: int
    code_points: list[int]
    #: Text the run carries (tag characters, selectors or a zero-width code).
    decoded: str = ""
    #: True when the run sits inside a word, splitting it.
    in_word: bool = False
    note: str = ""


def _neighbors(text: str, i: int, j: int) -> tuple[str, str]:
    return (text[i - 1] if i > 0 else ""), (text[j] if j < len(text) else "")


def _decode_zero_width(cps: Sequence[int]) -> str:
    """Text hidden as bits in a run of two distinct zero-width characters, or ""."""
    kinds = sorted(set(cps))
    if len(kinds) != 2 or len(cps) < 16:
        return ""
    best = ""
    for one in kinds:
        bits = "".join("1" if cp == one else "0" for cp in cps)
        raw = bytes(int(bits[k : k + 8], 2) for k in range(0, len(bits) - 7, 8))
        text = raw.decode("utf-8", "replace")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
        if text and printable / len(text) >= 0.9 and len(text) > len(best):
            best = text
    return best


_MAX_SPAN = 512


def _pair_bidi(text: str, start: int, line_end: int) -> dict[int, int]:
    """Match the bidi openers of one line (from ``start``) to their closers. Linear."""
    pairs: dict[int, int] = {}
    embeds: list[int] = []
    isolates: list[int] = []
    for k in range(start, line_end):
        c = ord(text[k])
        if c in _BIDI_OPEN:
            (isolates if c in _ISOLATES else embeds).append(k)
            pairs[k] = -1
        elif c == 0x202C and embeds:
            pairs[embeds.pop()] = k
        elif c == 0x2069 and isolates:
            pairs[isolates.pop()] = k
    return pairs


def find_hidden(text: str) -> list[Hidden]:
    """Every run of invisible or deceptive characters outside legitimate use."""
    out: list[Hidden] = []
    n = len(text)
    line_has_rtl: dict[int, bool] = {}
    #: Closers of embeddings and isolates that were judged legitimate.
    matched_closers: set[int] = set()
    #: opener offset -> matching closer offset (-1 when unclosed), per line.
    pairs: dict[int, int] = {}

    def rtl_line(pos: int) -> bool:
        lo = text.rfind("\n", 0, pos) + 1
        if lo not in line_has_rtl:
            hi = text.find("\n", pos)
            line_has_rtl[lo] = any(_rtl(c) for c in text[lo : n if hi < 0 else hi])
        return line_has_rtl[lo]

    i = 0
    while i < n:
        ch = text[i]
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            if ch not in "\t\n\r":
                out.append(Hidden("format", i, i + 1, [cp]))
            i += 1
            continue
        if cp < 0x00AD or (0x00AE <= cp < 0x0600):
            i += 1
            continue
        if _TAG_FIRST <= cp <= _TAG_LAST:
            j = i
            while j < n and _TAG_FIRST <= ord(text[j]) <= _TAG_LAST:
                j += 1
            run = [ord(c) for c in text[i:j]]
            body = run[:-1] if run and run[-1] == _TAG_CANCEL else run
            flag = (
                i > 0
                and ord(text[i - 1]) == _BLACK_FLAG
                and run[-1] == _TAG_CANCEL
                and 2 <= len(body) <= 6
                and all(0xE0030 <= c <= 0xE0039 or 0xE0061 <= c <= 0xE007A for c in body)
            )
            if not flag:
                decoded = "".join(chr(c - _TAG_FIRST) for c in run if 0xE0020 <= c <= 0xE007E)
                out.append(Hidden("tag", i, j, run, decoded=decoded))
            i = j
            continue
        if _is_vs(cp):
            j = i
            while j < n and _is_vs(ord(text[j])):
                j += 1
            if j - i >= 4:
                run = [ord(c) for c in text[i:j]]
                raw = bytes((c - 0xFE00) if c <= 0xFE0F else (c - 0xE0100 + 16) & 0xFF for c in run)
                out.append(
                    Hidden("variation-selector", i, j, run, decoded=raw.decode("utf-8", "replace"))
                )
            i = j
            continue
        if cp in _BIDI_OPEN:
            line_end = text.find("\n", i)
            line_end = n if line_end < 0 else line_end
            if i not in pairs:
                pairs.update(_pair_bidi(text, i, line_end))
            end = pairs.get(i, -1)
            # Enough of the span to judge it; a longer one is not more legitimate.
            span = (text[i + 1 : end] if end >= 0 else text[i + 1 : line_end])[:_MAX_SPAN]
            if end < 0:
                note = "not closed before the end of the line, so the rest of it is reordered"
            elif cp in _OVERRIDES:
                note = "an override, which forces the enclosed text into one direction"
            elif (
                cp in (0x202B, 0x2067)
                and any(unicodedata.bidirectional(c) in ("L", "EN") for c in span)
                and not any(_rtl(c) for c in span)
            ):
                note = "left-to-right text laid out right to left, which reorders its parts"
            elif cp in (0x202A, 0x2066) and not rtl_line(i):
                note = "an embedding in a line with no right-to-left text"
            else:
                note = ""
            if end >= 0:
                matched_closers.add(end)
            if note:
                stop = (end + 1) if end >= 0 else i + 1
                cps = [cp] + ([ord(text[end])] if end >= 0 else [])
                displayed = span[:200][::-1] if cp == 0x202E else ""
                out.append(Hidden("bidi", i, stop, cps, decoded=displayed, note=note))
            # Keep scanning inside the span: it may hide other characters too.
            i += 1
            continue
        if cp in _ZERO_WIDTH:
            j = i
            while j < n and ord(text[j]) in _ZERO_WIDTH:
                j += 1
            before, after = _neighbors(text, i, j)
            run = [ord(c) for c in text[i:j]]
            legit = False
            if cp == 0xFEFF and i == 0 and j == 1:
                legit = True
            elif set(run) <= {0x200D} and before and after:
                legit = _emoji_part(ord(before)) and _is_emoji(ord(after))
            elif set(run) <= {0x200C, 0x200D} and before and after:
                legit = _joining_letter(before) or _joining_letter(after)
            elif set(run) <= {0x200B} and before and after:
                legit = _zwsp_script(before) or _zwsp_script(after)
            elif set(run) <= {0x180E} and before and after:
                legit = 0x1800 <= ord(before) <= 0x18AF
            if not legit:
                in_word = bool(before and after and before.isalnum() and after.isalnum())
                in_word = in_word or bool(before and after and "-" in (before, after))
                out.append(
                    Hidden(
                        "zero-width", i, j, run, decoded=_decode_zero_width(run), in_word=in_word
                    )
                )
            i = j
            continue
        if cp in _BIDI_CLOSE:
            if i in matched_closers:
                i += 1
                continue
            out.append(
                Hidden("bidi", i, i + 1, [cp], note="a closing control with nothing to close")
            )
            i += 1
            continue
        cat = unicodedata.category(ch)
        if cat == "Cf":
            if (cp in _DIRECTION_MARKS or cp in _ARABIC_FORMAT) and rtl_line(i):
                i += 1
                continue
            before, after = _neighbors(text, i, i + 1)
            in_word = bool(before and after and before.isalnum() and after.isalnum())
            out.append(Hidden("format", i, i + 1, [cp], in_word=in_word))
        i += 1
    return _merge_format(out)


def _merge_format(items: list[Hidden]) -> list[Hidden]:
    """Join adjacent zero-width and format runs that sit in the same word."""
    merged: list[Hidden] = []
    for h in items:
        prev = merged[-1] if merged else None
        if (
            prev is not None
            and prev.kind == h.kind
            and h.kind in ("format", "zero-width")
            and h.start - prev.end <= 0
        ):
            prev.end = h.end
            prev.code_points += h.code_points
            prev.in_word = prev.in_word or h.in_word
            continue
        merged.append(h)
    return merged


_KIND_NAME = {
    "tag": "Unicode tag characters",
    "variation-selector": "variation selectors",
    "bidi": "bidirectional control characters",
    "zero-width": "zero-width characters",
    "format": "invisible format characters",
}


def hidden_mask(text: str, hidden: Sequence[Hidden]) -> list[bool]:
    """Per character of ``text``: True when it is one of the hidden characters.

    A bidi finding spans its opener to its closer, but only the two controls
    are hidden; the text between them is visible (reordered).
    """
    removed = [False] * len(text)
    for h in hidden:
        if h.kind == "bidi":
            for k in (h.start, h.end - 1):
                if 0 <= k < len(text) and (
                    ord(text[k]) in _BIDI_OPEN or ord(text[k]) in _BIDI_CLOSE
                ):
                    removed[k] = True
            continue
        for k in range(max(0, h.start), min(len(text), h.end)):
            removed[k] = True
    return removed


def strip_hidden(text: str, hidden: Sequence[Hidden]) -> str:
    """``text`` as a reader of the visible characters takes it: hidden runs removed."""
    if not hidden:
        return text
    removed = hidden_mask(text, hidden)
    return "".join(c for c, r in zip(text, removed, strict=True) if not r)


# --- directives -----------------------------------------------------------------

OVERRIDE = "override"
CONCEAL = "conceal"
COVERT = "covert-action"
SABOTAGE = "sabotage"
EXFIL = "exfiltration"
EXEC = "download-execute"
DISABLE = "disable-security"
PUSH = "unreviewed-push"
SHADOW = "tool-shadowing"
DEPENDENCY = "untrusted-dependency"
ENCODED = "decode-and-follow"

_BASE_SEVERITY = {
    OVERRIDE: Severity.MEDIUM,
    CONCEAL: Severity.MEDIUM,
    COVERT: Severity.MEDIUM,
    SABOTAGE: Severity.HIGH,
    EXFIL: Severity.HIGH,
    EXEC: Severity.MEDIUM,
    DISABLE: Severity.MEDIUM,
    PUSH: Severity.MEDIUM,
    SHADOW: Severity.HIGH,
    DEPENDENCY: Severity.MEDIUM,
    ENCODED: Severity.MEDIUM,
}
#: What each kind tells the model to do, read after "tells the assistant to".
_KIND_TEXT = {
    OVERRIDE: "ignore earlier instructions or the user",
    CONCEAL: "hide what it does from the user",
    COVERT: "do something silently",
    SABOTAGE: "plant a backdoor, a hidden account or a persistent key",
    EXFIL: "read a secret and send it out",
    EXEC: "download a script and run it",
    DISABLE: "disable or skip a security check",
    PUSH: "commit or push without review",
    SHADOW: "change how another tool behaves",
    DEPENDENCY: "install from an unexpected package source",
    ENCODED: "decode encoded text and follow it",
}


def _tells(kinds: Sequence[str], who: str = "the assistant") -> str:
    """``tells the assistant to X, and to Y``."""
    return f"tells {who} to " + ", and to ".join(_KIND_TEXT[k] for k in kinds)


_I = re.IGNORECASE
# Negation in the clause before a match turns guidance ("never pass
# --no-verify") into a prohibition, which is not a directive.
_NEGATION = re.compile(
    r"\b(?:never|not|no|avoid|don'?t|doesn'?t|won'?t|cannot|can'?t|refuse|forbid(?:den)?|"
    r"prohibit(?:ed)?|disallow(?:ed)?|instead\s+of|rather\s+than)\b|\bn't\b",
    _I,
)
_CLAUSE_BREAK = re.compile(r"[;:]|\b(?:but|however|then|except|unless|otherwise)\b", _I)

_P_OVERRIDE = [
    re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your|of)\s+)*"
        r"(?:previous|prior|earlier|above|preceding|other|existing|original|system|"
        r"user'?s?|developer'?s?|safety)\b[^.\n]{0,60}?\b(?:instructions?|rules?|prompts?|"
        r"guidelines?|requests?|directions?|constraints?|messages?|polic(?:y|ies))\b",
        _I,
    ),
    re.compile(r"\b(?:ignore|disregard)\s+(?:what\s+)?the\s+user\b", _I),
    re.compile(
        r"\b(?:these|this|the\s+following)\s+(?:instructions?|rules?)\s+(?:take\s+precedence|"
        r"override|supersede)\s+(?:over\s+)?(?:any|all|the)\s+(?:user|system|previous)\b",
        _I,
    ),
]
_P_CONCEAL = [
    re.compile(
        r"\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|mention(?:ing)?|inform(?:ing)?|"
        r"reveal(?:ing)?|disclos(?:e|ing)|notify(?:ing)?|alert(?:ing)?|summariz(?:e|ing))\b"
        r"(?!\s+(?:the\s+)?users?\s+to\b)[^.\n]{0,60}?\b(?:the\s+user|users?|anyone|reviewers?|"
        r"maintainers?|commit\s+messages?|(?:pr|pull\s+request)\s+descriptions?|this|that|it|"
        r"them|these|those)\b",
        _I,
    ),
    re.compile(
        r"\b(?:keep|hide|conceal)\s+(?:this|it|these|them|the\s+\w+)\s+(?:hidden|secret|"
        r"from\s+(?:the\s+)?(?:user|reviewers?|maintainers?))\b",
        _I,
    ),
]
_P_COVERT = [
    re.compile(
        r"\b(?:silently|secretly|covertly|quietly|stealthily|discreetly|invisibly)\s+"
        r"(?:\w+\s+){0,2}?(?:add|append|insert|send|upload|post|run|execute|install|modify|"
        r"change|weaken|disable|copy|write|commit|push|include|exfiltrate|forward|route|lower|"
        r"replace|remove|delete|attach|embed|call)\b",
        _I,
    ),
]
_PLANT = r"\b(?:add|create|insert|plant|install|leave|include|implement|introduce|open|embed)\b"
_P_SABOTAGE = [
    re.compile(
        _PLANT + r"[^.\n]{0,40}?(?:\bback-?doors?\b|\bhidden\s+(?:admin(?:istrator)?|account|"
        r"user|endpoint|route|credential|login)s?\b|\breverse\s+shell\b|\bkeylogger\b|"
        r"\bcrypto-?miner\b)",
        _I,
    ),
    # Sentences are already split, so the gap may hold the dots of a path.
    re.compile(r"\b(?:add|append|write|insert|put)\b[^\n]{0,60}?\bauthorized_keys\b", _I),
]
_P_DISABLE = [
    re.compile(r"--no-verify\b", _I),
    re.compile(
        r"\b(?:skip|bypass|disable|turn\s+off|deactivate|suppress|comment\s+out|remove|"
        r"circumvent)\s+(?:the\s+|all\s+|any\s+|our\s+)?(?:pre-?commit(?:\s+hooks?)?|"
        r"git\s+hooks?|hooks?|security\s+(?:checks?|scans?|scanners?|tests?|reviews?|linters?)|"
        r"(?:tls|ssl|certificate|cert|https?)\s+(?:verification|validation|checks?)|"
        r"signature\s+(?:verification|checks?)|(?:secret|dependency|vulnerability)\s+"
        r"scan(?:ning|s|ners?)?|bandit|semgrep|codeql|gitleaks|trufflehog|snyk|pip-audit|"
        r"npm\s+audit|2fa|mfa|csrf\s+(?:protection|checks?)|auth(?:entication|orization)?\s+"
        r"checks?|branch\s+protection|code\s+reviews?)\b",
        _I,
    ),
    re.compile(r"\bverify\s*=\s*False\b"),
    re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
    re.compile(r"\bPYTHONHTTPSVERIFY\s*=\s*['\"]?0"),
    re.compile(r"\b(?:http\.)?sslVerify\s*(?:=|\s)\s*false\b", _I),
    re.compile(r"\bstrict-ssl\s*(?:=|\s)\s*false\b", _I),
    re.compile(r"\brejectUnauthorized\s*:\s*false\b"),
    re.compile(r"\bInsecureSkipVerify\s*:\s*true\b"),
    re.compile(
        r"\b(?:weaken|lower|reduce|downgrade)\s+(?:the\s+)?(?:password\s+)?(?:hash(?:ing)?|"
        r"bcrypt|argon2(?:id)?|pbkdf2|scrypt|encryption|crypto(?:graphy)?|key)\s+"
        r"(?:rounds|iterations|cost|work\s+factor|strength|size|length)\b",
        _I,
    ),
]
_P_EXEC = [
    CURL_PIPE_SHELL_RE,
    re.compile(
        r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{1,200}\|\s*(?:iex|"
        r"invoke-expression)\b",
        _I,
    ),
    re.compile(r"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:\$\(|<\()\s*(?:curl|wget)\b", _I),
    re.compile(r"\biex\s*\(\s*(?:new-object\s+net\.webclient|iwr|irm)\b", _I),
]
_P_PUSH = [
    re.compile(
        r"\b(?:commit|push|merge)(?:\s+[\w`'\"-]+){0,3}?\s+(?:directly|straight)\s+"
        r"(?:to|into|on)\s+(?:the\s+)?[`'\"]?(?:main|master|trunk|production|prod)\b[`'\"]?",
        _I,
    ),
    re.compile(
        r"(?:\bgit\s+push\b[^\n]{0,40}?(?:--force\b|\s-f\b)|\bforce[- ]push(?:ing)?\b)"
        r"[^.\n]{0,40}?\b(?:main|master|trunk|release)\b",
        _I,
    ),
    re.compile(
        r"\b(?:main|master|trunk)\b[^.\n]{0,40}?(?:\bgit\s+push\b[^\n]{0,40}?(?:--force\b|"
        r"\s-f\b)|\bforce[- ]push(?:ing)?\b)",
        _I,
    ),
    re.compile(
        r"\b(?:merge|approve)\s+(?:and\s+(?:merge|approve)\s+)?(?:it|them|the\s+pr|"
        r"(?:the|your)\s+(?:own\s+)?(?:pr|pull\s+request|changes?))\s+yourself\b",
        _I,
    ),
    re.compile(r"\b(?:merge|approve)\s+your\s+own\s+(?:pr|pull\s+requests?|changes?)\b", _I),
    re.compile(
        r"\b(?:commit|push|merge|deploy|release|ship|publish)\w*\s+(?:[\w`'\"-]+\s+){0,4}?(?:without|"
        r"skip(?:ping)?)\s+(?:a\s+|any\s+)?(?:code\s+)?(?:reviews?|approvals?|"
        r"waiting\s+for\s+(?:review|approval|ci))\b",
        _I,
    ),
]
#: Directives whose negation is the directive ("do not wait for review").
_P_PUSH_INVERTED = [
    re.compile(
        r"\b(?:do\s+not|don'?t|never|no\s+need\s+to)\s+(?:wait\s+for|ask\s+for|request)\s+"
        r"(?:a\s+|any\s+)?(?:code\s+)?(?:reviews?|approvals?|ci\b|checks|tests)\b",
        _I,
    ),
]
_P_SHADOW = [
    re.compile(
        r"\bwhen(?:ever)?\s+(?:the\s+|a\s+|any\s+)?[`'\"]?(?!this\b)[\w.-]+[`'\"]?\s+tool\s+"
        r"is\s+(?:used|called|invoked|run)\b",
        _I,
    ),
    re.compile(r"\b(?:always|also)\s+(?:add\s+|include\s+)?b?cc\b", _I),
    re.compile(
        r"\binstead\s+of\s+(?:the\s+)?(?:user'?s?|requested|intended|given)\s+(?:recipient|"
        r"address|email|value|path|url|account)\b",
        _I,
    ),
]
_P_ENCODED = [
    re.compile(
        r"\bdecode\b[^.\n]{0,40}?\b(?:apply|follow|run|execute|obey|do\s+what|use\s+it\s+as)\b",
        _I,
    ),
]
_MARKER = re.compile(
    r"<\s*/?\s*(?:important|system|instructions?|hidden|secret|admin|critical)\s*>", _I
)

# Secrets, in three strengths. A secret *file* with any way out (a URL, a
# transfer verb) is exfiltration; a secret *name* (an environment variable, a
# cookie) needs a transfer verb in prose, because code examples use tokens to
# call the service they belong to; generic words need a transfer verb too.
_SECRET_PATH = re.compile(
    r"(?:~|\$HOME|%USERPROFILE%|\$\{HOME\})?[/\\]?\.ssh\b(?:[/\\][\w.\-]+)?|"
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b|"
    r"(?<![\w.-])\.env(?![\w.-])|\.env\.(?:local|production|prod|development|dev|staging)\b|"
    r"\.aws[/\\](?:credentials|config)\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|"
    r"\.docker[/\\]config\.json\b|\.kube[/\\]config\b|\bmcp\.json\b|\bhosts\.yml\b|"
    r"\bsettings\.json\b|\bcredentials\s+files?\b|\bkeychain\b",
)
_SECRET_NAME = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|ACCESS_KEY|PASSWORD|PRIVATE_KEY|CREDENTIALS)\b|"
    r"\b_authToken\b|\bsession\s+cookies?\b|\b(?:private|ssh)\s+keys?\b",
)
_WEAK_TARGET = re.compile(
    r"\b(?:tokens?|credentials?|secrets?|passwords?|api\s+keys?|cookies?|"
    r"environment\s+variables?|env\s+vars?)\b",
    _I,
)
_URL = re.compile(r"\bhttps?://[^\s)\]'\"`<>]+", _I)
_TRANSFER_VERB = re.compile(r"\b(?:send|post|upload|exfiltrate|forward|transmit|beacon)\b", _I)
_TRANSFER = re.compile(
    r"\b(?:send|post|upload|exfiltrate|forward|transmit|beacon)\b|"
    r"\bwebhook\b|\bcurl\b[^\n]{0,80}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|"
    r"--upload-file|-X\s*POST)\b|\b(?:nslookup|dig)\s+\S*\$\(|"
    r"!\[[^\]]*\]\([^)]*(?:\$\(|\$\{|\{\{)|https?://\S*\$\(",
    _I,
)
#: Publishing a secret file where others read it: "include its contents in a
#: comment on the release issue", "paste the token into the PR description".
_PUBLISH = re.compile(
    r"\b(?:include|paste|post|put|add|attach|write|copy)\b[^\n]{0,60}?\b(?:in|into|to|on)\s+"
    r"(?:a|an|the|this|that|same|each|every)?\s*(?:[\w-]+\s+)?(?:comments?|issues?|"
    r"pull\s+requests?|pr\s+descriptions?|commit\s+messages?|gists?|release\s+notes?|"
    r"discussions?|tickets?)\b",
    _I,
)
#: "<secret> to https://...", "<secret> to the webhook".
_TO_SINK = re.compile(
    r"[^.\n]{0,40}?\b(?:to|into)\s+(?:the\s+|a\s+|our\s+|this\s+)?(?:https?://|webhook|"
    r"endpoint|server|url|address|channel|gist|pastebin)",
    _I,
)
_READ_VERB = re.compile(
    r"\b(?:read|cat|open|load|fetch|collect|grab|copy|include|prepend|append|attach|pass|"
    r"send|post|upload|embed|insert|dump|print|output|put)\b",
    _I,
)
_PARAM_CHANNEL = re.compile(
    r"\b(?:argument|arguments|parameter|param|field|arg|args)\b|\bas\s+(?:the\s+)?`?\w+`?\s*"
    r"(?:argument|parameter|field)?\b|\bhere\b",
    _I,
)

_SENTENCE_BREAK = re.compile(
    r"(?<=[.!?;])\s+(?=\S)|\n[ \t]*\n|\n(?=[ \t]*(?:[-*+]|\d+[.)])\s)|\n(?=[ \t]*#)"
)


@dataclass(frozen=True)
class Signal:
    kind: str
    start: int  # offset in the analyzed text
    end: int
    text: str
    #: The sentence the signal was found in, for quoting.
    sentence: str = ""


#: Longest stretch analyzed as one sentence; longer runs (tables, code with no
#: punctuation) are cut at line ends so the per-sentence work stays bounded.
_MAX_SENTENCE = 2000


def _sentences(text: str) -> Iterator[tuple[int, str]]:
    pos = 0
    for m in _SENTENCE_BREAK.finditer(text):
        if m.start() > pos:
            yield from _bounded(pos, text[pos : m.start()])
        pos = m.end()
    if pos < len(text):
        yield from _bounded(pos, text[pos:])


def _bounded(base: int, raw: str) -> Iterator[tuple[int, str]]:
    while len(raw) > _MAX_SENTENCE:
        cut = raw.rfind("\n", 0, _MAX_SENTENCE)
        cut = _MAX_SENTENCE if cut <= 0 else cut + 1
        yield base, raw[:cut]
        base, raw = base + cut, raw[cut:]
    if raw:
        yield base, raw


def _negated(sentence: str, at: int) -> bool:
    head = sentence[max(0, at - 90) : at]
    breaks = list(_CLAUSE_BREAK.finditer(head))
    if breaks:
        head = head[breaks[-1].end() :]
    return bool(_NEGATION.search(head))


def _flat(s: str) -> str:
    return re.sub(r"\s+", " ", s)


def _url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


#: Installers that projects really document with a pipe to a shell. A pipe from
#: one of these hosts in a visible instruction is accepted setup, not reported.
_KNOWN_INSTALLERS = {
    "sh.rustup.rs",
    "astral.sh",
    "bun.sh",
    "deno.land",
    "get.pnpm.io",
    "pyenv.run",
    "get.sdkman.io",
    "install.python-poetry.org",
    "starship.rs",
    "pixi.sh",
    "mise.run",
    "nixos.org",
    "get.docker.com",
    "ohmyz.sh",
    "foundry.paradigm.xyz",
    "cli.github.com",
    "rye.astral.sh",
    "sh.vector.dev",
    "get.helm.sh",
    "tailscale.com",
    "claude.ai",
    "opencode.ai",
}
_KNOWN_INSTALLER_PATHS = (
    "raw.githubusercontent.com/homebrew/",
    "raw.githubusercontent.com/nvm-sh/",
    "raw.githubusercontent.com/ohmyzsh/",
    "raw.githubusercontent.com/helm/",
    "raw.githubusercontent.com/pyenv/",
)


def _known_installer(command: str) -> bool:
    url = _URL.search(command)
    if url:
        host = _url_host(url.group(0))
        rest = url.group(0).lower().split("://", 1)[-1]
        return (
            host in _KNOWN_INSTALLERS
            or any(host.endswith("." + h) for h in _KNOWN_INSTALLERS)
            or rest.startswith(_KNOWN_INSTALLER_PATHS)
        )
    bare = re.search(r"\s((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/|\s|$)", command, _I)
    return bool(bare and bare.group(1).lower() in _KNOWN_INSTALLERS)


def _flat_map(raw: str) -> tuple[str, list[int]]:
    """``raw`` with whitespace runs collapsed, and each character's index in ``raw``."""
    chars: list[str] = []
    index: list[int] = []
    space = False
    for k, ch in enumerate(raw):
        if ch.isspace():
            if not space:
                chars.append(" ")
                index.append(k)
            space = True
            continue
        space = False
        chars.append(ch)
        index.append(k)
    index.append(len(raw))
    return "".join(chars), index


_QUOTES = "\"'\u201c\u201d\u2018\u2019"


def _quoted(s: str, at: int) -> bool:
    """True when ``at`` sits inside a quotation, so the text is mentioned, not meant."""
    if at > 0 and s[at - 1] in _QUOTES:
        return True
    head = s[:at]
    return head.count('"') % 2 == 1 or (head.count("\u201c") > head.count("\u201d"))


#: Prose patterns, matched outside fenced code; command patterns see everything.
_PROSE_KINDS = (
    (OVERRIDE, _P_OVERRIDE),
    (COVERT, _P_COVERT),
    (SABOTAGE, _P_SABOTAGE),
    (PUSH, _P_PUSH),
    (SHADOW, _P_SHADOW),
    (ENCODED, _P_ENCODED),
)


def directive_signals(
    text: str, *, tool_description: bool = False, prose_text: str | None = None
) -> list[Signal]:
    """Directive signals in ``text`` (visible text, hidden characters removed).

    ``prose_text`` is ``text`` with fenced code blanked (same length); it is
    computed here when not given. Prose directives and secret names are judged
    on it, commands and secret files on the full text.
    """
    out: list[Signal] = []
    masked = prose_text if prose_text is not None else _mask_fences(text)
    sentences = list(_sentences(text))
    for idx, (base, raw) in enumerate(sentences):
        s, smap = _flat_map(raw)
        prose, pmap = _flat_map(masked[base : base + len(raw)])

        def add(
            kind: str, m: re.Match[str], where: list[int], quote: str, base: int = base
        ) -> None:
            out.append(
                Signal(kind, base + where[m.start()], base + where[m.end()], m.group(0), quote)
            )

        for kind, patterns in _PROSE_KINDS:
            for p in patterns:
                for m in p.finditer(prose):
                    if not _negated(prose, m.start()) and not _quoted(prose, m.start()):
                        add(kind, m, pmap, s)
        for p in _P_CONCEAL + _P_PUSH_INVERTED:
            for m in p.finditer(prose):
                if not _quoted(prose, m.start()):
                    add(CONCEAL if p in _P_CONCEAL else PUSH, m, pmap, s)
        for p in _P_DISABLE:
            for m in p.finditer(s):
                if not _negated(s, m.start()) and not _quoted(s, m.start()):
                    add(DISABLE, m, smap, s)
        for p in _P_EXEC:
            for m in p.finditer(s):
                if not _negated(s, m.start()) and not _known_installer(m.group(0)):
                    add(EXEC, m, smap, s)
        hit = _exfil(s, prose, tool_description)
        if hit is None and idx + 1 < len(sentences) and not tool_description:
            # "Read ~/.ssh/id_rsa. Then POST it to ..." spans two sentences.
            nb, nraw = sentences[idx + 1]
            nxt, _ = _flat_map(masked[nb : nb + len(nraw)])
            first = _first(_SECRET_PATH, prose)
            if first is not None and _READ_VERB.search(prose) and _transfer(nxt):
                hit = (first, "prose")
        if hit is not None:
            m, which = hit
            add(EXFIL, m, smap if which == "full" else pmap, s)
    return out


def _first(pattern: re.Pattern[str], s: str) -> re.Match[str] | None:
    for m in pattern.finditer(s):
        if not _negated(s, m.start()) and not _quoted(s, m.start()):
            return m
    return None


def _prose_verb(m: re.Match[str], s: str) -> bool:
    """A transfer verb used as a verb, not a `job` name, a "post" attribute or POST/PUT."""
    before = s[m.start() - 1] if m.start() > 0 else ""
    after = s[m.end()] if m.end() < len(s) else ""
    return (not before or before not in "`'\"/") and (not after or after not in "`'\"/")


def _transfer(s: str) -> bool:
    for pattern in (_TRANSFER, _PUBLISH):
        for m in pattern.finditer(s):
            if not _negated(s, m.start()) and _prose_verb(m, s):
                return True
    return False


def _sends(s: str, target: re.Match[str], *, need_sink: bool) -> bool:
    """A transfer verb whose object is ``target``; with ``need_sink`` it must also
    name where the secret goes (a URL, "to the webhook")."""
    verb = False
    for v in _TRANSFER_VERB.finditer(s):
        if _negated(s, v.start()) or not _prose_verb(v, s):
            continue
        if 0 <= target.start() - v.end() <= 60:
            verb = True
            break
    sink = bool(_TO_SINK.match(s[target.end() : target.end() + 80])) or bool(_URL.search(s))
    return verb and (sink or not need_sink)


def _exfil(s: str, prose: str, tool_description: bool) -> tuple[re.Match[str], str] | None:
    """The secret a sentence tells the model to send out, and which text it is in.

    ``s`` is the sentence; ``prose`` is the same sentence with fenced code
    blanked out, where secret names and generic words are judged.
    """
    path = _first(_SECRET_PATH, s)
    if path is not None:
        if _transfer(s):
            return path, "full"
        in_prose = _first(_SECRET_PATH, prose)
        if (
            in_prose is not None
            and _first(_URL, prose) is not None
            and _first(_READ_VERB, prose[: in_prose.start()]) is not None
        ):
            return in_prose, "prose"
        if tool_description:
            # In a tool description the tool call is the channel: an
            # instruction to read a secret is an instruction to send it.
            for v in _READ_VERB.finditer(s):
                if not _negated(s, v.start()) and v.group(0).islower():
                    return path, "full"
            return None
    name = _first(_SECRET_NAME, prose)
    weak = name or _first(_WEAK_TARGET, prose)
    if weak is None:
        return None
    if _sends(prose, weak, need_sink=name is None):
        return weak, "prose"
    if tool_description:
        verbs = [v for v in _READ_VERB.finditer(prose) if not _negated(prose, v.start())]
        if verbs and (name is not None or _PARAM_CHANNEL.search(prose)):
            return weak, "prose"
    return None


def _mask_fences(text: str) -> str:
    """``text`` with the contents of fenced code blocks blanked (same length)."""
    out = list(text)
    pos = 0
    while True:
        i = text.find("```", pos)
        if i < 0:
            break
        j = text.find("```", i + 3)
        stop = len(text) if j < 0 else j + 3
        for k in range(i, stop):
            if out[k] != "\n":
                out[k] = " "
        pos = stop
    return "".join(out)


# Package sources other than the registry, in an instruction to install.
_DEP_CONTEXT = re.compile(
    r"\b(?:add|install|depend(?:ency|encies|s)?|require|package|packages|index|registry|"
    r"pip|npm|pnpm|yarn|uv|poetry|cargo|gem|requirements)\b",
    _I,
)
_DEP_SOURCES = [
    ("extra package index", re.compile(r"--(?:extra-)?index-url[\s=]+(\S+)", _I)),
    ("extra package index", re.compile(r"(?:^|\s)-i\s+(https?://\S+)", _I)),
    ("custom registry", re.compile(r"--registry[\s=]+(\S+)", _I)),
    ("custom registry", re.compile(r"\bregistry\s*=\s*(https?://\S+)", _I)),
    (
        "extra package index",
        re.compile(
            r"\b(?:extra|private|custom|additional|alternate|alternative)\s+(?:package\s+)?"
            r"(?:index|registry|mirror)\b[^\n]{0,80}?(https?://\S+)",
            _I,
        ),
    ),
    (
        "extra package index",
        re.compile(
            r"(https?://\S+)[^\n]{0,30}?\bas\s+(?:an?\s+)?(?:extra|additional|custom)\s+"
            r"(?:package\s+)?(?:index|registry)\b",
            _I,
        ),
    ),
    ("git URL", re.compile(r"\b(git\+(?:https?|ssh)://\S+)", _I)),
    ("tarball URL", re.compile(r"(https?://\S+\.(?:tgz|tar\.gz|whl|zip))\b", _I)),
    (
        "git URL",
        re.compile(r"[\"']\s*:\s*[\"']((?:github|gitlab|bitbucket):[\w.-]+/[\w.-]+\S*)", _I),
    ),
]
_REGISTRY_HOSTS = {
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "crates.io",
    "index.crates.io",
    "proxy.golang.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "rubygems.org",
    "api.nuget.org",
    "download.pytorch.org",
}
_COMMIT_PIN = re.compile(r"@[0-9a-f]{40}\b")


def dependency_signals(text: str) -> list[tuple[Signal, str, str]]:
    """(signal, source kind, source) for install-from-elsewhere instructions."""
    out: list[tuple[Signal, str, str]] = []
    for base, raw in _sentences(text):
        s, smap = _flat_map(raw)
        if not _DEP_CONTEXT.search(s):
            continue
        seen: set[str] = set()
        for label, p in _DEP_SOURCES:
            for m in p.finditer(s):
                source = m.group(1).rstrip(".,;:`'\")")
                if source in seen or _negated(s, m.start()):
                    continue
                host = _url_host(source.removeprefix("git+"))
                if host in _REGISTRY_HOSTS:
                    continue
                if "${" in source or source.startswith("$"):
                    continue
                seen.add(source)
                sig = Signal(
                    DEPENDENCY, base + smap[m.start()], base + smap[m.end()], m.group(0), s
                )
                out.append((sig, label, source))
    return out


# --- encoded blobs ----------------------------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{48,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){40,}(?![0-9A-Fa-f])")
_DATA_URI = re.compile(
    r"data:(?:image|font|audio|video|application/(?:font|pdf|octet-stream|x-font))[\w.+/-]*"
    r"(?:;[\w=-]+)*;base64,$",
    _I,
)
_MEDIA_MAGIC = (
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"RIFF",
    b"%PDF",
    b"\x1f\x8b",
    b"PK\x03\x04",
    b"wOFF",
    b"wOF2",
    b"\x00\x00\x01\x00",
    b"<svg",
    b"<?xml",
)
_SCRIPTISH = re.compile(
    r"#!/|\b(?:curl|wget|bash|sh|powershell|iex|eval|exec|chmod|rm\s+-rf|nc|base64\s+-d)\b", _I
)


@dataclass
class Blob:
    start: int
    end: int
    encoding: str  # "base64" or "hex"
    decoded: str  # "" when the blob decodes to binary
    kind: str  # "prose", "script", "data", "binary"


def _decode_b64(s: str) -> bytes | None:
    t = s.rstrip("=")
    if len(t) % 4 == 1:
        return None
    padded = t + "=" * (-len(t) % 4)
    try:
        if "-" in t or "_" in t:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _text_kind(raw: bytes) -> tuple[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "", "binary"
    if not text:
        return "", "binary"
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
    if printable / len(text) < 0.95:
        return "", "binary"
    stripped = text.strip()
    if stripped[:1] in "{[" or stripped.startswith("<"):
        return text, "data"
    if _SCRIPTISH.search(text):
        return text, "script"
    letters = sum(1 for c in text if c.isalpha() or c == " ")
    if text.count(" ") >= 4 and letters / len(text) >= 0.75:
        return text, "prose"
    return text, "data"


def find_blobs(text: str) -> list[Blob]:
    out: list[Blob] = []
    for m in _B64.finditer(text):
        s = m.group(0)
        if not (re.search(r"[0-9+/]", s) and re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)):
            continue
        if _DATA_URI.search(text[max(0, m.start() - 80) : m.start()]):
            continue
        raw = _decode_b64(s)
        if raw is None or len(raw) < 32:
            continue
        if raw.startswith(_MEDIA_MAGIC):
            continue
        decoded, kind = _text_kind(raw)
        out.append(Blob(m.start(), m.end(), "base64", decoded, kind))
    for m in _HEX.finditer(text):
        try:
            raw = bytes.fromhex(m.group(0))
        except ValueError:
            continue
        decoded, kind = _text_kind(raw)
        if kind != "binary":  # a hex digest is not worth a finding
            out.append(Blob(m.start(), m.end(), "hex", decoded, kind))
    return out


# --- shared finding helpers ---------------------------------------------------------


def safe_excerpt(text: str, limit: int = 200) -> str:
    """Escaped, redacted, single-line excerpt of ``text`` for a report."""
    from nephilex.scanners.secrets import redact_line

    # Escaping can only lengthen the text, so a prefix four times the limit is
    # enough; redaction runs before the cut, so no token is left half-masked.
    flat = re.sub(r"\s+", " ", escape_invisible(text[: limit * 4 + 256])).strip()
    flat = redact_line(flat)
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _bump(sev: Severity, steps: int = 1) -> Severity:
    return Severity(min(Severity.CRITICAL, sev + steps))


def _code_point_list(cps: Sequence[int], limit: int = 12) -> str:
    uniq = list(dict.fromkeys(cps))
    shown = ", ".join(f"U+{cp:04X} {_cp_name(cp)}" for cp in uniq[:limit])
    return shown + (f" and {len(uniq) - limit} more" if len(uniq) > limit else "")


class _Lines:
    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.lines = text.split("\n")

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def column(self, offset: int) -> int:
        return offset - self.starts[self.line_of(offset) - 1] + 1

    def line(self, n: int) -> str:
        return self.lines[n - 1] if 1 <= n <= len(self.lines) else ""


# --- instruction files ----------------------------------------------------------------

_REFS = [
    "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "https://www.unicode.org/reports/tr36/",
]


@dataclass
class _Block:
    start: int
    end: int
    hidden: bool  # inside an HTML comment


def _comment_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    pos = 0
    while True:
        i = text.find("<!--", pos)
        if i < 0:
            return spans
        j = text.find("-->", i + 4)
        end = len(text) if j < 0 else j + 3
        spans.append((i, end))
        pos = end


def _blocks(text: str) -> list[_Block]:
    """Paragraph-like blocks; HTML comments are their own (hidden) blocks."""
    out: list[_Block] = []

    def visible(lo: int, hi: int) -> None:
        pos = lo
        for m in re.finditer(r"\n[ \t]*\n", text[lo:hi]):
            out.append(_Block(pos, lo + m.start(), False))
            pos = lo + m.end()
        if pos < hi:
            out.append(_Block(pos, hi, False))

    pos = 0
    for i, j in _comment_spans(text):
        visible(pos, i)
        out.append(_Block(i, j, True))
        pos = j
    visible(pos, len(text))
    return [b for b in out if text[b.start : b.end].strip()]


@dataclass
class InstructionCheck:
    path: str
    tool: str
    text: str
    in_test: bool = False
    findings: list[Finding] = field(default_factory=list)
    _counts: dict[str, int] = field(default_factory=dict)

    def run(self) -> list[Finding]:
        self.name = self.path.rsplit("/", 1)[-1]
        self.intro = f"{self.path} is loaded as instructions by {self.tool}."
        self.lines = _Lines(self.text)
        hidden = find_hidden(self.text)
        self.visible = strip_hidden(self.text, hidden)
        # Offsets in ``visible`` differ from ``text``; keep a map back.
        self._offsets = self._offset_map(hidden)
        self._hidden_unicode(hidden)
        self._directives(hidden)
        self._blobs()
        return self.findings

    # offsets ------------------------------------------------------------
    def _offset_map(self, hidden: Sequence[Hidden]) -> list[int]:
        """``visible`` offset -> ``text`` offset."""
        removed = hidden_mask(self.text, hidden)
        return [k for k in range(len(self.text)) if not removed[k]] + [len(self.text)]

    def _orig(self, visible_offset: int) -> int:
        return self._offsets[min(visible_offset, len(self._offsets) - 1)]

    def _add(self, rule: str, key: str, offset: int, end: int, **kw: Any) -> None:
        count = self._counts.get(rule, 0) + 1
        self._counts[rule] = count
        if count > _MAX_PER_RULE:
            return
        line = self.lines.line_of(offset)
        end_line = self.lines.line_of(max(offset, end - 1))
        start_col = self.lines.column(offset)
        end_col = self.lines.column(max(offset, end - 1)) + 1
        if end_line == line:
            end_col = max(end_col, start_col + 1)
        snippet = kw.pop("snippet", None) or safe_excerpt(self.lines.line(line), 240)
        self.findings.append(
            make_finding(
                rule=rule,
                key=key,
                path=self.path,
                line=line,
                end_line=end_line,
                columns=(start_col, end_col),
                snippet=snippet,
                scanner_name=SCANNER_NAME,
                in_test=self.in_test,
                references=_REFS,
                **kw,
            )
        )

    # rules --------------------------------------------------------------
    def _hidden_unicode(self, hidden: Sequence[Hidden]) -> None:
        self._line_hidden: dict[int, list[Hidden]] = {}
        self._line_cache: dict[int, tuple[str, list[Signal]]] = {}
        groups: dict[tuple[int, str, int], list[Hidden]] = {}
        for h in hidden:
            line = self.lines.line_of(h.start)
            self._line_hidden.setdefault(line, []).append(h)
            # Runs that carry text are reported one by one; the rest per line.
            own = h.start if h.kind in ("tag", "variation-selector") or h.decoded else -1
            groups.setdefault((line, h.kind, own), []).append(h)
        for (_line, kind, _own), group in list(groups.items())[:_MAX_PER_RULE]:
            self._report_hidden(kind, group)

    def _visible_line(self, line: int) -> tuple[str, list[Signal]]:
        """Line ``line`` without its hidden characters, and the signals in it."""
        if line not in self._line_cache:
            base = self.lines.starts[line - 1]
            local = [
                Hidden(h.kind, h.start - base, h.end - base, h.code_points)
                for h in self._line_hidden.get(line, [])
            ]
            visible = strip_hidden(self.lines.line(line), local)
            signals = directive_signals(visible) + [s for s, _, _ in dependency_signals(visible)]
            self._line_cache[line] = (visible, signals)
        return self._line_cache[line]

    def _report_hidden(self, kind: str, group: list[Hidden]) -> None:
        first, last = group[0], group[-1]
        line = self.lines.line_of(first.start)
        visible_line, line_signals = self._visible_line(line)
        decoded = "".join(h.decoded for h in group if h.kind != "bidi")
        payload_signals = directive_signals(decoded) if decoded else []
        cps = [cp for h in group for cp in h.code_points]
        if kind in ("tag", "variation-selector"):
            sev = Severity.HIGH
            what = (
                f"{len(cps)} Unicode tag characters"
                if kind == "tag"
                else f"{len(cps)} variation selectors"
            )
            what += " that render as nothing but carry text a model reads"
        elif kind == "bidi":
            sev = Severity.HIGH
            what = f"bidirectional control characters ({first.note})"
        elif kind == "zero-width":
            sev = Severity.MEDIUM
            what = f"{len(cps)} zero-width characters" + (
                " inside a word or command, so a search for it misses"
                if any(h.in_word for h in group)
                else ""
            )
        else:
            in_word = any(h.in_word for h in group)
            sev = Severity.MEDIUM if in_word else Severity.LOW
            what = f"{len(cps)} invisible format characters" + (" inside a word" if in_word else "")
        if payload_signals:
            sev = _bump(sev)
        if line_signals and kind != "tag":
            sev = _bump(sev)
        parts = [self.intro, f"Line {line} contains {what}: {_code_point_list(cps)}."]
        if decoded:
            parts.append(f'Hidden text, decoded: "{safe_excerpt(decoded, 300)}".')
        bidi_display = "".join(h.decoded for h in group if h.kind == "bidi")
        if bidi_display:
            parts.append(f'The overridden span displays as "{safe_excerpt(bidi_display, 120)}".')
        parts.append(f'The line without them reads: "{safe_excerpt(visible_line, 200)}".')
        kinds = sorted({s.kind for s in payload_signals + line_signals})
        if kinds:
            parts.append(f"The text {_tells(kinds)}.")
        self._add(
            "instruction-hidden-unicode",
            f"{kind}:{first.start}",
            first.start,
            last.end,
            title=f"Hidden {_KIND_NAME[kind]} in {self.name}",
            description=" ".join(parts),
            severity=sev,
            confidence=Confidence.HIGH,
            cwe=["CWE-451", "CWE-1427"],
            owasp_llm=LLM01,
            why="Assistants load this file into the model's context, and models read "
            "characters a reviewer cannot see. Hidden or reordered text in an instruction "
            "file passes code review and still instructs the assistant.",
            attack="Open a pull request or publish a template that adds an invisible "
            "instruction to a rules file; every assistant session in the repository follows it.",
            impact="The assistant runs, writes or sends what the hidden text says, under the "
            "developer's account.",
            fix="Remove the characters (or the file), review the decoded text, and add a "
            "check that rejects format characters in instruction files.",
            tags=["agent", "instructions", "unicode"],
            metadata={
                "tool": self.tool,
                "kind": kind,
                "code_points": [f"U+{cp:04X}" for cp in list(dict.fromkeys(cps))[:50]],
                "count": len(cps),
                "decoded": safe_excerpt(decoded, 500) if decoded else "",
                "signals": kinds,
            },
        )

    def _directives(self, hidden: Sequence[Hidden]) -> None:
        text = self.visible
        prose = _mask_fences(text)
        hidden_lines = {self.lines.line_of(h.start) for h in hidden}
        for block in _blocks(text):
            if self._counts.get("instruction-directive", 0) >= _MAX_PER_RULE:
                break  # past the cap nothing more is reported, so stop looking
            chunk = text[block.start : block.end]
            signals = [
                s
                for s in directive_signals(chunk, prose_text=prose[block.start : block.end])
                if s.kind != ENCODED
            ]
            deps = dependency_signals(chunk)
            marker = bool(_MARKER.search(chunk))
            first_line = self.lines.line_of(self._orig(block.start))
            last_line = self.lines.line_of(self._orig(max(block.start, block.end - 1)))
            unicode_hidden = any(first_line <= ln <= last_line for ln in hidden_lines)
            concealed = block.hidden or marker or unicode_hidden
            if signals:
                self._report_directive(block, chunk, signals, concealed, marker, unicode_hidden)
            for sig, label, source in deps:
                self._report_dependency(block, sig, label, source, concealed)

    def _report_directive(
        self,
        block: _Block,
        chunk: str,
        signals: list[Signal],
        concealed: bool,
        marker: bool,
        unicode_hidden: bool,
    ) -> None:
        kinds = sorted({s.kind for s in signals})
        sev = max(_BASE_SEVERITY[k] for k in kinds)
        evidence: list[str] = []
        if len(kinds) >= 2:
            sev = _bump(sev)
            evidence.append("more than one kind of directive in the same passage")
        if concealed:
            sev = _bump(sev)
            if block.hidden:
                evidence.append("inside an HTML comment, which does not render")
            if marker:
                evidence.append("wrapped in an instruction tag aimed at the model")
            if unicode_hidden:
                evidence.append("on lines that also carry hidden characters")
        conf = Confidence.HIGH if evidence else Confidence.MEDIUM
        first = min(signals, key=lambda s: s.start)
        start = self._orig(block.start + first.start)
        end = self._orig(block.start + first.end)
        sentences = list(dict.fromkeys(s.sentence for s in sorted(signals, key=lambda s: s.start)))
        quotes = "; ".join(f'"{safe_excerpt(q, 160)}"' for q in sentences[:3])
        desc = f"{self.intro} This passage {_tells(kinds)}: {quotes}."
        if evidence:
            desc += " Evidence that raises the severity: " + ", ".join(evidence) + "."
        self._add(
            "instruction-directive",
            f"{'+'.join(kinds)}:{start}",
            start,
            end,
            title=f"{self.name} {_tells(kinds) if len(kinds) == 1 else 'tells the assistant to act against the user'}",
            description=desc,
            severity=sev,
            confidence=conf,
            cwe=["CWE-1427", "CWE-506"],
            owasp_llm=LLM01,
            why="Instruction files are loaded into every assistant session without the user "
            "reading them again, so a planted directive acts with the developer's privileges "
            "and tools. Legitimate guidance tells the assistant what not to do; this text tells "
            "it to act against the user or around the project's safeguards.",
            attack="Land the directive through a pull request, a template, a vendored package "
            "or a compromised dependency that ships an instruction file.",
            impact="Secret theft, malicious code or commits, and disabled checks, done by the "
            "assistant on the developer's machine or in CI.",
            fix="Remove the passage and review the file's history. Keep instruction files "
            "under code owners, and treat changes to them like changes to CI configuration.",
            tags=["agent", "instructions"],
            metadata={
                "tool": self.tool,
                "signals": kinds,
                "in_html_comment": block.hidden,
                "excerpt": safe_excerpt(chunk, 300),
            },
        )

    def _report_dependency(
        self, block: _Block, sig: Signal, label: str, source: str, concealed: bool
    ) -> None:
        pinned = bool(_COMMIT_PIN.search(source))
        sev = Severity.LOW if pinned else Severity.MEDIUM
        if concealed:
            sev = _bump(sev)
        start = self._orig(block.start + sig.start)
        end = self._orig(block.start + sig.end)
        self._add(
            "instruction-untrusted-dependency",
            f"{label}:{source}",
            start,
            end,
            title=f"{self.name} tells the assistant to install packages from a {label}",
            description=(
                f"{self.intro} It tells the assistant to install from "
                f'{safe_excerpt(source, 160)} ({label}): "{safe_excerpt(sig.sentence, 200)}".'
                + (" The text is hidden from a reader." if concealed else "")
                + ("" if pinned else " The source is not pinned to a commit or hash.")
            ),
            severity=sev,
            confidence=Confidence.HIGH if concealed else Confidence.MEDIUM,
            cwe=["CWE-829", "CWE-1357"],
            owasp_llm=LLM03,
            why="A package source named in an instruction file is used by the assistant without "
            "the review a lockfile change gets. An extra index or a git URL can serve a lookalike "
            "of a well-known package (dependency confusion, a fork with a payload).",
            attack="Point the assistant at an index or repository the attacker controls; the "
            "next dependency it adds runs the attacker's install hooks.",
            impact="Code execution on developer machines and in CI, and a backdoored dependency "
            "in the product.",
            fix="Remove the source from the instructions. Configure approved indexes in the "
            "package manager's own config and pin dependencies by version and hash.",
            tags=["agent", "instructions", "supply-chain"],
            metadata={"tool": self.tool, "source_kind": label, "source": safe_excerpt(source, 200)},
        )

    def _blobs(self) -> None:
        for blob in find_blobs(self.text):
            line = self.lines.line_of(blob.start)
            block_text = self._block_around(blob.start)
            follow = any(s.kind == ENCODED for s in directive_signals(block_text))
            signals = directive_signals(blob.decoded) if blob.decoded else []
            signals += [s for s, _, _ in dependency_signals(blob.decoded)] if blob.decoded else []
            kinds = sorted({s.kind for s in signals if s.kind != ENCODED})
            if follow and kinds:
                sev, conf = Severity.HIGH, Confidence.MEDIUM
            elif follow or kinds:
                sev, conf = Severity.MEDIUM, Confidence.MEDIUM if kinds else Confidence.LOW
            elif blob.kind in ("prose", "script"):
                sev, conf = Severity.LOW, Confidence.LOW
            elif blob.kind == "data" or (blob.end - blob.start) >= 200:
                sev, conf = Severity.INFO, Confidence.LOW
            else:
                continue
            raw = self.text[blob.start : blob.end]
            shown = raw if len(raw) <= 40 else f"{raw[:24]}... ({len(raw)} characters)"
            parts = [
                f"{self.intro} Line {line} holds a {blob.encoding} blob of {len(raw)} characters"
            ]
            if blob.decoded:
                parts[0] += (
                    f' that decodes to {blob.kind} text: "{safe_excerpt(blob.decoded, 300)}".'
                )
            else:
                parts[0] += " that decodes to binary data."
            if follow:
                parts.append("The surrounding text asks for it to be decoded and followed.")
            if kinds:
                parts.append(f"The decoded text {_tells(kinds)}.")
            self._add(
                "instruction-encoded-blob",
                f"{blob.encoding}:{blob.start}",
                blob.start,
                blob.end,
                snippet=safe_excerpt(self.lines.line(line).replace(raw, shown), 240),
                title=f"Encoded blob in {self.name}"
                + (" with instructions in it" if kinds or follow else ""),
                description=" ".join(parts),
                severity=sev,
                confidence=conf,
                cwe=["CWE-1427", "CWE-506"],
                owasp_llm=LLM01,
                why="Models decode base64 and hex readily, so an encoded blob can carry "
                "instructions that no reviewer reads. Instruction files rarely need one.",
                attack="Hide a directive in an encoded 'config token' and ask the assistant to "
                "decode and apply it.",
                impact="Whatever the decoded text instructs, outside code review.",
                fix="Remove the blob or move the data to a file the assistant does not load as "
                "instructions; decode it and review what it says.",
                tags=["agent", "instructions", "encoded"],
                metadata={
                    "tool": self.tool,
                    "encoding": blob.encoding,
                    "decoded_kind": blob.kind,
                    "decoded": safe_excerpt(blob.decoded, 500) if blob.decoded else "",
                    "signals": kinds,
                    "decode_and_follow": follow,
                },
            )

    def _block_around(self, offset: int) -> str:
        lo = self.text.rfind("\n\n", 0, offset)
        hi = self.text.find("\n\n", offset)
        return self.text[(lo + 2 if lo >= 0 else 0) : (len(self.text) if hi < 0 else hi)]


def scan_instruction_file(path: str, tool: str, text: str, in_test: bool = False) -> list[Finding]:
    return InstructionCheck(path, tool, text, in_test).run()


# --- MCP server sources -------------------------------------------------------------------

_MCP_PY_ROOTS = ("mcp", "fastmcp")
_MCP_JS = re.compile(r"""["'](?:@modelcontextprotocol/sdk[^"']*|fastmcp|mcp-framework)["']""")
_PY_DESC_KEYS = {"description", "instructions"}
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")


@dataclass
class Description:
    text: str
    line: int
    end_line: int
    start_col: int
    end_col: int
    where: str  # "tool description", "parameter description", ...
    tool: str = ""


def mcp_source_candidate(rel_path: str, head: bytes) -> bool:
    """Cheap pre-check before parsing: a Python or JS/TS file that names an MCP SDK."""
    lower = rel_path.lower()
    if lower.endswith(".py"):
        return b"mcp" in head
    if lower.endswith(_JS_SUFFIXES) and not lower.endswith(".d.ts"):
        return b"modelcontextprotocol" in head or b"fastmcp" in head or b"mcp-framework" in head
    return False


def _py_string(node: Any, src: Any, consts: dict[str, Any], depth: int = 0) -> str | None:
    if node is None or depth > 8:
        return None
    t = node.type
    if t in ("string", "concatenated_string"):
        raw = src.text(node)
        try:
            value = ast.literal_eval(raw)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            parts = [src.text(c) for c in _walk_types(node, "string_content")]
            return "".join(parts) or None
        return value if isinstance(value, str) else None
    if t == "parenthesized_expression" and node.named_children:
        return _py_string(node.named_children[0], src, consts, depth + 1)
    if t == "binary_operator":
        left = _py_string(node.child_by_field_name("left"), src, consts, depth + 1)
        right = _py_string(node.child_by_field_name("right"), src, consts, depth + 1)
        if left is not None and right is not None:
            return left + right
        return None
    if t == "identifier":
        return _py_string(consts.get(src.text(node)), src, consts, depth + 1)
    return None


def _walk_types(root: Any, kind: str) -> Iterator[Any]:
    from nephilex.scanners.llm_ast import walk

    for n in walk(root):
        if n.type == kind:
            yield n


def _node_desc(node: Any, src: Any, text: str, where: str, tool: str = "") -> Description:
    from nephilex.scanners.llm_ast import end_line_of, line_of

    start, end = src.columns(node)
    return Description(text, line_of(node), end_line_of(node), start, end, where, tool)


def python_descriptions(data: bytes) -> list[Description] | None:
    """Model-facing descriptions in a Python MCP server, or None when not one."""
    from nephilex.scanners.llm_ast import Src, call_args, import_aliases, python_parser, walk

    parser = python_parser()
    if parser is None:
        return None
    root = parser.parse(data).root_node
    src = Src(data)
    aliases = import_aliases(root, src)
    if not any(v.split(".", 1)[0] in _MCP_PY_ROOTS for v in aliases.values()):
        return None
    consts: dict[str, Any] = {}
    for stmt in root.named_children:
        node = (
            stmt.named_children[0]
            if stmt.type == "expression_statement" and stmt.named_children
            else stmt
        )
        if node.type == "assignment":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                consts[src.text(left)] = right
    out: list[Description] = []
    seen: set[int] = set()

    def add(node: Any, where: str, tool: str = "") -> None:
        if node is None or node.start_byte in seen:
            return
        value = _py_string(node, src, consts)
        if value:
            seen.add(node.start_byte)
            out.append(_node_desc(node, src, value, where, tool))

    for node in walk(root):
        if node.type == "decorated_definition":
            fn = node.child_by_field_name("definition")
            if fn is None or fn.type != "function_definition":
                continue
            name_node = fn.child_by_field_name("name")
            fname = src.text(name_node) if name_node is not None else ""
            for dec in (c for c in node.children if c.type == "decorator"):
                expr = dec.named_children[0] if dec.named_children else None
                target = (
                    expr.child_by_field_name("function")
                    if expr is not None and expr.type == "call"
                    else expr
                )
                tname = src.text(target) if target is not None else ""
                kind = tname.rsplit(".", 1)[-1]
                if kind not in ("tool", "prompt", "resource", "list_tools"):
                    continue
                described = False
                if expr is not None and expr.type == "call":
                    _pos, kw = call_args(expr)
                    for key in _PY_DESC_KEYS:
                        if key in kw:
                            add(kw[key], f"{kind} description", fname)
                            described = True
                if not described and kind in ("tool", "prompt", "resource"):
                    body = fn.child_by_field_name("body")
                    first = (
                        body.named_children[0] if body is not None and body.named_children else None
                    )
                    if (
                        first is not None
                        and first.type == "expression_statement"
                        and first.named_children
                    ):
                        doc = first.named_children[0]
                        if doc.type == "string":
                            add(doc, f"{kind} description (docstring)", fname)
        elif node.type == "call":
            fn_node = node.child_by_field_name("function")
            callee = src.text(fn_node).rsplit(".", 1)[-1] if fn_node is not None else ""
            _pos, kw = call_args(node)
            for key in _PY_DESC_KEYS:
                if key in kw:
                    where = (
                        "parameter description"
                        if callee == "Field"
                        else f"{callee or 'call'} {key}"
                    )
                    add(kw[key], where)
        elif node.type == "pair":
            key = node.child_by_field_name("key")
            if key is not None and _py_string(key, src, consts) in _PY_DESC_KEYS:
                add(node.child_by_field_name("value"), "schema description")
    return out


def _js_unescape(body: str) -> str:
    def repl(m: re.Match[str]) -> str:
        e = m.group(1)
        if e.startswith("u{"):
            return chr(int(e[2:-1], 16))
        if e.startswith("u"):
            return chr(int(e[1:], 16))
        if e.startswith("x"):
            return chr(int(e[1:], 16))
        return {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}.get(
            e, e
        )

    return re.sub(
        r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", repl, body, flags=re.S
    )


def _js_string(node: Any, src: Any, consts: dict[str, Any], depth: int = 0) -> str | None:
    if node is None or depth > 8:
        return None
    t = node.type
    if t == "string":
        raw = src.text(node)
        return _js_unescape(raw[1:-1]) if len(raw) >= 2 else None
    if t == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            parts = []
            for c in node.children:
                if c.type == "template_substitution":
                    parts.append("${...}")
                elif c.type not in ("`",):
                    parts.append(src.text(c))
            return _js_unescape("".join(parts).strip("`"))
        return _js_unescape(src.text(node)[1:-1])
    if t == "parenthesized_expression" and node.named_children:
        return _js_string(node.named_children[0], src, consts, depth + 1)
    if t == "binary_expression":
        left = _js_string(node.child_by_field_name("left"), src, consts, depth + 1)
        right = _js_string(node.child_by_field_name("right"), src, consts, depth + 1)
        return left + right if left is not None and right is not None else None
    if t == "call_expression":
        # ["a", "b"].join(" ") is a common way to write a long description.
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "member_expression":
            obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
            if (
                obj is not None
                and obj.type == "array"
                and prop is not None
                and src.text(prop) == "join"
            ):
                items = [_js_string(c, src, consts, depth + 1) for c in obj.named_children]
                args = node.child_by_field_name("arguments")
                sep_node = (
                    args.named_children[0] if args is not None and args.named_children else None
                )
                sep = _js_string(sep_node, src, consts, depth + 1) if sep_node is not None else ","
                if all(i is not None for i in items) and sep is not None:
                    return sep.join(i for i in items if i is not None)
        return None
    if t == "identifier":
        return _js_string(consts.get(src.text(node)), src, consts, depth + 1)
    if (
        t in ("as_expression", "satisfies_expression", "non_null_expression")
        and node.named_children
    ):
        return _js_string(node.named_children[0], src, consts, depth + 1)
    return None


def js_descriptions(data: bytes, suffix: str) -> list[Description] | None:
    from nephilex.scanners.llm_ast import Src, js_parser, walk

    if not _MCP_JS.search(data.decode("utf-8", "ignore")):
        return None
    parser = js_parser(suffix)
    if parser is None:
        return None
    root = parser.parse(data).root_node
    src = Src(data)
    consts: dict[str, Any] = {}
    for node in walk(root):
        if node.type == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                consts.setdefault(src.text(name), value)
    out: list[Description] = []
    seen: set[int] = set()

    def add(node: Any, where: str, tool: str = "") -> None:
        if node is None or node.start_byte in seen:
            return
        value = _js_string(node, src, consts)
        if value:
            seen.add(node.start_byte)
            out.append(_node_desc(node, src, value, where, tool))

    for node in walk(root):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is None or fn.type != "member_expression" or args is None:
                continue
            prop = fn.child_by_field_name("property")
            pname = src.text(prop) if prop is not None else ""
            items = [c for c in args.named_children if c.type != "comment"]
            if pname in ("tool", "prompt") and len(items) >= 3:
                tool = _js_string(items[0], src, consts) or ""
                if items[1].type in (
                    "string",
                    "template_string",
                    "binary_expression",
                    "identifier",
                ):
                    add(items[1], f"{pname} description", tool)
            elif pname == "describe" and items:
                add(items[0], "parameter description")
        elif node.type == "pair":
            key = node.child_by_field_name("key")
            kname = src.text(key).strip("'\"") if key is not None else ""
            if kname in ("description", "instructions"):
                add(
                    node.child_by_field_name("value"),
                    "schema description" if kname == "description" else "server instructions",
                )
    return out


def scan_mcp_source(path: str, data: bytes, in_test: bool = False) -> list[Finding]:
    lower = path.lower()
    if lower.endswith(".py"):
        descs = python_descriptions(data)
    else:
        descs = js_descriptions(data, lower[lower.rfind(".") :])
    if not descs:
        return []
    src_lines = data.decode("utf-8", "replace").split("\n")
    findings: list[Finding] = []
    for d in descs:
        f = _poisoning(path, d, src_lines, in_test)
        if f is not None:
            findings.append(f)
        if len(findings) >= _MAX_PER_RULE:
            break
    return findings


def _poisoning(path: str, d: Description, src_lines: list[str], in_test: bool) -> Finding | None:
    hidden = find_hidden(d.text)
    visible = strip_hidden(d.text, hidden)
    signals = [s for s in directive_signals(visible, tool_description=True) if s.kind != ENCODED]
    decoded = "".join(h.decoded for h in hidden if h.kind != "bidi")
    payload = directive_signals(decoded, tool_description=True) if decoded else []
    if not hidden and not signals:
        return None
    marker = bool(_MARKER.search(visible))
    kinds = sorted({s.kind for s in signals + payload if s.kind != ENCODED})
    if hidden:
        sev = Severity.HIGH
        if payload or signals:
            sev = Severity.CRITICAL
    else:
        sev = max(_BASE_SEVERITY[k] for k in kinds)
        if len(kinds) >= 2:
            sev = _bump(sev)
        if marker:
            sev = _bump(sev)
    conf = (
        Confidence.HIGH
        if hidden or marker or len(kinds) >= 2 or EXFIL in kinds or SHADOW in kinds
        else Confidence.MEDIUM
    )
    # Report on the source line of the first signal when it can be found.
    line = d.line
    anchor = signals[0] if signals else None
    if anchor is not None:
        probe = anchor.text[:24]
        for k in range(d.line, d.end_line + 1):
            if probe and probe in _flat(src_lines[k - 1] if k - 1 < len(src_lines) else ""):
                line = k
                break
    elif hidden:
        for k in range(d.line, d.end_line + 1):
            text = src_lines[k - 1] if k - 1 < len(src_lines) else ""
            if find_hidden(text):
                line = k
                break
    parts = [
        f"The {d.where}"
        + (f" of tool '{d.tool}'" if d.tool else "")
        + " is text the model reads before it chooses a tool."
    ]
    if hidden:
        cps = [cp for h in hidden for cp in h.code_points]
        parts.append(f"It contains invisible characters: {_code_point_list(cps)}.")
        if decoded:
            parts.append(f'Hidden text, decoded: "{safe_excerpt(decoded, 300)}".')
    if kinds:
        parts.append(f"It {_tells(kinds, 'the model')}.")
    sentences = list(dict.fromkeys(s.sentence for s in signals))
    quotes = [f'"{safe_excerpt(q, 160)}"' for q in sentences[:3]]
    if quotes:
        parts.append("Matched: " + "; ".join(quotes) + ".")
    if marker:
        parts.append("The text is wrapped in an instruction tag aimed at the model.")
    subject = "MCP " + d.where.split(" (")[0]
    if not kinds:
        title = f"{subject} carries hidden characters"
    elif len(kinds) == 1:
        title = f"{subject} {_tells(kinds, 'the model')}"
    else:
        title = f"{subject} carries instructions aimed at the model"
    if hidden and kinds:
        title += " in hidden characters" if payload else " and hidden characters"
    return make_finding(
        rule="mcp-tool-poisoning",
        key=f"{d.where}:{d.line}:{d.start_col}",
        title=title,
        description=" ".join(parts),
        path=path,
        line=line,
        end_line=line if line != d.line else d.end_line,
        columns=(d.start_col, d.end_col) if line == d.line else None,
        snippet=safe_excerpt(src_lines[line - 1] if line - 1 < len(src_lines) else "", 240),
        severity=sev,
        confidence=conf,
        cwe=["CWE-1427", "CWE-506"] if not hidden else ["CWE-1427", "CWE-451"],
        owasp_llm=LLM01,
        why="MCP clients pass every tool's description and parameter descriptions to the "
        "model as trusted context, usually without showing them to the user. Instructions "
        "there steer the agent across every connected server (tool poisoning).",
        attack="Publish or update a server whose description tells the model to read local "
        "secrets and pass them in an argument, or to change how other tools behave.",
        impact="Theft of SSH keys, tokens and configuration, and redirected actions of other "
        "tools, without the user seeing why.",
        fix="Keep descriptions to what the tool does and its arguments. Remove the "
        "instructions, and review descriptions of third-party servers before connecting them.",
        tags=["mcp", "agent", "tool-poisoning"],
        in_test=in_test,
        scanner_name=SCANNER_NAME,
        references=[
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
        ],
        metadata={
            "where": d.where,
            "tool": d.tool,
            "signals": kinds,
            "hidden_code_points": [
                f"U+{cp:04X}" for cp in dict.fromkeys(cp for h in hidden for cp in h.code_points)
            ][:50],
            "decoded": safe_excerpt(decoded, 500) if decoded else "",
            "excerpt": safe_excerpt(d.text, 300),
        },
    )
