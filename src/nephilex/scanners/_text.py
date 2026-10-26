"""Shared line handling and regex fragments for the line-based scanners.

Scanned repositories are untrusted, and Python's ``re`` cannot be interrupted
once a match starts. Every line-based scanner therefore feeds its regexes
through :func:`iter_scan_lines`, which bounds the amount of text a single
``search`` call sees. A line longer than ``max_len`` is not skipped (that would
let an attacker hide a payload by padding the line); it is split into
overlapping windows of at most ``max_len`` characters, each reported under the
original line number.

Patterns used here must also be written so a single search is close to linear
in the window size: no nested or adjacent overlapping quantifiers, and no
``.*`` with DOTALL across a whole file.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence

#: Longest text a single regex search is run on. Longer lines are windowed.
MAX_SCAN_LINE = 2000
#: Overlap between consecutive windows of a long line, so a construct that
#: straddles a window boundary is still seen whole by one of them.
WINDOW_OVERLAP = 256

#: Remote content piped straight into a shell (``curl ... | sh``). One
#: definition shared by the malware, cicd, iac and lang-sast scanners.
#: At least one argument (a URL, a variable, flags) must sit between the
#: download command and the pipe: a real fetch always has one, while prose
#: that merely names the pattern ("avoid curl | bash") does not.
#: Linear: ``\s+`` and ``[^\s|]`` cannot match the same character, and
#: ``[^\n|]*`` stops at the first pipe. Each sudo flag (``-E``, ``--preserve-env``)
#: is a run of visible ASCII (``[!-~]``) followed by spaces or tabs. The two
#: classes are disjoint by construction, so the repeated group cannot split one
#: input two ways; ``\S``/``\s`` are also disjoint in Python, but static ReDoS
#: checks that model them loosely (control characters in both) report
#: exponential backtracking there. Flags with control characters are not real.
CURL_PIPE_SHELL = (
    r"\b(?:curl|wget|fetch)\s+[^\s|][^\n|]*\|\s*"
    r"(?:sudo[ \t]+(?:-[!-~]+[ \t]+)*)?(?:ba|z)?sh\b"
)
CURL_PIPE_SHELL_RE = re.compile(CURL_PIPE_SHELL, re.IGNORECASE)

#: (host, path prefix) of widely documented installer scripts that are meant to
#: be piped into a shell (uv, rustup, nvm, Homebrew, bun, deno, pnpm, ...).
KNOWN_INSTALLERS: tuple[tuple[str, str], ...] = (
    ("astral.sh", "/"),  # uv and ruff, install.sh and install.ps1
    ("sh.rustup.rs", "/"),
    ("win.rustup.rs", "/"),
    ("static.rust-lang.org", "/rustup/"),
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),
    ("raw.githubusercontent.com", "/homebrew/install/"),
    ("bun.sh", "/install"),
    ("bun.com", "/install"),
    ("deno.land", "/install"),
    ("deno.land", "/x/install/"),
    ("dl.deno.land", "/"),
    ("get.pnpm.io", "/"),
    ("install.python-poetry.org", "/"),
    ("pyenv.run", "/"),
    ("raw.githubusercontent.com", "/pyenv/pyenv-installer/"),
    ("get.sdkman.io", "/"),
    ("get.docker.com", "/"),
    ("deb.nodesource.com", "/setup_"),
    ("rpm.nodesource.com", "/setup_"),
    ("sdk.cloud.google.com", "/"),
    ("pixi.sh", "/install."),
    ("mise.run", "/"),
    ("starship.rs", "/install.sh"),
    ("get.scoop.sh", "/"),
    ("community.chocolatey.org", "/install.ps1"),
)
#: URLs inside a command, and their parts.
URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|ftp)://[^\s|'\"`)<>]+")
_URL_PARTS = re.compile(r"(?i)^(https?|ftp)://(?:[^/@\s]+@)?([^/:?#\s]+)(?::\d+)?([^?#\s]*)")
_IPV4 = re.compile(r"^\d+(?:\.\d+){3}$")
#: A scheme-less host argument (``iwr -useb get.scoop.sh | iex``).
_BARE_HOST = re.compile(r"(?i)(?<![\w./$-])((?:[a-z0-9-]+\.)+[a-z]{2,})(/[^\s|'\"`)<>]*)?")


def is_known_installer(url: str) -> bool:
    """An HTTPS URL (or bare host) of a well-known installer script."""
    m = _URL_PARTS.match(url)
    if m is None:
        bare = _BARE_HOST.fullmatch(url)
        if bare is None:
            return False
        host, path = bare.group(1).lower(), (bare.group(2) or "/").lower()
    else:
        if m.group(1).lower() != "https":
            return False
        host, path = m.group(2).lower(), (m.group(3) or "/").lower()
    return any(host == h and path.startswith(p) for h, p in KNOWN_INSTALLERS)


def remote_script_source(command: str) -> str:
    """Where a download-and-run command gets its script from.

    ``"known"``: only well-known installers; ``"https"``: fixed HTTPS hosts;
    ``"other"``: plain HTTP, an IP address, a variable or an unknown host;
    ``"none"``: no URL, variable or host at all (prose such as "curl ... | sh").
    """
    urls = URL_IN_TEXT.findall(command)
    if not urls:
        hosts = [m.group(0) for m in _BARE_HOST.finditer(command)]
        if hosts and all(is_known_installer(h) for h in hosts):
            return "known"
        if hosts or "$" in command or "`" in command or "%" in command:
            return "other"
        return "none"
    if all(is_known_installer(u) for u in urls):
        return "known"
    for u in urls:
        m = _URL_PARTS.match(u)
        if m is None or m.group(1).lower() != "https" or _IPV4.match(m.group(2)) or "$" in u:
            return "other"
    return "https"


def line_windows(line: str, max_len: int = MAX_SCAN_LINE) -> list[str]:
    """Return ``line`` itself, or overlapping windows of it if it is too long."""
    if len(line) <= max_len:
        return [line]
    step = max(1, max_len - WINDOW_OVERLAP)
    out: list[str] = []
    start = 0
    while True:
        out.append(line[start : start + max_len])
        if start + max_len >= len(line):
            return out
        start += step


def search_line(
    pattern: re.Pattern[str], line: str, max_len: int = MAX_SCAN_LINE
) -> re.Match[str] | None:
    """First match of ``pattern`` in ``line``, searching at most ``max_len`` at a time.

    The match's ``.string`` is the window it was found in, which is the useful
    part to show as a snippet when the line is very long.
    """
    for window in line_windows(line, max_len):
        m = pattern.search(window)
        if m:
            return m
    return None


def iter_scan_windows(
    text: str | Sequence[str], max_len: int = MAX_SCAN_LINE
) -> Iterator[tuple[int, int, str]]:
    """Like :func:`iter_scan_lines`, plus each segment's offset in its line.

    ``(lineno, offset, segment)``: a match at ``m.start()`` in ``segment`` sits
    at column ``offset + m.start() + 1`` (1-based) of line ``lineno``.
    """
    lines = text.splitlines() if isinstance(text, str) else text
    step = max(1, max_len - WINDOW_OVERLAP)
    for lineno, line in enumerate(lines, start=1):
        if len(line) <= max_len:
            yield lineno, 0, line
        else:
            for i, window in enumerate(line_windows(line, max_len)):
                yield lineno, i * step, window


def match_columns(m: re.Match[str], offset: int = 0) -> tuple[int, int]:
    """1-based ``(start_column, end_column)`` of a match, end exclusive (SARIF)."""
    return offset + m.start() + 1, offset + max(m.end(), m.start() + 1) + 1


def snippet_line(line: str, limit: int = 240) -> str:
    """A source line for ``Location.snippet``: indentation kept, line ending dropped."""
    return line.rstrip("\r\n")[:limit]


def iter_scan_lines(
    text: str | Sequence[str], max_len: int = MAX_SCAN_LINE
) -> Iterator[tuple[int, str]]:
    """Yield ``(lineno, segment)`` pairs with every segment at most ``max_len``.

    ``text`` is either the file content or its already-split lines. Normal lines
    are yielded once; an over-long line is yielded as several overlapping
    windows that share its line number, so callers that report one finding per
    rule and line should de-duplicate on ``(rule, lineno)``.
    """
    lines = text.splitlines() if isinstance(text, str) else text
    for lineno, line in enumerate(lines, start=1):
        if len(line) <= max_len:
            yield lineno, line
        else:
            for window in line_windows(line, max_len):
                yield lineno, window
