"""What a regular-expression allowlist check clears (nephilex.scanners._regexguard)."""

from __future__ import annotations

import re

import pytest

from nephilex.scanners._regexguard import allowed_chars, cleared_cwes


@pytest.mark.parametrize(
    ("pattern", "kind"),
    [
        ("[a-z]+", "match"),  # no end anchor: "abc<script>" matches
        ("[a-z]+$", "search"),  # no start anchor: anything before the letters
        ("^.+$", "fullmatch"),  # any character
        ("^[^<>]+$", "fullmatch"),  # a negated class: quotes, slashes, ...
        ("^[\x00-\uffff]+$", "fullmatch"),  # too wide to enumerate
        ("(?m)^[a-z]+$", "match"),  # per line: "abc\n<script>" matches
        ("^(", "fullmatch"),  # not a valid pattern
    ],
)
def test_untrusted_patterns_clear_nothing(pattern, kind):
    assert cleared_cwes(pattern, kind) == frozenset()


def test_enumeration_clears_every_injection_class():
    cleared = cleared_cwes("^(asc|desc|name|created)$", "fullmatch")
    for cwe in ("CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-90", "CWE-643", "CWE-95", "CWE-918"):
        assert cwe in cleared


def test_dot_and_dash_keep_path_and_sql_open():
    cleared = cleared_cwes("^[a-zA-Z0-9 _.\-]+$", "fullmatch")
    assert {"CWE-79", "CWE-78", "CWE-90", "CWE-501"} <= cleared
    assert "CWE-22" not in cleared  # ".." is allowed
    assert "CWE-89" not in cleared  # space and "-" (comments, OR clauses)


def test_dollar_with_match_allows_a_trailing_newline():
    assert "\n" in (allowed_chars("^[a-z]+$", "match") or ())
    assert "CWE-78" not in cleared_cwes("^[a-z]+$", "match")
    assert "CWE-78" in cleared_cwes("^[a-z]+\Z", "match")
    assert "CWE-78" in cleared_cwes("^[a-z]+$", "fullmatch")


def test_ignorecase_adds_the_other_case():
    chars = allowed_chars("^[a-z]+$", "fullmatch", re.IGNORECASE) or frozenset()
    assert "A" in chars and "a" in chars
