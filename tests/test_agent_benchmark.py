"""Tests for the labeled LLM and agent benchmark runner (benchmarks/agent/run.py).

The runner decides every published number for the agent corpus, so the split
rule, the manifest checks and the scoring arithmetic are pinned here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from benchmarks.agent import run

# --- split rule ----------------------------------------------------------------


def test_split_rule_is_sha256_mod_3() -> None:
    for sid in ("a", "ipi-x", "chain-y", "tb-z", "out-1", "agency-2"):
        expected = int(hashlib.sha256(sid.encode()).hexdigest(), 16) % 3 == 0
        assert (run.split_of(sid) == "heldout") is expected


def test_split_is_stable_across_calls() -> None:
    assert run.split_of("same-id") == run.split_of("same-id")


# --- manifest ------------------------------------------------------------------


def _manifest(tmp_path: Path, scenarios: list[dict]) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "scenarios": scenarios}), encoding="utf-8")
    return path


def _scenario(sid: str, *, owasp: str = "LLM05", safe: bool = True) -> dict:
    cases = [{"path": f"{sid}/vulnerable", "vulnerable": True, "expected_owasp": [owasp]}]
    if safe:
        cases.append({"path": f"{sid}/safe", "vulnerable": False, "expected_owasp": [owasp]})
    return {"id": sid, "category": "output-handling", "language": "python", "cases": cases}


def test_load_cases_assigns_both_cases_of_a_scenario_to_one_split(tmp_path: Path) -> None:
    cases = run.load_cases(_manifest(tmp_path, [_scenario("s1"), _scenario("s2")]))
    assert len(cases) == 4
    for sid in ("s1", "s2"):
        assert len({c.split for c in cases if c.scenario == sid}) == 1


@pytest.mark.parametrize(
    "scenarios",
    [
        [_scenario("dup"), _scenario("dup")],
        [_scenario("lonely", safe=False)],
        [_scenario("bad-id", owasp="LLM11")],
        [_scenario("old-id", owasp="LLM02:2023")],
    ],
)
def test_load_cases_rejects_bad_manifests(tmp_path: Path, scenarios: list[dict]) -> None:
    with pytest.raises(ValueError):
        run.load_cases(_manifest(tmp_path, scenarios))


def test_committed_corpus_is_well_formed() -> None:
    cases = run.load_cases()
    assert len(cases) >= 60
    assert sum(c.vulnerable for c in cases) == sum(not c.vulnerable for c in cases)
    assert {c.split for c in cases} == {"dev", "heldout"}
    for c in cases:
        # One file per case, at the path its tool reads it from (instruction
        # files such as .cursor/rules/style.mdc sit in subdirectories).
        files = [p for p in (run.CORPUS / c.path).rglob("*") if p.is_file()]
        assert len(files) == 1, c.path


# --- scoring -------------------------------------------------------------------


def _case(vulnerable: bool, owasp: tuple[str, ...] = ("LLM01",)) -> run.Case:
    return run.Case("s", "c", "python", "s/x", vulnerable, owasp, (), "dev")


def test_outcomes_match_on_expected_owasp_only() -> None:
    hit = run.CaseResult(_case(True), [("llm.r", "LLM01", "High", 3)])
    off = run.CaseResult(_case(True), [("llm.r", "LLM06", "High", 3)])
    miss = run.CaseResult(_case(True))
    fp = run.CaseResult(_case(False), [("llm.r", "LLM06", "Low", 1), ("llm.q", "LLM01", "Low", 2)])
    tn = run.CaseResult(_case(False))
    assert [r.outcome for r in (hit, off, miss, fp, tn)] == ["TP", "FN", "FN", "FP", "TN"]


def test_score_counts_one_false_positive_per_safe_case() -> None:
    results = [
        run.CaseResult(_case(True), [("llm.r", "LLM01", "High", 3)]),
        run.CaseResult(_case(True)),
        run.CaseResult(_case(False), [("a", "LLM01", "Low", 1), ("b", "LLM01", "Low", 2)]),
        run.CaseResult(_case(False)),
    ]
    s = run.score(results)
    assert (s["TP"], s["FN"], s["FP"], s["TN"]) == (1, 1, 1, 1)
    assert s["recall"] == 0.5
    assert s["precision"] == 0.5


def test_score_leaves_undefined_rates_as_none() -> None:
    s = run.score([run.CaseResult(_case(False))])
    assert s["recall"] is None
    assert s["precision"] is None


# --- end to end on a two-case corpus --------------------------------------------


def test_scan_case_end_to_end(tmp_path: Path) -> None:
    pytest.importorskip("tree_sitter_python")
    from nephilex.plugins import register_builtins

    register_builtins()
    vuln = tmp_path / "s" / "vulnerable"
    safe = tmp_path / "s" / "safe"
    vuln.mkdir(parents=True)
    safe.mkdir(parents=True)
    head = (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def calc(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[{'role': 'user', "
        "'content': q}])\n"
        "    out = r.choices[0].message.content\n"
    )
    (vuln / "app.py").write_text(head + "    return eval(out)\n", encoding="utf-8")
    (safe / "app.py").write_text(head + "    return float(out)\n", encoding="utf-8")
    v = run.scan_case(
        run.Case("s", "c", "python", "s/vulnerable", True, ("LLM05",), (), "dev"), tmp_path
    )
    s = run.scan_case(
        run.Case("s", "c", "python", "s/safe", False, ("LLM05",), (), "dev"), tmp_path
    )
    assert v.outcome == "TP"
    assert s.outcome == "TN"
