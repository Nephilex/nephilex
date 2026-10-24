#!/usr/bin/env python3
"""Score Nephilex's LLM and agent scanners on the labeled agent corpus.

The corpus (``corpus/manifest.json``) holds scenarios, each a vulnerable case
and a matching safe case: the same app done correctly. Every case is one file,
scanned on its own with only the ``llm`` and ``agent-config`` scanners.

Scoring, per split and overall:

* a vulnerable case is a **true positive** when at least one finding at or
  above LOW severity carries one of the case's ``expected_owasp`` ids, and a
  **false negative** otherwise (findings in another OWASP category are counted
  as off-target, not as a catch);
* a safe case with any finding at or above LOW is a **false positive** (one per
  case, however many findings it has);
* recall = TP / (TP + FN), precision = TP / (TP + FP).

The split is fixed by rule, decided before any detection rule was written for
this corpus: a scenario is held out when the SHA-256 of its id, read as an
integer, is divisible by 3. Both cases of a scenario land in the same split, so
the held-out split measures recall and false positives on code the rules were
not tuned against.

    python benchmarks/agent/run.py                 # dev and held-out summary
    python benchmarks/agent/run.py --details dev   # per-case results for dev
    python benchmarks/agent/run.py --only dev      # score the dev split alone
    python benchmarks/agent/run.py --json results/after.json
    python benchmarks/agent/run.py --category tool-poisoning   # one category only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
MANIFEST = CORPUS / "manifest.json"
SCANNERS = ("llm", "agent-config")
SPLITS = ("dev", "heldout")
ALLOWED_OWASP = {"LLM01", "LLM02", "LLM03", "LLM05", "LLM06", "LLM07"}


@dataclass(frozen=True)
class Case:
    scenario: str
    category: str
    language: str
    path: str
    vulnerable: bool
    expected_owasp: tuple[str, ...]
    cwe: tuple[str, ...]
    split: str


@dataclass
class CaseResult:
    case: Case
    #: (rule id, OWASP id, severity label, line) of every finding at or above LOW.
    findings: list[tuple[str, str, str, int | None]] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return any(f[1] in self.case.expected_owasp for f in self.findings)

    @property
    def outcome(self) -> str:
        if self.case.vulnerable:
            return "TP" if self.matched else "FN"
        return "FP" if self.findings else "TN"


def split_of(scenario_id: str) -> str:
    """The fixed split rule: SHA-256 of the scenario id divisible by 3 is held out."""
    digest = int(hashlib.sha256(scenario_id.encode("utf-8")).hexdigest(), 16)
    return "heldout" if digest % 3 == 0 else "dev"


def load_cases(manifest: Path = MANIFEST) -> list[Case]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    cases: list[Case] = []
    seen: set[str] = set()
    for sc in data["scenarios"]:
        sid = sc["id"]
        if sid in seen:
            raise ValueError(f"duplicate scenario id {sid!r}")
        seen.add(sid)
        kinds = sorted(c["vulnerable"] for c in sc["cases"])
        if kinds != [False, True]:
            raise ValueError(f"scenario {sid!r} needs one vulnerable and one safe case")
        for c in sc["cases"]:
            owasp = tuple(c["expected_owasp"])
            bad = set(owasp) - ALLOWED_OWASP
            if not owasp or bad:
                raise ValueError(f"{c['path']}: unexpected OWASP ids {sorted(bad) or owasp}")
            cases.append(
                Case(
                    scenario=sid,
                    category=sc["category"],
                    language=sc["language"],
                    path=c["path"],
                    vulnerable=bool(c["vulnerable"]),
                    expected_owasp=owasp,
                    cwe=tuple(c.get("cwe", ())),
                    split=split_of(sid),
                )
            )
    return cases


def _owasp_id(value: str) -> str:
    return value.split(":", 1)[0]


def scan_case(case: Case, corpus: Path = CORPUS) -> CaseResult:
    """Scan one case directory in isolation with the LLM and agent scanners."""
    from nephilex.core.config import AIConfig, Config
    from nephilex.core.engine import ScanEngine
    from nephilex.core.models import Severity
    from nephilex.core.project import Project

    src = corpus / case.path
    tmp = Path(tempfile.mkdtemp(prefix="nephilex-agent-bench-"))
    try:
        work = tmp / "app"
        shutil.copytree(src, work)
        cfg = Config(
            scanners=list(SCANNERS),
            cache=False,
            parallel=False,
            ai=AIConfig(enabled=False),
            audit_log=False,
        )
        result = ScanEngine(cfg).scan(Project.from_path(work))
        out = CaseResult(case)
        for f in result.sorted_findings():
            if f.severity < Severity.LOW or f.scanner not in SCANNERS:
                continue
            owasp = _owasp_id(str(f.metadata.get("owasp_llm") or (f.owasp or [""])[0]))
            out.findings.append((f.rule_id, owasp, f.severity.label, f.location.start_line))
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def score(results: Iterable[CaseResult]) -> dict[str, Any]:
    tally = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}
    for r in results:
        tally[r.outcome] += 1
    tp, fn, fp = tally["TP"], tally["FN"], tally["FP"]
    return {
        "vulnerable": tp + fn,
        "safe": fp + tally["TN"],
        **tally,
        "recall": _rate(tp, tp + fn),
        "precision": _rate(tp, tp + fp),
    }


def summarize(results: Sequence[CaseResult]) -> dict[str, Any]:
    report: dict[str, Any] = {"splits": {}, "by_category": {}}
    for split in SPLITS:
        report["splits"][split] = score(r for r in results if r.case.split == split)
    report["splits"]["all"] = score(results)
    for cat in sorted({r.case.category for r in results}):
        report["by_category"][cat] = {
            split: score(r for r in results if r.case.category == cat and r.case.split == split)
            for split in SPLITS
        }
    report["cases"] = [
        {
            "path": r.case.path,
            "split": r.case.split,
            "vulnerable": r.case.vulnerable,
            "expected_owasp": list(r.case.expected_owasp),
            "outcome": r.outcome,
            "findings": [
                {"rule": rule, "owasp": ow, "severity": sev, "line": line}
                for rule, ow, sev, line in r.findings
            ],
        }
        for r in results
    ]
    return report


def _fmt(v: float | None) -> str:
    return "  n/a" if v is None else f"{v:6.1%}"


def print_summary(report: dict[str, Any]) -> None:
    print("Nephilex, labeled LLM and agent corpus")
    print("=" * 66)
    print(
        f"{'split':<9} {'vuln':>5} {'safe':>5} {'TP':>4} {'FN':>4} {'FP':>4} {'recall':>8} "
        f"{'precision':>10}"
    )
    print("-" * 66)
    for split in (*SPLITS, "all"):
        s = report["splits"][split]
        if not s["vulnerable"] and not s["safe"]:
            continue
        print(
            f"{split:<9} {s['vulnerable']:>5} {s['safe']:>5} {s['TP']:>4} {s['FN']:>4} "
            f"{s['FP']:>4} {_fmt(s['recall']):>8} {_fmt(s['precision']):>10}"
        )


def print_details(results: Sequence[CaseResult], split: str) -> None:
    print(f"\nPer-case results, {split} split")
    print("-" * 66)
    for r in results:
        if r.case.split != split:
            continue
        found = ", ".join(f"{rule}[{ow}]@{line}" for rule, ow, _sev, line in r.findings) or "-"
        print(f"{r.outcome}  {r.case.path:<55} {found}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--json", type=Path, help="write the full report to this path")
    parser.add_argument(
        "--details",
        choices=SPLITS,
        action="append",
        default=[],
        help="print per-case outcomes for a split (repeatable)",
    )
    parser.add_argument(
        "--only",
        choices=SPLITS,
        help="scan and score one split only (rule work uses --only dev, so the "
        "held-out split stays unseen until the final run)",
    )
    parser.add_argument(
        "--category",
        action="append",
        default=[],
        help="scan and score only scenarios of this category (repeatable)",
    )
    args = parser.parse_args(argv)

    from nephilex.plugins import register_builtins

    register_builtins()
    cases = [
        c
        for c in load_cases()
        if args.only in (None, c.split) and (not args.category or c.category in args.category)
    ]
    if not cases:
        parser.error("no cases match the selected split and categories")
    results = [scan_case(c) for c in cases]
    report = summarize(results)
    print_summary(report)
    for split in args.details:
        print_details(results, split)
    if args.json:
        path = args.json if args.json.is_absolute() else HERE / args.json
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"\nWrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
