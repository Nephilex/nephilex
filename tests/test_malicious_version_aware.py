"""Version-aware malicious-package matching.

A package name on the malicious-package list is only malicious at the versions
that were actually compromised. Flagging a clean, pinned version (coa 2.0.2,
before the Nov 2021 npm compromise) as "known malicious" is a false positive, so
the check compares the installed version against the affected set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners.supply_chain import SupplyChainScanner
from nephilex.supply_chain import intel
from nephilex.supply_chain.intel import (
    MaliciousEntry,
    _parse_feed_index,
    is_malicious,
    malicious_match,
)
from nephilex.supply_chain.versions import VersionRange, compare, equals


def _scan_malicious(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    return [
        f for f in SupplyChainScanner().scan(ctx) if f.rule_id == "supply-chain.known-malicious"
    ]


def _malicious_findings(tmp_path: Path, deps: dict[str, str]):
    return _scan_malicious(tmp_path, {"package.json": json.dumps({"dependencies": deps})})


def _is_unconfirmed(f) -> bool:
    return "unconfirmed" in f.title.lower()


# --- the coa regression ----------------------------------------------------
def test_coa_clean_version_is_not_flagged():
    # 2.0.2 predates the compromise (affected set starts at 2.0.3).
    assert malicious_match("npm", "coa", "2.0.2", online=False).affected is False
    assert is_malicious("npm", "coa", version="2.0.2", online=False) is False


def test_coa_affected_versions_are_flagged():
    for v in ("2.0.3", "2.1.1", "2.1.3"):
        assert malicious_match("npm", "coa", v, online=False).affected is True, v
        assert is_malicious("npm", "coa", version=v, online=False) is True, v


def test_coa_after_fixed_range_is_not_flagged():
    # 2.2.0 and 2.1.0 / 2.1.2 are not in the published affected set.
    for v in ("2.1.0", "2.1.2", "2.2.0"):
        assert malicious_match("npm", "coa", v, online=False).affected is False, v


def test_scanner_does_not_flag_clean_coa(tmp_path: Path):
    assert _malicious_findings(tmp_path, {"coa": "2.0.2"}) == []


def test_scanner_flags_affected_coa(tmp_path: Path):
    findings = _malicious_findings(tmp_path, {"coa": "2.0.3"})
    assert len(findings) == 1
    f = findings[0]
    assert "2.0.3" in f.title
    assert f.severity.name == "CRITICAL"
    assert f.confidence.name == "HIGH"
    assert "2.0.3" in f.description  # affected versions named


# --- name-only entries keep matching every version -------------------------
def test_name_only_entry_flags_any_version(tmp_path: Path):
    # flatmap-stream is a bundled name-only entry: every version is malicious.
    assert is_malicious("npm", "flatmap-stream", version="0.1.0", online=False) is True
    assert is_malicious("npm", "flatmap-stream", version="99.0.0", online=False) is True
    findings = _malicious_findings(tmp_path, {"flatmap-stream": "0.1.0"})
    assert len(findings) == 1
    assert findings[0].severity.name == "CRITICAL"


# --- unknown / unpinned versions still flag, marked unconfirmed -------------
def test_unpinned_version_still_flags_but_unconfirmed(tmp_path: Path):
    # A wildcard spec (2.x) is not a single confirmable version; the name still
    # matches, so the finding stands but is marked version-unconfirmed.
    findings = _malicious_findings(tmp_path, {"coa": "2.x"})
    assert len(findings) == 1
    f = findings[0]
    assert "unconfirmed" in f.title.lower()
    assert f.confidence.name == "LOW"
    assert f.metadata["version_confirmed"] is False
    assert "could not be confirmed" in f.description


def test_malicious_match_unknown_version_is_unconfirmed():
    m = malicious_match("npm", "coa", None, online=False)
    assert m.matched is True
    assert m.affected is True  # cannot clear it
    assert m.version_known is False
    assert m.has_version_info is True


@pytest.mark.parametrize(
    "spec", ["^2.0.0", "~2.0.3", ">=2.0.0", "2.x", "*", "1 - 2", ">=1 <2", "latest"]
)
def test_npm_manifest_range_spec_is_unconfirmed_not_dropped(tmp_path: Path, spec: str):
    # collect_packages strips the operator (^2.0.0 -> 2.0.0) or drops the spec
    # entirely (*), which previously made a malicious range spec look like a
    # clean concrete version and silently disappear. It must stay reported, as
    # version-unconfirmed at low confidence.
    findings = _malicious_findings(tmp_path, {"coa": spec})
    assert len(findings) == 1, spec
    f = findings[0]
    assert _is_unconfirmed(f), spec
    assert f.confidence.name == "LOW", spec
    assert f.metadata["version_confirmed"] is False, spec


def test_npm_manifest_exact_pin_is_version_aware(tmp_path: Path):
    # A true exact manifest pin (no operator) is a confirmable version, so the
    # version-aware decision applies: 2.0.2 clean, 2.0.3 malicious.
    assert _malicious_findings(tmp_path, {"coa": "2.0.2"}) == []


def test_npm_lockfile_pin_clean_version_stays_clean(tmp_path: Path):
    # A lockfile pin of the clean 2.0.2 is a real installed version and must not
    # be flagged, even though the name is on the malicious list.
    lock = json.dumps({"packages": {"node_modules/coa": {"version": "2.0.2"}}})
    assert _scan_malicious(tmp_path, {"package-lock.json": lock}) == []


def test_npm_lockfile_pin_affected_version_is_critical(tmp_path: Path):
    lock = json.dumps({"packages": {"node_modules/coa": {"version": "2.0.3"}}})
    findings = _scan_malicious(tmp_path, {"package-lock.json": lock})
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.name == "CRITICAL"
    assert not _is_unconfirmed(f)


def test_npm_range_manifest_defers_to_lockfile_pin(tmp_path: Path):
    # A ^2.0.0 range in package.json alongside a lockfile pin: the lockfile is
    # authoritative, so a clean locked 2.0.2 produces no finding, and an
    # affected locked 2.0.3 produces exactly one confirmed Critical finding (not
    # a duplicate unconfirmed one from the range spec).
    files_clean = {
        "package.json": json.dumps({"dependencies": {"coa": "^2.0.0"}}),
        "package-lock.json": json.dumps({"packages": {"node_modules/coa": {"version": "2.0.2"}}}),
    }
    assert _scan_malicious(tmp_path, files_clean) == []


def test_npm_range_manifest_with_affected_lockfile_pin_reports_once(tmp_path: Path):
    files = {
        "package.json": json.dumps({"dependencies": {"coa": "^2.0.0"}}),
        "package-lock.json": json.dumps({"packages": {"node_modules/coa": {"version": "2.0.3"}}}),
    }
    findings = _scan_malicious(tmp_path, files)
    assert len(findings) == 1
    assert not _is_unconfirmed(findings[0])
    assert findings[0].severity.name == "CRITICAL"


def test_name_only_entry_flags_range_spec_as_confirmed(tmp_path: Path):
    # A name-only entry affects every version, so even a range/wildcard spec is a
    # confirmed hit, not merely unconfirmed.
    findings = _malicious_findings(tmp_path, {"flatmap-stream": "*"})
    assert len(findings) == 1
    assert not _is_unconfirmed(findings[0])
    assert findings[0].severity.name == "CRITICAL"


# --- PyPI PEP 440 range matching and normalization -------------------------
def test_pypi_pep440_range_matching():
    entry = MaliciousEntry("PyPI", "evil-pkg", ranges=(VersionRange("1.0.0", "1.3.0"),))
    assert entry.affects("1.0.0") is True
    assert entry.affects("1.2.5") is True
    assert entry.affects("1.3.0") is False  # fixed is exclusive
    assert entry.affects("0.9.0") is False
    # PEP 440 pre-releases compare correctly.
    assert entry.affects("1.2.0rc1") is True


def test_pypi_name_normalization_still_matches():
    idx = _parse_feed_index([{"ecosystem": "PyPI", "name": "Evil_Pkg"}])
    entry = idx.entries.get(("PyPI", "evil-pkg"))
    assert entry is not None
    # Every PEP 503 spelling resolves to the same entry (name-only -> any version).
    for spelling in ("evil-pkg", "Evil_Pkg", "evil.pkg", "EVIL__PKG"):
        assert is_malicious_against(idx, "PyPI", spelling, "1.0.0") is True


def is_malicious_against(idx, eco, name, version):
    key = intel.normalize_name(eco, name)
    entry = idx.entries.get(key)
    return entry is not None and entry.affects(version)


# --- feed parsing: affected[].ranges and affected[].versions ---------------
def test_feed_with_ranges_is_parsed():
    data = [
        {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "evil-pkg"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "2.0.3"}, {"fixed": "2.2.0"}],
                        }
                    ],
                }
            ]
        }
    ]
    idx = _parse_feed_index(data)
    entry = idx.entries.get(("npm", "evil-pkg"))
    assert entry is not None
    assert entry.ranges == (VersionRange("2.0.3", "2.2.0"),)
    assert entry.affects("2.1.0") is True
    assert entry.affects("2.2.0") is False
    assert entry.affects("2.0.2") is False


def test_feed_with_exact_versions_is_parsed():
    data = [
        {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "coa"},
                    "versions": ["2.0.3", "2.1.1"],
                }
            ]
        }
    ]
    idx = _parse_feed_index(data)
    entry = idx.entries.get(("npm", "coa"))
    assert entry is not None
    assert entry.versions == frozenset({"2.0.3", "2.1.1"})
    assert entry.affects("2.0.3") is True
    assert entry.affects("2.0.2") is False


def test_version_only_feed_entry_merges_to_name_only_on_conflict():
    # A name-only source union a version-aware source stays name-only (safe).
    idx = _parse_feed_index(
        [
            {"ecosystem": "npm", "name": "coa"},
            {"ecosystem": "npm", "name": "coa", "versions": ["2.0.3"]},
        ]
    )
    entry = idx.entries.get(("npm", "coa"))
    assert entry.has_version_info is False
    assert entry.affects("2.0.2") is True  # name-only wins -> any version


# --- comparison primitives -------------------------------------------------
def test_semver_and_pep440_compare():
    assert compare("npm", "2.0.2", "2.0.3") < 0
    assert compare("npm", "2.10.0", "2.9.0") > 0  # numeric, not lexical
    assert equals("npm", "v1.2.3", "1.2.3") is True
    assert compare("PyPI", "1.0.0", "1.0.0.post1") < 0
    assert equals("PyPI", "1.0", "1.0.0") is True
