"""PyPI names are compared after PEP 503 normalization.

PyPI treats `Evil_Pkg`, `evil.pkg` and `evil-pkg` as the same project, so a
malicious-package entry must match every spelling, and a spelling variant of a
popular package must not be reported as a typosquat of it.
"""

from __future__ import annotations

import json

import pytest

from nephilex.scanners import supply_chain
from nephilex.supply_chain import intel


def test_normalize_name():
    assert intel.normalize_name("PyPI", "Evil__Pkg.Name") == ("PyPI", "evil-pkg-name")
    assert intel.normalize_name("npm", "Evil_Pkg") == ("npm", "evil_pkg")


def test_feed_entries_are_normalized():
    parsed = intel._parse_feed_payload([{"ecosystem": "PyPI", "name": "Evil_Pkg"}])
    assert parsed == {("PyPI", "evil-pkg")}


def test_malicious_lookup_matches_every_pypi_spelling(monkeypatch):
    monkeypatch.setattr(
        intel,
        "load_malicious_packages",
        lambda **kw: frozenset({("PyPI", "evil-pkg"), ("npm", "evil-pkg")}),
    )
    for spelling in ("evil-pkg", "Evil_Pkg", "evil.pkg", "EVIL__PKG"):
        assert intel.is_malicious("PyPI", spelling), spelling
    assert not intel.is_malicious("npm", "evil_pkg")


def test_spelling_variant_is_not_a_typosquat(monkeypatch):
    monkeypatch.setattr(
        supply_chain, "_load_popular", lambda: {"PyPI": ["python-dateutil"], "npm": ["lodash"]}
    )
    assert supply_chain._typosquat_candidates("python_dateutil", "PyPI") == []
    assert supply_chain._typosquat_candidates("Python.DateUtil", "PyPI") == []
    assert supply_chain._typosquat_candidates("python-dateutll", "PyPI") == ["python-dateutil"]
    assert supply_chain._typosquat_candidates("lodahs", "npm") == []
    assert supply_chain._typosquat_candidates("lodas", "npm") == ["lodash"]


@pytest.mark.parametrize(
    ("name", "ecosystem"),
    [("preact", "npm"), ("gaxios", "npm"), ("vuex", "npm"), ("pipx", "PyPI"), ("pyaml", "PyPI")],
)
def test_popular_packages_next_to_a_popular_name_are_not_typosquats(name, ecosystem):
    # preact is one edit from react, but it is a widely used package itself.
    assert supply_chain._typosquat_candidates(name, ecosystem) == []


def test_a_real_typo_of_react_is_still_a_typosquat():
    assert supply_chain._typosquat_candidates("reactt", "npm") == ["react"]


def test_preact_in_a_lockfile_is_not_reported(tmp_path):
    from nephilex.core.config import Config
    from nephilex.core.plugin import ScannerContext
    from nephilex.core.project import Project

    lock = {"lockfileVersion": 3, "packages": {"node_modules/preact": {"version": "10.29.8"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    cfg = Config(scanner_options={"supply-chain": {"online_intel": False}})
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=cfg)
    assert [f.rule_id for f in supply_chain.SupplyChainScanner().scan(ctx)] == []


def test_levenshtein_is_shared():
    assert intel.levenshtein("kitten", "sitting") == 3
    assert intel.levenshtein("", "abc") == 3
