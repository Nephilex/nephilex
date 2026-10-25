"""Per-ecosystem version comparison for malicious-package version ranges.

The malicious-package intel records which versions of a package are actually
compromised (OSV ``affected[].versions`` exact lists and ``affected[].ranges``
with ``introduced`` / ``fixed`` events). Deciding whether an installed version
is one of them needs ecosystem-correct comparison:

* **PyPI** uses PEP 440, handled by ``packaging.version`` (already a transitive
  dependency through the toolchain). Non-conforming strings are compared with a
  lenient numeric fallback rather than being dropped.
* **npm** (and every other ecosystem here) uses SemVer. There is no vendored
  SemVer library, so this module implements the small, well-defined subset the
  intel needs: parse ``major.minor.patch`` with an optional prerelease, and
  compare two versions. A full SemVer range grammar (``^``/``~``/``||``) is not
  needed: the intel only ever carries exact versions and ``introduced``/``fixed``
  bounds, which is what OSV emits.

Everything here is pure and side-effect free, so it is cheap to call per package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- generic numeric fallback ---------------------------------------------
# Used when a string is not valid PEP 440 / SemVer. Compares the leading numeric
# dotted components; it is deliberately simple and only a backstop.
_NUM = re.compile(r"\d+")


def _loose_key(v: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-+]", v.strip())
    nums: list[int] = []
    for p in parts:
        m = _NUM.match(p)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums) or (0,)


# --- PyPI / PEP 440 --------------------------------------------------------
def _pep440_compare(a: str, b: str) -> int:
    """Return -1/0/1 for ``a`` vs ``b`` under PEP 440, with a numeric fallback."""
    try:
        from packaging.version import InvalidVersion, Version

        try:
            va, vb = Version(a), Version(b)
        except InvalidVersion:
            ka, kb = _loose_key(a), _loose_key(b)
            return (ka > kb) - (ka < kb)
        return (va > vb) - (va < vb)
    except ImportError:  # pragma: no cover - packaging ships with the toolchain
        ka, kb = _loose_key(a), _loose_key(b)
        return (ka > kb) - (ka < kb)


def _pep440_equal(a: str, b: str) -> bool:
    try:
        from packaging.version import InvalidVersion, Version

        try:
            return Version(a) == Version(b)
        except InvalidVersion:
            return _loose_key(a) == _loose_key(b)
    except ImportError:  # pragma: no cover
        return _loose_key(a) == _loose_key(b)


# --- SemVer (npm and the other ecosystems) ---------------------------------
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_parts(v: str) -> tuple[int, int, int, tuple[object, ...]] | None:
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4)
    # No prerelease sorts *after* any prerelease of the same core (SemVer §11).
    if pre is None:
        pre_key: tuple[object, ...] = (1,)
    else:
        ids: list[object] = []
        for ident in pre.split("."):
            if ident.isdigit():
                ids.append((0, int(ident)))  # numeric identifiers are lowest
            else:
                ids.append((1, ident))
        pre_key = (0, tuple(ids))
    return major, minor, patch, pre_key


def _semver_compare(a: str, b: str) -> int:
    pa, pb = _semver_parts(a), _semver_parts(b)
    if pa is None or pb is None:
        ka, kb = _loose_key(a), _loose_key(b)
        return (ka > kb) - (ka < kb)
    return (pa > pb) - (pa < pb)


def _semver_equal(a: str, b: str) -> bool:
    pa, pb = _semver_parts(a), _semver_parts(b)
    if pa is None or pb is None:
        return _loose_key(a) == _loose_key(b)
    return pa == pb


# --- public, ecosystem-aware API -------------------------------------------
def _is_pypi(ecosystem: str) -> bool:
    return ecosystem.lower() == "pypi"


def compare(ecosystem: str, a: str, b: str) -> int:
    """Return -1/0/1 for ``a`` vs ``b`` using the ecosystem's version grammar."""
    return _pep440_compare(a, b) if _is_pypi(ecosystem) else _semver_compare(a, b)


def equals(ecosystem: str, a: str, b: str) -> bool:
    """Whether two version strings denote the same release in this ecosystem."""
    return _pep440_equal(a, b) if _is_pypi(ecosystem) else _semver_equal(a, b)


def is_exact(ecosystem: str, version: str) -> bool:
    """Whether ``version`` is a single concrete release this ecosystem can compare.

    A range spec, a wildcard (``2.x``, ``*``), a dist-tag or any string the
    ecosystem's grammar does not accept as one version returns ``False`` so the
    caller treats the installed version as unconfirmed rather than guessing.
    """
    if not version:
        return False
    if _is_pypi(ecosystem):
        try:
            from packaging.version import InvalidVersion, Version

            try:
                Version(version)
                return True
            except InvalidVersion:
                return False
        except ImportError:  # pragma: no cover
            return bool(re.match(r"^\d+(\.\d+)*$", version.strip()))
    return _semver_parts(version) is not None


@dataclass(frozen=True)
class VersionRange:
    """A half-open ``[introduced, fixed)`` range, OSV's ECOSYSTEM/SEMVER shape.

    ``introduced`` ``None`` (or the OSV sentinel ``"0"``) means "from the first
    version"; ``fixed`` ``None`` means "with no known fix", i.e. open-ended. A
    version is in range when ``introduced <= v`` and (``fixed`` is None or
    ``v < fixed``).
    """

    introduced: str | None = None
    fixed: str | None = None

    def contains(self, ecosystem: str, version: str) -> bool:
        intro = self.introduced
        if intro is not None and intro != "0" and compare(ecosystem, version, intro) < 0:
            return False
        return self.fixed is None or compare(ecosystem, version, self.fixed) < 0
