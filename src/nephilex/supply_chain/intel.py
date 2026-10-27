"""Malicious-package intelligence: bundled seed + optional online refresh."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path

from nephilex.supply_chain.versions import VersionRange, equals

log = logging.getLogger("nephilex.supply_chain.intel")

# Remote feeds refresh the bundled seed. None is published by default, so a
# scan makes no feed request unless one is configured: the URL listed here
# before (a ``nephilex-intel`` repository) never existed and returned 404 on
# every online scan.
#
# The OpenSSF malicious-packages repository has no aggregate file per ecosystem:
# ``osv/malicious/<ecosystem>/`` holds one OSV record per package (checked
# through the GitHub API on 2026-10-26), so the ``osv/malicious/npm.json`` URL
# listed here before never existed. Those records are served by the OSV API,
# which the dependency scanner queries for every pinned dependency, so known
# malware in any ecosystem is reported there (see ``osv.is_malware_record``).
#
# A team that keeps its own list can set NEPHILEX_INTEL_FEED to one or more
# comma-separated HTTPS URLs serving the bundled file's format.
_FEED_ENV = "NEPHILEX_INTEL_FEED"
_CACHE_TTL = 24 * 3600


def _configured_feeds() -> tuple[str, ...]:
    """HTTPS feed URLs from NEPHILEX_INTEL_FEED; other schemes are skipped."""
    urls = []
    for url in os.environ.get(_FEED_ENV, "").split(","):
        url = url.strip()
        if not url:
            continue
        if not url.lower().startswith("https://"):
            log.warning("%s: skipping %s, only https:// feeds are fetched", _FEED_ENV, url)
            continue
        urls.append(url)
    return tuple(urls)


def normalize_name(ecosystem: str, name: str) -> tuple[str, str]:
    """The ``(ecosystem, name)`` key used for every malicious-package lookup.

    PyPI treats runs of ``-``, ``_`` and ``.`` as equivalent and ignores case
    (PEP 503), so ``Evil_Pkg``, ``evil.pkg`` and ``evil-pkg`` are one package and
    must match the same intel entry. Other ecosystems are only lowercased.
    """
    if ecosystem.lower() == "pypi":
        return ecosystem, re.sub(r"[-_.]+", "-", name).lower()
    return ecosystem, name.lower()


@dataclass(frozen=True)
class MaliciousEntry:
    """What is known about a malicious package: its key and the affected versions.

    ``versions`` is an exact-match list (OSV ``affected[].versions``) and
    ``ranges`` is a list of ``[introduced, fixed)`` bounds (OSV
    ``affected[].ranges``). When BOTH are empty the entry carries no version
    information, which means *every* version matches: this is how the bundled
    name-only entries keep behaving exactly as before, and the safe default for
    any feed entry whose affected versions could not be parsed.
    """

    ecosystem: str
    name: str
    versions: frozenset[str] = frozenset()
    ranges: tuple[VersionRange, ...] = ()

    @property
    def has_version_info(self) -> bool:
        return bool(self.versions) or bool(self.ranges)

    def affects(self, version: str) -> bool:
        """Whether ``version`` is one of the compromised releases.

        With no version information every version is affected (name-only entry).
        """
        if not self.has_version_info:
            return True
        for v in self.versions:
            if equals(self.ecosystem, version, v):
                return True
        return any(r.contains(self.ecosystem, version) for r in self.ranges)

    def affected_description(self) -> str:
        """A short human description of which versions are affected, or ''."""
        parts: list[str] = []
        if self.versions:
            parts.extend(sorted(self.versions))
        for r in self.ranges:
            if r.introduced in (None, "0") and r.fixed:
                parts.append(f"< {r.fixed}")
            elif r.fixed:
                parts.append(f">= {r.introduced} and < {r.fixed}")
            elif r.introduced not in (None, "0"):
                parts.append(f">= {r.introduced}")
        return ", ".join(parts)

    def merge(self, other: MaliciousEntry) -> MaliciousEntry:
        """Combine two entries for the same key, unioning their version info.

        A name-only entry (no version info) is absorbing: unioning anything with
        "matches any version" still matches any version, so the result stays
        name-only. This keeps the safe default when one source is version-aware
        and another is not.
        """
        if not self.has_version_info or not other.has_version_info:
            return MaliciousEntry(self.ecosystem, self.name)
        return MaliciousEntry(
            self.ecosystem,
            self.name,
            self.versions | other.versions,
            tuple(dict.fromkeys(self.ranges + other.ranges)),
        )


@dataclass
class MaliciousIndex:
    """Malicious packages keyed by ``(ecosystem, name)`` with version info.

    ``names`` is the backward-compatible name-only view that
    :func:`load_malicious_packages` returns; ``entries`` carries the version
    detail used by :func:`malicious_match`.
    """

    entries: dict[tuple[str, str], MaliciousEntry] = field(default_factory=dict)

    def add(self, entry: MaliciousEntry) -> None:
        key = normalize_name(entry.ecosystem, entry.name)
        existing = self.entries.get(key)
        self.entries[key] = existing.merge(entry) if existing else entry

    def names(self) -> set[tuple[str, str]]:
        return set(self.entries)

    def update(self, other: MaliciousIndex) -> None:
        for entry in other.entries.values():
            self.add(entry)


def _bundled() -> MaliciousIndex:
    with (
        resources.files("nephilex.scanners.data")
        .joinpath("supply_chain.json")
        .open(encoding="utf-8") as fh
    ):
        data = json.load(fh)
    return _parse_feed_index(data.get("packages", []))


def _as_str_set(value: object) -> frozenset[str]:
    """Coerce an OSV/bundled ``versions`` list into a set of version strings."""
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(v) for v in value if isinstance(v, (str, int, float)) and str(v))


def _parse_ranges(value: object) -> tuple[VersionRange, ...]:
    """Parse OSV ``affected[].ranges`` (ECOSYSTEM/SEMVER events) into VersionRanges.

    Each range is a list of events; an ``introduced`` opens a half-open interval
    that the next ``fixed`` (or ``last_affected``) closes. Anything unrecognized
    is skipped rather than guessed, keeping the safe default.
    """
    if not isinstance(value, list):
        return ()
    out: list[VersionRange] = []
    for rng in value:
        if not isinstance(rng, dict):
            continue
        rtype = str(rng.get("type", "")).upper()
        if rtype and rtype not in ("ECOSYSTEM", "SEMVER"):
            continue  # GIT ranges carry commit hashes, not versions we can compare
        events = rng.get("events")
        if not isinstance(events, list):
            continue
        introduced: str | None = None
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if "introduced" in ev:
                introduced = str(ev["introduced"])
            elif "fixed" in ev:
                out.append(VersionRange(introduced, str(ev["fixed"])))
                introduced = None
            elif "last_affected" in ev:
                # Inclusive upper bound: treat it as its own exact-ish range by
                # leaving it open-ended from the last introduced point. The
                # scanner also exact-matches the version list, so this stays safe.
                out.append(VersionRange(introduced, None))
                introduced = None
        if introduced is not None:
            out.append(VersionRange(introduced, None))
    return tuple(out)


def _entry_from_dict(e: dict, *, eco: object, name: object) -> MaliciousEntry | None:
    if not eco or not name:
        return None
    return MaliciousEntry(
        str(eco),
        str(name),
        _as_str_set(e.get("versions")),
        _parse_ranges(e.get("ranges")),
    )


def _parse_feed_index(items: object) -> MaliciousIndex:
    """Parse a feed payload's items into a version-aware :class:`MaliciousIndex`.

    Handles both the bundled/cache shape (``{"ecosystem","name",versions?,ranges?}``)
    and the OSV/OSSF shape (``{"affected":[{"package":{...},"versions":[...],
    "ranges":[...]}]}``).
    """
    index = MaliciousIndex()
    if not isinstance(items, list):
        return index
    for e in items:
        if not isinstance(e, dict):
            continue
        affected = e.get("affected")
        if affected:
            for aff in affected if isinstance(affected, list) else []:
                if not isinstance(aff, dict):
                    continue
                pkg = aff.get("package") or {}
                if not isinstance(pkg, dict):
                    continue
                entry = _entry_from_dict(aff, eco=pkg.get("ecosystem"), name=pkg.get("name"))
                if entry is not None:
                    index.add(entry)
            continue
        entry = _entry_from_dict(e, eco=e.get("ecosystem"), name=e.get("name"))
        if entry is not None:
            index.add(entry)
    return index


def _parse_feed_payload(data: object) -> set[tuple[str, str]]:
    """Name-only view of a feed payload (kept for backward compatibility)."""
    if isinstance(data, dict):
        items = data.get("packages") or data.get("items") or []
    elif isinstance(data, list):
        items = data
    else:
        return set()
    return _parse_feed_index(items).names()


def _cache_path() -> Path:
    base = Path.home() / ".nephilex" / "cache"
    base.mkdir(parents=True, exist_ok=True)
    return base / "malicious-packages.json"


def _read_cache() -> MaliciousIndex | None:
    path = _cache_path()
    if not path.is_file():
        return None
    try:
        if time.time() - path.stat().st_mtime > _CACHE_TTL:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return _parse_feed_index(data.get("packages", []))
    except (OSError, ValueError, TypeError):
        return None


def _write_cache(index: MaliciousIndex) -> None:
    packages: list[dict] = []
    for (eco, _norm), entry in sorted(index.entries.items()):
        rec: dict = {"ecosystem": eco, "name": entry.name}
        if entry.versions:
            rec["versions"] = sorted(entry.versions)
        if entry.ranges:
            rec["ranges"] = [
                {
                    "type": "ECOSYSTEM",
                    "events": (
                        ([{"introduced": r.introduced or "0"}])
                        + ([{"fixed": r.fixed}] if r.fixed else [])
                    ),
                }
                for r in entry.ranges
            ]
        packages.append(rec)
    with contextlib.suppress(OSError):
        _cache_path().write_text(json.dumps({"packages": packages}, indent=2), encoding="utf-8")


def _fetch_remote(urls: tuple[str, ...] | str, timeout: float) -> MaliciousIndex | None:
    import httpx  # imported here: only an online fetch needs it, not every CLI start

    if isinstance(urls, str):
        urls = (urls,)
    merged = MaliciousIndex()
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url)
                resp.raise_for_status()
                payload = resp.json()
                items = (
                    (payload.get("packages") or payload.get("items") or [])
                    if isinstance(payload, dict)
                    else payload
                )
                merged.update(_parse_feed_index(items))
        except Exception as exc:
            log.debug("malicious-package feed fetch failed for %s: %s", url, exc)
    return merged if merged.entries else None


@lru_cache(maxsize=8)
def load_malicious_index(
    *, online: bool = True, feed_url: str | None = None, timeout: float = 10.0
) -> MaliciousIndex:
    """Version-aware malicious-package index (bundled + cache + optional remote)."""
    merged = MaliciousIndex()
    merged.update(_bundled())
    cached = _read_cache()
    if cached:
        merged.update(cached)
    urls = (feed_url,) if feed_url else _configured_feeds()
    if online and urls:
        remote = _fetch_remote(urls, timeout)
        if remote:
            merged.update(remote)
            _write_cache(merged)
    return merged


def load_malicious_packages(
    *, online: bool = True, feed_url: str | None = None, timeout: float = 10.0
) -> frozenset[tuple[str, str]]:
    """Return merged malicious-package name set (bundled + cache + optional remote).

    Name-only view kept for backward compatibility; use
    :func:`load_malicious_index` or :func:`malicious_match` when the installed
    version matters. Caching lives on :func:`load_malicious_index`; this function
    exposes a ``cache_clear`` that clears that shared cache so existing callers
    keep working.
    """
    return frozenset(
        load_malicious_index(online=online, feed_url=feed_url, timeout=timeout).names()
    )


# Keep the long-standing ``load_malicious_packages.cache_clear()`` API working by
# routing it to the index cache that now holds the data.
load_malicious_packages.cache_clear = load_malicious_index.cache_clear  # type: ignore[attr-defined]


def merge_intel(bundled_only: bool = False, **kwargs) -> frozenset[tuple[str, str]]:
    """Alias for :func:`load_malicious_packages` with explicit offline mode."""
    return load_malicious_packages(online=not bundled_only, **kwargs)


@dataclass(frozen=True)
class MaliciousMatch:
    """Result of checking one installed package against the intel.

    * ``matched``          - the name is on the malicious list at all.
    * ``affected``         - the installed version is a compromised one
                             (always ``True`` when ``version_known`` is ``False``
                             and the name matches, because we cannot clear it).
    * ``version_known``    - the installed version could be parsed/compared.
    * ``has_version_info`` - the intel knows which versions are affected.
    * ``affected_versions``- human text of the affected versions, or ''.
    """

    matched: bool
    affected: bool = False
    version_known: bool = False
    has_version_info: bool = False
    affected_versions: str = ""

    def __bool__(self) -> bool:
        return self.matched


_NO_MATCH = MaliciousMatch(matched=False)


def malicious_match(
    ecosystem: str, name: str, version: str | None = None, *, online: bool = True
) -> MaliciousMatch:
    """Check one package (and optionally its installed version) against the intel.

    When ``version`` is ``None`` or cannot be compared, a name match is still
    reported (``affected=True``) but ``version_known`` is ``False`` so callers
    can lower confidence and say the version was not confirmed. When the version
    is known and the intel carries affected versions, ``affected`` is ``True``
    only if the installed version is actually one of them.
    """
    key = normalize_name(ecosystem, name)
    entry = load_malicious_index(online=online).entries.get(key)
    if entry is None:
        return _NO_MATCH
    desc = entry.affected_description()
    if version is None:
        return MaliciousMatch(
            matched=True,
            affected=True,
            version_known=False,
            has_version_info=entry.has_version_info,
            affected_versions=desc,
        )
    return MaliciousMatch(
        matched=True,
        affected=entry.affects(version),
        version_known=True,
        has_version_info=entry.has_version_info,
        affected_versions=desc,
    )


def is_malicious(
    ecosystem: str, name: str, *, version: str | None = None, online: bool = True
) -> bool:
    """Whether a package (optionally at a specific version) is known malicious.

    Backward compatible: with no ``version`` this is a pure name lookup against
    :func:`load_malicious_packages`, exactly as before (so callers that only ask
    "is this name malicious", like the MCP package check, are unaffected). With a
    ``version`` it returns ``True`` only when that version is an affected one (or
    the intel has no version info for the name).
    """
    if version is None:
        key = normalize_name(ecosystem, name)
        return key in load_malicious_packages(online=online)
    return malicious_match(ecosystem, name, version, online=online).affected


# Popular package names used for typosquat / homoglyph detection (spec §7).
_POPULAR_PACKAGES = frozenset(
    {
        "lodash",
        "react",
        "express",
        "axios",
        "request",
        "webpack",
        "typescript",
        "eslint",
        "prettier",
        "moment",
        "async",
        "debug",
        "chalk",
        "commander",
        "dotenv",
        "uuid",
        "jsonwebtoken",
        "bcrypt",
        "mongoose",
        "sequelize",
        "django",
        "flask",
        "requests",
        "numpy",
        "pandas",
        "pytest",
        "setuptools",
    }
)


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two names (shared by both typosquat checks)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def typosquat_risk(name: str, *, popular: frozenset[str] | None = None) -> tuple[bool, str]:
    """Return (is_suspicious, matched_popular_name) for package typosquatting."""
    n = name.lower().strip()
    pool = popular or _POPULAR_PACKAGES
    if n in pool:
        return False, ""
    for pkg in pool:
        if abs(len(n) - len(pkg)) > 2:
            continue
        dist = levenshtein(n, pkg)
        if 0 < dist <= 2:
            return True, pkg
        if n.replace("-", "").replace("_", "") == pkg.replace("-", ""):
            return True, pkg
    return False, ""


def maintainer_anomaly(*, account_age_days: int | None, publish_count: int | None) -> bool:
    """Heuristic: brand-new maintainer with few publishes may indicate takeover."""
    if account_age_days is None or publish_count is None:
        return False
    return account_age_days < 30 and publish_count <= 2
