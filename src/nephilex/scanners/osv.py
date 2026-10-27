"""OSV (osv.dev) client for real, current vulnerability data.

The bundled advisory file is a small offline seed. This module queries the public
`OSV database <https://osv.dev>`_ for the project's actual dependencies, which
covers thousands of advisories across many ecosystems.

Design goals (this is security-critical plumbing, so correctness beats cleverness):

* **No silent gaps.** Every declared package is queried, requests are *batched*
  in chunks rather than truncated. A hard ceiling exists only as a runaway guard,
  and exceeding it is logged, never silent. A dropped dependency in a security
  scan reads as "you're covered" when you are not.
* **Resilient.** Transient failures (timeouts, 429, 5xx) are retried with
  exponential backoff before the caller falls back to the offline seed.
* **Fast on repeat scans.** Fetched advisory records are cached on disk (keyed by
  a hash of the vulnerability id, with a TTL), so re-scanning a large lock file
  does not re-hit the network and stays polite to the public API.
* **Private.** Only package **names and versions** are sent to OSV, never source.

When OSV is unreachable, :func:`query` raises :class:`OSVError` so the dependency
scanner can fall back to the bundled seed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import time
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from nephilex.core.models import Severity

log = logging.getLogger("nephilex.scanners.osv")

OSV_API = "https://api.osv.dev"

# OSV's querybatch accepts up to 1000 queries per request; chunk to stay within it.
# There is deliberately no ceiling on the number of packages: batching already
# bounds each request, and a cap let a lockfile padded with junk entries push
# real dependencies past the limit so they were never checked.
_BATCH_SIZE = 1000
# Cap concurrent record fetches so a large transitive tree stays polite to the API.
_MAX_FETCH_WORKERS = 8
# Retry policy for transient failures.
_MAX_RETRIES = 3
_BACKOFF_BASE = 0.5  # seconds; doubles each retry
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
# Cached advisory records are considered fresh for this long.
_CACHE_TTL = 24 * 3600
# Indirection so tests can stub out backoff sleeps.
_SLEEP = time.sleep

# OSV/GHSA qualitative severity -> Nephilex severity.
_SEVERITY_WORD = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


@dataclass
class OSVAdvisory:
    id: str
    summary: str
    severity: Severity = Severity.MEDIUM
    cve: str = ""
    fixed: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    affected_symbols: list[str] = field(default_factory=list)
    #: The record reports malware (a ``MAL-`` id or alias), not a vulnerability:
    #: there is no fixed version to upgrade to.
    malicious: bool = False
    aliases: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)


class OSVError(RuntimeError):
    pass


# --- on-disk cache ---------------------------------------------------------
def _cache_dir() -> Path:
    override = os.environ.get("NEPHILEX_CACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "nephilex"
    return base / "osv"


def _cache_file(cache_dir: Path, vuln_id: str) -> Path:
    # Hash the id for the filename: stable, and immune to path traversal from a
    # crafted advisory id (which is untrusted data from the API).
    digest = hashlib.sha256(vuln_id.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest}.json"


def _cache_get(vuln_id: str, cache_dir: Path) -> dict | None:
    try:
        blob = json.loads(_cache_file(cache_dir, vuln_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(blob, dict) or time.time() - float(blob.get("fetched", 0)) > _CACHE_TTL:
        return None
    vuln = blob.get("vuln")
    return vuln if isinstance(vuln, dict) else None


def _cache_put(vuln_id: str, vuln: dict, cache_dir: Path) -> None:
    try:  # cache is best-effort; a write failure must never fail a scan
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache_file(cache_dir, vuln_id).write_text(
            json.dumps({"fetched": time.time(), "vuln": vuln}), encoding="utf-8"
        )
    except OSError:
        pass


# --- HTTP with retry -------------------------------------------------------
def _request_with_retry(
    client: httpx.Client, method: str, url: str, **kwargs: object
) -> httpx.Response:
    """Issue a request, retrying transient failures with exponential backoff.

    Returns the last response on a retryable status after exhausting attempts (so
    the caller decides how to treat it); raises the underlying error only if no
    response was ever received.
    """
    delay = _BACKOFF_BASE
    last_exc: httpx.HTTPError | None = None
    last_resp: httpx.Response | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            resp = client.request(method, url, **kwargs)  # type: ignore[arg-type]
        except httpx.HTTPError as exc:
            last_exc = exc
        else:
            last_resp = resp
            if resp.status_code not in _RETRYABLE_STATUS:
                return resp
        if attempt < _MAX_RETRIES - 1:
            _SLEEP(delay)
            delay *= 2
    if last_resp is not None:
        return last_resp
    raise last_exc or OSVError(f"OSV request to {url} failed")


# --- public API ------------------------------------------------------------
def query(
    ecosystem: str,
    deps: Mapping[str, str] | Iterable[tuple[str, str]],
    *,
    timeout: float = 15.0,
    use_cache: bool = True,
    client: httpx.Client | None = None,
) -> dict[tuple[str, str], list[OSVAdvisory]]:
    """Return advisories per (package, version) for the given ecosystem.

    ``deps`` may be a ``{name: version}`` mapping (one version per package) or an
    iterable of ``(name, version)`` pairs. The pair form is what lets a package
    pinned at *two* versions in a lock tree be queried at both, rather than
    collapsing to a single version and silently missing the other. Duplicate
    pairs are de-duplicated while preserving order (so results stay deterministic).

    Raises OSVError on any network/HTTP problem so the caller can fall back to the
    offline seed. Never raises for "no vulnerabilities", that is an empty result.
    """
    raw = deps.items() if isinstance(deps, Mapping) else deps
    seen: set[tuple[str, str]] = set()
    items: list[tuple[str, str]] = []
    for pair in raw:
        if pair not in seen:
            seen.add(pair)
            items.append(pair)
    if not items:
        return {}

    own_client = client is None
    client = client or httpx.Client(timeout=timeout)
    per_pkg_ids: list[list[str]] = []
    id_set: set[str] = set()
    records: dict[str, OSVAdvisory] = {}
    skipped = 0
    try:
        # 1) Batched lookups across all packages (no silent truncation).
        for start in range(0, len(items), _BATCH_SIZE):
            chunk = items[start : start + _BATCH_SIZE]
            queries = [
                {"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk
            ]
            resp = _request_with_retry(
                client, "POST", f"{OSV_API}/v1/querybatch", json={"queries": queries}
            )
            resp.raise_for_status()
            for res in resp.json().get("results", []):
                ids = [v["id"] for v in (res.get("vulns") or [])]
                per_pkg_ids.append(ids)
                id_set.update(ids)

        # 2) Fetch each unique vuln once, cache-first, concurrently. Reassembled by
        # id below so output is deterministic regardless of completion order.
        cache_dir = _cache_dir()

        def _fetch(vid: str) -> tuple[str, OSVAdvisory | None]:
            if use_cache:
                cached = _cache_get(vid, cache_dir)
                if cached is not None:
                    return vid, _parse_vuln(cached)
            r = _request_with_retry(client, "GET", f"{OSV_API}/v1/vulns/{vid}")
            if r.status_code != 200:
                return vid, None
            data = r.json()
            if use_cache:
                _cache_put(vid, data, cache_dir)
            return vid, _parse_vuln(data)

        if id_set:
            workers = min(_MAX_FETCH_WORKERS, len(id_set))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for vid, adv in pool.map(_fetch, sorted(id_set)):
                    if adv is None:
                        skipped += 1
                    else:
                        records[vid] = adv
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise OSVError(f"OSV lookup failed: {exc}") from exc
    finally:
        if own_client:
            client.close()

    if skipped:
        log.warning(
            "OSV: %d advisory record(s) could not be fetched after %d "
            "attempts and were omitted from this scan.",
            skipped,
            _MAX_RETRIES,
        )

    out: dict[tuple[str, str], list[OSVAdvisory]] = {}
    for (name, version), ids in zip(items, per_pkg_ids, strict=False):
        advisories = [records[i] for i in ids if i in records]
        if advisories:
            out[(name, version)] = advisories
    return out


def _parse_vuln(vuln: dict, *, package: str = "") -> OSVAdvisory:
    vid = vuln.get("id", "")
    aliases = vuln.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), "")
    summary = vuln.get("summary") or (vuln.get("details", "")[:200]) or vid

    refs = [r.get("url", "") for r in (vuln.get("references") or []) if r.get("url")]
    if cve:
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve}")

    cwe = [
        c for c in (vuln.get("database_specific", {}).get("cwe_ids") or []) if isinstance(c, str)
    ]

    symbols: list[str] = []
    from nephilex.analysis.symbol_reachability import extract_osv_symbols

    symbols = extract_osv_symbols(vuln, package)
    malicious = is_malware_record(vuln)

    return OSVAdvisory(
        id=vid,
        summary=summary,
        severity=Severity.CRITICAL if malicious else _severity_of(vuln),
        cve=cve,
        fixed=None if malicious else _fixed_version(vuln),
        cwe=["CWE-506"] if malicious else (cwe or ["CWE-1104"]),
        references=refs[:5],
        affected_symbols=symbols,
        malicious=malicious,
        aliases=[a for a in aliases if isinstance(a, str)],
        affected_versions=_affected_versions(vuln),
    )


def is_malware_record(vuln: dict) -> bool:
    """Whether an OSV record reports a malicious package rather than a vulnerability.

    The OpenSSF malicious-packages records that OSV serves have ``MAL-`` ids
    (GitHub's malware advisories are published as aliases of them), and carry
    ``malicious-packages-origins`` in ``database_specific``.
    """
    ids = [vuln.get("id", ""), *(vuln.get("aliases") or [])]
    if any(isinstance(i, str) and i.upper().startswith("MAL-") for i in ids):
        return True
    specific = vuln.get("database_specific")
    if isinstance(specific, dict):
        if "malicious-packages-origins" in specific:
            return True
        kind = specific.get("type")
        if isinstance(kind, str) and kind.lower() == "malware":
            return True
    return False


def _affected_versions(vuln: dict) -> list[str]:
    out: list[str] = []
    for affected in vuln.get("affected", []) or []:
        if isinstance(affected, dict):
            out.extend(str(v) for v in affected.get("versions", []) or [] if isinstance(v, str))
    return out[:50]


def _severity_of(vuln: dict) -> Severity:
    word = (vuln.get("database_specific", {}) or {}).get("severity")
    if isinstance(word, str) and word.upper() in _SEVERITY_WORD:
        return _SEVERITY_WORD[word.upper()]
    # Fall back to a CVSS base score if present in the vector's severity list.
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score", "")
        band = _cvss_band(score)
        if band is not None:
            return band
    return Severity.MEDIUM


def _cvss_band(vector_or_score: str) -> Severity | None:
    """Map a CVSS base score to a band.

    Accepts either a bare number (``"9.8"``) or a full CVSS v3.x vector string
    (``"CVSS:3.1/AV:N/AC:L/..."``). OSV/GHSA advisories usually carry the vector,
    not the number, so parsing only bare floats silently defaulted every
    vector-only advisory to MEDIUM -- under-rating real 9.8s that teams gate on.
    """
    if not isinstance(vector_or_score, str):
        return None
    text = vector_or_score.strip()
    value: float | None = None
    if text.upper().startswith("CVSS:3"):
        value = _cvss3_base_score(text)
    else:
        try:
            value = float(text)
        except (TypeError, ValueError):
            value = None
    if value is None:
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return None


# CVSS v3.1 metric weights (spec section 7). PR depends on Scope, handled below.
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed


def _cvss3_roundup(value: float) -> float:
    """Official CVSS v3.1 roundup: ceil to one decimal place, avoiding fp error."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def _cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.x base score from a vector string, or None if malformed."""
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:  # skip the leading "CVSS:3.x"
        key, _, val = part.partition(":")
        if key and val:
            metrics[key.upper()] = val.upper()
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _CVSS3_PR_C if scope_changed else _CVSS3_PR_U
        av = _CVSS3_AV[metrics["AV"]]
        ac = _CVSS3_AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _CVSS3_UI[metrics["UI"]]
        conf = _CVSS3_CIA[metrics["C"]]
        integ = _CVSS3_CIA[metrics["I"]]
        avail = _CVSS3_CIA[metrics["A"]]
    except KeyError:
        return None  # missing/invalid metric -> let the caller fall back

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
    return _cvss3_roundup(min(raw, 10.0))


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None
