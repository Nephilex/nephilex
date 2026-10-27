"""``nephilex_check_package``: is this dependency safe to add?

An AI assistant that is about to add a dependency asks three questions here:

1. Is the package known to be malicious? (bundled malicious-package intel,
   refreshed from the online feeds unless the server is offline)
2. Is the name a likely typosquat of a popular package?
3. Does the requested version have known vulnerabilities? (OSV, only when a
   version is given)

It also asks the package registry whether the name exists at all. A name
that does not exist is often one the model invented (a "hallucinated"
package, which an attacker can register later). That lookup only runs for
registries Nephilex knows how to ask (npm, PyPI, crates.io); for any other
ecosystem, or when the lookup fails, the answer is ``unknown``, never a guess.

Network use: OSV, the registry lookup and any intel feed set in
``NEPHILEX_INTEL_FEED`` all use the network. Set ``NEPHILEX_MCP_OFFLINE=1`` to keep the server offline; the bundled
intel and typosquat checks still run and the rest report ``unknown``.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import httpx

OFFLINE_ENV = "NEPHILEX_MCP_OFFLINE"
_REGISTRY_TIMEOUT = 8.0
_OSV_TIMEOUT = 15.0
_INTEL_TIMEOUT = 8.0

# OSV ecosystem names, keyed by the spellings an agent is likely to use.
_ECOSYSTEMS = {
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "rust": "crates.io",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "java": "Maven",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
}

# A conservative package-name charset covering npm (scoped), PyPI, crates,
# Go module paths, Maven group:artifact, gems, NuGet and Packagist vendor/name.
# Anything else is refused before it reaches a URL or a lookup.
_NAME = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,213}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")


def offline() -> bool:
    return os.environ.get(OFFLINE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def normalize_ecosystem(value: str) -> str:
    key = value.strip().lower()
    if key in _ECOSYSTEMS:
        return _ECOSYSTEMS[key]
    choices = ", ".join(sorted(set(_ECOSYSTEMS.values())))
    raise ValueError(f"unknown ecosystem {value!r} (choose from: {choices})")


def registry_url(ecosystem: str, name: str) -> str | None:
    """The metadata URL whose 404 means "no such package", if Nephilex knows one."""
    if ecosystem == "npm":
        # Scoped names keep the @ and encode the slash, as the registry expects.
        return "https://registry.npmjs.org/" + quote(name, safe="@")
    if ecosystem == "PyPI":
        return f"https://pypi.org/pypi/{quote(name, safe='')}/json"
    if ecosystem == "crates.io":
        return f"https://crates.io/api/v1/crates/{quote(name, safe='')}"
    return None


def _registry_client() -> httpx.Client:
    """The HTTP client for registry lookups (a seam for tests)."""
    return httpx.Client(
        timeout=_REGISTRY_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": "nephilex (package existence check)"},
    )


def registry_exists(ecosystem: str, name: str) -> tuple[bool | None, str]:
    """``(exists, how)``: True/False from the registry, None when unknown."""
    url = registry_url(ecosystem, name)
    if url is None:
        return None, f"no registry lookup for {ecosystem}"
    if offline():
        return None, f"offline ({OFFLINE_ENV} is set)"
    try:
        with _registry_client() as http:
            resp = http.get(url)
    except httpx.HTTPError as exc:
        return None, f"registry lookup failed: {exc.__class__.__name__}"
    if resp.status_code == 200:
        return True, url
    if resp.status_code == 404:
        return False, url
    return None, f"registry answered HTTP {resp.status_code}"


def _typosquats(ecosystem: str, name: str) -> list[str]:
    from nephilex.scanners.supply_chain import _typosquat_candidates
    from nephilex.supply_chain.intel import typosquat_risk

    hits = list(_typosquat_candidates(name, ecosystem))
    if ecosystem in ("npm", "PyPI"):
        suspicious, popular = typosquat_risk(name)
        if suspicious and popular not in hits:
            hits.append(popular)
    return sorted(set(hits))


def _known_vulns(ecosystem: str, name: str, version: str | None) -> dict[str, Any]:
    if not version:
        return {"status": "not_checked", "reason": "pass a version to look up advisories"}
    if offline():
        return {"status": "unknown", "reason": f"offline ({OFFLINE_ENV} is set)"}
    from nephilex.scanners import osv

    try:
        found = osv.query(ecosystem, {name: version}, timeout=_OSV_TIMEOUT)
    except osv.OSVError as exc:
        return {"status": "unknown", "reason": str(exc)}
    advisories = found.get((name, version), [])
    return {
        "status": "vulnerable" if advisories else "none_known",
        "advisories": [
            {
                "id": a.id,
                "cve": a.cve,
                "severity": a.severity.name.lower(),
                "summary": a.summary,
                "fixed_in": a.fixed,
            }
            for a in advisories
        ],
    }


def check_package(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run every package check and return one structured verdict."""
    from nephilex.supply_chain.intel import is_malicious

    eco_raw = arguments.get("ecosystem")
    name = arguments.get("name")
    version = arguments.get("version")
    if not isinstance(eco_raw, str) or not eco_raw.strip():
        raise ValueError("'ecosystem' is required (for example npm or PyPI)")
    if not isinstance(name, str) or not _NAME.match(name.strip()):
        raise ValueError("'name' must be a package name")
    if version is not None and (not isinstance(version, str) or not _VERSION.match(version)):
        raise ValueError("'version' must be a plain version string such as 1.2.3")
    ecosystem = normalize_ecosystem(eco_raw)
    name = name.strip()

    malicious = is_malicious(ecosystem, name, online=not offline())
    squats = _typosquats(ecosystem, name)
    exists, how = registry_exists(ecosystem, name)
    vulns = _known_vulns(ecosystem, name, version)

    if exists is True:
        existence = {"status": "exists", "source": how}
    elif exists is False:
        existence = {
            "status": "not_found",
            "source": how,
            "note": "No such package on the registry. The name may be hallucinated; "
            "an attacker can register it later, so do not install it.",
        }
    else:
        existence = {"status": "unknown", "reason": how}

    if malicious:
        verdict = "malicious"
    elif exists is False:
        verdict = "possibly_hallucinated"
    elif vulns["status"] == "vulnerable":
        verdict = "vulnerable"
    elif squats:
        verdict = "suspicious"
    elif exists is None or vulns["status"] == "unknown":
        verdict = "unknown"
    else:
        verdict = "no_known_issues"

    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "verdict": verdict,
        "malicious": {
            "known_malicious": malicious,
            "source": "bundled intel"
            + ("" if offline() else ", refreshed from the online feeds when reachable"),
        },
        "typosquat": {"suspicious": bool(squats), "resembles": squats},
        "registry": existence,
        "vulnerabilities": vulns,
        "network": not offline(),
    }
