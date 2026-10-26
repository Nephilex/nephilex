"""Supply-chain risk scanner: malicious packages, typosquats, suspicious scripts.

This is the foundation of Nephilex's supply-chain engine. It does not replace CVE
lookup (see :mod:`nephilex.scanners.dependencies`); it adds intelligence about
*malicious* and *suspicious* packages independent of published advisories.

Checks:

* **Known malicious packages** - bundled seed list (OSV/GitHub advisory sourced).
* **Typosquatting** - edit distance <= 1 from a popular package in the same ecosystem.
* **Suspicious npm lifecycle scripts**: ``preinstall`` / ``postinstall`` with shell
  or network patterns in ``package.json``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import iter_scan_windows, match_columns
from nephilex.scanners.dependencies import _PARSERS, _loads, collect_packages
from nephilex.supply_chain.intel import (
    MaliciousMatch,
    levenshtein,
    load_malicious_packages,
    malicious_match,
    normalize_name,
)
from nephilex.supply_chain.scripts import LIFECYCLE_HOOKS, SUSPICIOUS_INSTALL_SCRIPT
from nephilex.supply_chain.versions import is_exact


@lru_cache(maxsize=1)
def _load_supply_chain_data() -> dict:
    with (
        resources.files("nephilex.scanners.data")
        .joinpath("supply_chain.json")
        .open(encoding="utf-8") as fh
    ):
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _load_popular() -> dict:
    return _load_supply_chain_data().get("popular", {})


@lru_cache(maxsize=8)
def _established(ecosystem: str) -> frozenset[str]:
    """Normalized names that are real, widely used packages in their own right.

    The popular list plus well-known packages one edit away from a popular name
    (``preact`` next to ``react``, ``pipx`` next to ``pip``). A package on this
    list is never reported as a typosquat of its neighbour.
    """
    data = _load_supply_chain_data()
    names = [*data.get("popular", {}).get(ecosystem, [])]
    names += data.get("popular_neighbours", {}).get(ecosystem, [])
    return frozenset(normalize_name(ecosystem, n)[1] for n in names)


def _typosquat_candidates(name: str, ecosystem: str) -> list[str]:
    popular = _load_popular().get(ecosystem, [])
    hits: list[str] = []
    # Compare normalized names, so a PyPI spelling variant of a popular package
    # (python_dateutil for python-dateutil) is not mistaken for a typosquat.
    _, norm = normalize_name(ecosystem, name)
    if norm in _established(ecosystem):
        return hits
    for pkg in popular:
        _, other = normalize_name(ecosystem, pkg)
        if norm == other:
            continue
        if levenshtein(norm, other) <= 1:
            hits.append(pkg)
    return hits


def _known_malicious(
    ecosystem: str, name: str, version: str, *, online: bool = True
) -> MaliciousMatch:
    """Version-aware malicious check for one installed package."""
    return malicious_match(ecosystem, name, version or None, online=online)


def _npm_spec_is_exact_pin(spec: str) -> bool:
    """Whether an npm ``package.json`` dependency spec pins one exact version.

    A manifest range (``^2.0.0``, ``~2.0.3``, ``>=2.0.0``, ``2.x``, ``*``,
    ``1 - 2``, ``>=1 <2``, ``latest``, a git/url/file spec) is NOT an exact pin:
    the resolved version is unknown without a lockfile, so a malicious-name match
    on it must be reported as version-unconfirmed, never dropped as "clean". Only
    a bare concrete SemVer such as ``2.0.0`` or ``=2.0.0`` is an exact pin.
    """
    s = spec.strip()
    if s.startswith("="):  # npm treats a leading = as an exact pin
        s = s[1:].strip()
    return is_exact("npm", s)


def _npm_manifest_specs(project) -> dict[tuple[str, str], str]:
    """Map ``(rel_path, normalized npm name)`` to the raw ``package.json`` spec.

    Unlike ``collect_packages``, this keeps the operator (``^``, ``~``, ``*``,
    ...) so the scanner can tell a range spec from an exact pin, and it keeps
    specs ``collect_packages`` drops entirely (``*``, ``latest``, git/url specs)
    so a malicious dependency pinned to a non-numeric range is still seen.
    """
    out: dict[tuple[str, str], str] = {}
    for f in project.files_matching("package.json"):
        data = _loads(f.text())
        if not isinstance(data, dict):
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(name, str) or not isinstance(spec, str):
                    continue
                _, norm = normalize_name("npm", name)
                # First section wins, matching collect_packages' first-seen order.
                out.setdefault((f.rel_path, norm), spec)
    return out


def _hook_position(f, hook: str) -> tuple[int, int, int] | None:
    """``(line, start_column, end_column)`` of the ``"hook":`` key in a package.json."""
    key = re.compile(rf'"{re.escape(hook)}"\s*:')
    for lineno, offset, seg in iter_scan_windows(f.lines()):
        m = key.search(seg)
        if m:
            return (lineno, *match_columns(m, offset))
    return None


def _scan_npm_scripts(project, counter: int) -> Iterable[Finding]:
    for f in project.files_matching("package.json"):
        data = _loads(f.text())
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            continue
        for hook in LIFECYCLE_HOOKS:
            body = scripts.get(hook)
            if not isinstance(body, str) or not SUSPICIOUS_INSTALL_SCRIPT.search(body):
                continue
            counter += 1
            pos = _hook_position(f, hook)
            yield Finding(
                id=f"supply-chain:npm-script:{counter}",
                rule_id="supply-chain.npm-lifecycle-script",
                scanner="supply-chain",
                title=f"Suspicious npm {hook} script",
                description=(
                    f"The `{hook}` script in package.json contains patterns associated "
                    f"with shell execution, downloads, or credential access."
                ),
                # The line number lets the engine merge this with the malware
                # scanner's finding for the same script (same file, line, CWE).
                location=Location(
                    path=f.rel_path,
                    start_line=pos[0] if pos else None,
                    end_line=pos[0] if pos else None,
                    start_column=pos[1] if pos else None,
                    end_column=pos[2] if pos else None,
                    snippet=body[:200],
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-506"],
                owasp=["A06:2021-Vulnerable and Outdated Components"],
                why_vulnerable=(
                    "Lifecycle scripts run automatically on install without user "
                    "confirmation, a common supply-chain attack vector."
                ),
                attacker_perspective=(
                    "A compromised or malicious package can execute arbitrary commands "
                    "during `npm install` via lifecycle hooks."
                ),
                business_impact=(
                    "Install-time script execution can exfiltrate credentials, plant "
                    "backdoors, or compromise developer machines and CI runners."
                ),
                remediation=Remediation(
                    summary=f"Review the `{hook}` script; remove or pin trusted sources.",
                    guidance=(
                        "Prefer lockfiles, verify package provenance, and use "
                        "`npm ci --ignore-scripts` in CI until scripts are audited."
                    ),
                ),
                tags=["supply-chain", "npm", hook],
                metadata={"hook": hook},
            )


@scanner
class SupplyChainScanner(Scanner):
    name = "supply-chain"
    category = "supply-chain"
    description = "Flags known malicious packages, typosquats, and suspicious install scripts."

    def applies_to(self, project) -> bool:
        # File presence only: parsing every manifest here ran untrusted input
        # through the parsers before the scan (and outside its error handling).
        return bool(project.files_matching(*_PARSERS))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        online_intel = bool(opts.get("online_intel", True))
        # Warm intel cache once per scan (bundled + optional remote).
        load_malicious_packages(online=online_intel)

        counter = 0
        seen: set[tuple[str, str, str]] = set()

        # Raw npm manifest specs so a range (``^2.0.0``) is told apart from an
        # exact pin (``2.0.0``). ``collect_packages`` strips the operator, which
        # would make a malicious range spec look like a clean concrete version.
        npm_specs = _npm_manifest_specs(ctx.project)
        packages = collect_packages(ctx.project)
        # npm names that have at least one exact version somewhere (a lockfile
        # pin, or an exact manifest pin). For such a name, a manifest *range*
        # spec is ignored: the exact pin is the resolved, authoritative version,
        # so a clean locked version stays clean and is never reported twice.
        npm_exact_names: set[str] = set()
        for eco, p, name, _v in packages:
            if eco != "npm":
                continue
            _, nrm = normalize_name(eco, name)
            s = npm_specs.get((p, nrm))
            if s is None or _npm_spec_is_exact_pin(s):
                npm_exact_names.add(nrm)
        # Normalized npm names a malicious check already covered in the main loop
        # (either reported, or cleared because an exact pin was out of range), so
        # the manifest-range pass below does not re-flag the same dependency.
        npm_malicious_seen: set[str] = set()

        for ecosystem, path, pkg, version in packages:
            key = (ecosystem, pkg.lower(), path)
            if key in seen:
                continue
            seen.add(key)

            # An npm manifest range spec has no confirmable installed version,
            # even though collect_packages handed us the operator-stripped number.
            _, norm = normalize_name(ecosystem, pkg)
            spec = npm_specs.get((path, norm)) if ecosystem == "npm" else None
            is_range = spec is not None and not _npm_spec_is_exact_pin(spec)
            if is_range and norm in npm_exact_names:
                # A lockfile/exact pin for the same package is authoritative; let
                # that entry decide, so a range spec does not double-report.
                continue
            version_known = (
                _npm_spec_is_exact_pin(spec) if spec is not None else is_exact(ecosystem, version)
            )
            check_version = version if version_known else None
            match = _known_malicious(ecosystem, pkg, check_version or "", online=online_intel)
            if match.matched:
                if ecosystem == "npm":
                    npm_malicious_seen.add(norm)
                finding = self._malicious_finding(
                    match, counter + 1, ecosystem, path, pkg, version, version_known
                )
                if finding is not None:
                    counter += 1
                    yield finding
                    continue
                # Name matches but this pinned, confirmable version is not an
                # affected one (e.g. coa 2.0.2): not malicious, fall through so a
                # typosquat check can still run on the name.

            typos = _typosquat_candidates(pkg, ecosystem)
            if typos:
                counter += 1
                yield Finding(
                    id=f"supply-chain:typosquat:{counter}",
                    rule_id="supply-chain.typosquat",
                    scanner="supply-chain",
                    title=f"Possible typosquat: {pkg}",
                    description=(
                        f"`{pkg}` is one edit away from popular package(s): {', '.join(typos)}."
                    ),
                    location=Location(path=path, snippet=f"{pkg}=={version}"),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    likelihood=Likelihood.POSSIBLE,
                    cwe=["CWE-506"],
                    owasp=["A06:2021-Vulnerable and Outdated Components"],
                    why_vulnerable=(
                        "Typosquatting packages mimic trusted names to trick "
                        "installers into pulling the wrong dependency."
                    ),
                    attacker_perspective=(
                        "Developers mistyping a package name may install an attacker-"
                        "controlled package with the same install privileges."
                    ),
                    business_impact="Supply-chain compromise via mistaken dependency.",
                    remediation=Remediation(
                        summary=f"Verify `{pkg}` is intentional; prefer `{typos[0]}` if not.",
                        guidance=(
                            "Check package provenance, publisher identity, and download "
                            "counts before accepting unfamiliar names."
                        ),
                    ),
                    tags=["supply-chain", "typosquat", ecosystem.lower()],
                    metadata={
                        "ecosystem": ecosystem,
                        "package": pkg,
                        "similar_to": typos,
                    },
                )

        # Malicious npm dependencies whose manifest spec collect_packages drops
        # entirely (``*``, ``latest``, git/url/file specs): no confirmable
        # version, so still report them, version-unconfirmed, never dropped.
        for (path, norm), spec in npm_specs.items():
            if norm in npm_malicious_seen or norm in npm_exact_names:
                continue
            if _npm_spec_is_exact_pin(spec):
                continue  # a concrete pin is handled by the main loop
            match = _known_malicious("npm", norm, "", online=online_intel)
            if not match.matched:
                continue
            npm_malicious_seen.add(norm)  # one finding per name across manifests
            finding = self._malicious_finding(match, counter + 1, "npm", path, norm, spec, False)
            if finding is not None:
                counter += 1
                yield finding

        yield from _scan_npm_scripts(ctx.project, counter)

    @staticmethod
    def _malicious_finding(
        match: MaliciousMatch,
        index: int,
        ecosystem: str,
        path: str,
        pkg: str,
        version: str,
        version_known: bool,
    ) -> Finding | None:
        """Build the known-malicious finding, or ``None`` if this version is clean.

        * Version known and in the affected set -> Critical, high confidence.
        * Version known but NOT affected (the intel lists other versions) ->
          ``None``: a clean, pinned version must not be labelled malicious.
        * Version unknown (unpinned, a range spec, or unparseable) -> still a
          finding, but lower confidence, and the text says the version could not
          be confirmed and only some versions are affected.
        """
        if version_known and not match.affected:
            return None

        affected = match.affected_versions
        version_confirmed = version_known and match.affected and match.has_version_info
        version_unconfirmed = not version_known and match.has_version_info

        if version_confirmed:
            title = f"Known malicious package: {pkg} {version}"
            description = (
                f"`{pkg}` ({ecosystem}) is on Nephilex's malicious-package intelligence "
                f"list. The affected versions are {affected}, and the installed version "
                f"`{version}` is one of them."
            )
            confidence = Confidence.HIGH
            likelihood = Likelihood.ALMOST_CERTAIN
        elif version_unconfirmed:
            # Name matches but the installed version could not be pinned down.
            shown = version or "unspecified"
            title = f"Possibly malicious package: {pkg} (version unconfirmed)"
            description = (
                f"`{pkg}` ({ecosystem}) is on Nephilex's malicious-package intelligence "
                f"list. Only some versions are affected ({affected}), but the installed "
                f"version ({shown}) could not be confirmed, so it is not certain this "
                f"project uses an affected one. Pin the version to confirm."
            )
            confidence = Confidence.LOW
            likelihood = Likelihood.POSSIBLE
        else:
            # No per-version intel for this name: every version is affected, the
            # long-standing behaviour for the bundled name-only entries.
            title = f"Known malicious package: {pkg}"
            description = (
                f"`{pkg}` ({ecosystem}) appears on Nephilex's malicious-package "
                f"intelligence list, which flags every version of this package."
            )
            confidence = Confidence.HIGH
            likelihood = Likelihood.ALMOST_CERTAIN

        return Finding(
            id=f"supply-chain:malicious:{index}",
            rule_id="supply-chain.known-malicious",
            scanner="supply-chain",
            title=title,
            description=description,
            location=Location(path=path, snippet=f"{pkg}=={version}"),
            severity=Severity.CRITICAL,
            confidence=confidence,
            likelihood=likelihood,
            cwe=["CWE-506"],
            owasp=["A06:2021-Vulnerable and Outdated Components"],
            why_vulnerable=(
                "This package has been reported as malicious in public supply-chain advisories."
            ),
            attacker_perspective=(
                "Malicious packages can steal credentials, backdoor builds, "
                "or run arbitrary code during install or import."
            ),
            business_impact=(
                "Critical supply-chain compromise; remove immediately and "
                "rotate any credentials that may have been exposed."
            ),
            remediation=Remediation(
                summary=(
                    f"Confirm the installed version of `{pkg}`; remove or pin it to a "
                    f"version outside the affected set ({affected})."
                    if version_unconfirmed
                    else f"Remove `{pkg}` and audit systems that installed it."
                ),
                guidance=(
                    "Rotate secrets, review CI logs, and scan for persistence. "
                    "Pin dependencies and enable lockfile-only installs."
                ),
            ),
            tags=["supply-chain", "malicious", ecosystem.lower()],
            metadata={
                "ecosystem": ecosystem,
                "package": pkg,
                "version": version,
                "version_confirmed": version_confirmed,
                "affected_versions": affected,
            },
        )
