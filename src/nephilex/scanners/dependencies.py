"""Dependency vulnerability scanner.

Parses dependency manifests **and lock files** for the common ecosystems, then
matches declared versions against live OSV data (falling back to a bundled
advisory seed, ``data/advisories.json``). Lock files matter because they pin the
full *transitive* dependency tree with exact versions, which is where most real
dependency risk lives, whereas top-level manifests only list direct deps and
often use loose ranges.

Supported inputs:

* PyPI: ``requirements.txt`` (``==`` pins), ``poetry.lock``, ``Pipfile.lock``.
* npm: ``package.json`` (direct), ``package-lock.json``, ``yarn.lock``.
* Go: ``go.mod``.
* crates.io: ``Cargo.lock``.
* RubyGems: ``Gemfile.lock``.
* Packagist: ``composer.lock``.

New ecosystems match against live OSV data (the bundled seed only covers
PyPI/npm), so they require network access to surface findings.

Version comparison is intentionally lightweight, enough to evaluate the simple
``<x.y.z`` ranges the seed data uses, without pulling in a full SemVer engine.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Iterable
from functools import lru_cache
from importlib import resources
from typing import Any

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner

log = logging.getLogger("nephilex.scanners.dependencies")


@lru_cache(maxsize=1)
def _load_advisories() -> list[dict]:
    with (
        resources.files("nephilex.scanners.data")
        .joinpath("advisories.json")
        .open(encoding="utf-8") as fh
    ):
        return json.load(fh).get("advisories", [])


def _parse_version(v: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-+]", v.strip())
    nums: list[int] = []
    for p in parts:
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
        if not m:
            break
    return tuple(nums) or (0,)


def _version_lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _matches_range(version: str, spec: str) -> bool:
    """Evaluate the small subset of range syntax used by the advisory data."""
    spec = spec.strip()
    if spec.startswith("<="):
        return not _version_lt(spec[2:], version)  # version <= bound
    if spec.startswith("<"):
        return _version_lt(version, spec[1:])
    if spec.startswith(">="):
        return not _version_lt(version, spec[2:])
    if spec.startswith(">"):
        return _version_lt(spec[1:], version)
    if spec.startswith("=="):
        return _parse_version(version) == _parse_version(spec[2:])
    return _parse_version(version) == _parse_version(spec)


# --- manifest parsers ------------------------------------------------------
# Each parser returns a list of (package, version) pairs. Returning pairs rather
# than a {name: version} dict preserves a package pinned at MULTIPLE versions in
# one tree (routine in npm nested node_modules, Cargo, composer); a name-keyed
# dict silently dropped all but the last, so the others were never scanned.
def _unique_pairs(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """De-duplicate (name, version) pairs, preserving first-seen order.

    Keeps *distinct versions* of the same package (the whole point); only exact
    duplicates collapse, so downstream querying stays deterministic.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if m:
            pairs.append((m.group(1).lower(), m.group(2)))
    return _unique_pairs(pairs)


def _loads(text: str) -> Any:
    """Parse JSON tolerantly: strips a UTF-8 BOM (common in Windows-authored files)
    and returns None instead of raising on malformed input.

    Manifests come from the scanned repository, so the result can be any JSON
    type: callers must type-check every value they use. RecursionError is caught
    too, since deeply nested input makes the decoder raise it.
    """
    try:
        return json.loads(text.lstrip("\ufeff"))
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        return None


def _dict_section(data: dict, key: str) -> dict:
    """``data[key]`` if it is a JSON object, else an empty dict."""
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    data = _loads(text)
    if not isinstance(data, dict):
        return pairs
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in _dict_section(data, key).items():
            if not isinstance(ver, str):
                continue  # e.g. {"a": 1}: not a version spec
            cleaned = ver.lstrip("^~>=< ").strip()
            if re.match(r"^\d", cleaned):
                pairs.append((name.lower(), cleaned))
    return _unique_pairs(pairs)


def _parse_package_lock(text: str) -> list[tuple[str, str]]:
    """npm ``package-lock.json``, full transitive tree (lockfileVersion 1/2/3)."""
    pairs: list[tuple[str, str]] = []
    data = _loads(text)
    if not isinstance(data, dict):
        return pairs

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue  # "" is the project root
            name = key.split("node_modules/")[-1]
            ver = str(meta.get("version", ""))
            if name and re.match(r"^\d", ver):
                pairs.append((name.lower(), ver))  # keep every pinned version

    if not packages:  # lockfileVersion 1: nested "dependencies" trees
        # Explicit stack, not recursion: nesting depth is attacker-controlled.
        stack = [data.get("dependencies")]
        while stack:
            tree = stack.pop()
            if not isinstance(tree, dict):
                continue
            for name, meta in tree.items():
                if not isinstance(meta, dict):
                    continue
                ver = str(meta.get("version", ""))
                if re.match(r"^\d", ver):
                    pairs.append((name.lower(), ver))
                stack.append(meta.get("dependencies"))
    return _unique_pairs(pairs)


def _parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """yarn.lock (classic v1 and berry), resolved versions per package."""
    pairs: list[tuple[str, str]] = []
    names: list[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            names = []
            for spec in raw.rstrip()[:-1].split(","):
                spec = spec.strip().strip('"')
                at = spec.rfind("@")  # keep scoped @scope/name; drop the range
                name = spec[:at] if at > 0 else spec
                if name:
                    names.append(name.lower())
        else:
            m = re.match(r'\s+version:?\s+"?([0-9][^"\s]*)"?', raw)
            if m and names:
                for name in names:
                    pairs.append((name, m.group(1)))
                names = []
    return _unique_pairs(pairs)


def _parse_toml_packages(text: str) -> list[tuple[str, str]]:
    """TOML lock files with ``[[package]]`` entries, poetry.lock and Cargo.lock."""
    pairs: list[tuple[str, str]] = []
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            current = None
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"', line)
        if m and current:
            pairs.append((current, m.group(1)))  # Cargo pins the same crate twice
            current = None
    return _unique_pairs(pairs)


# Back-compat alias (poetry.lock shares the [[package]] shape).
_parse_poetry_lock = _parse_toml_packages


def _parse_go_mod(text: str) -> list[tuple[str, str]]:
    """go.mod, module requirements (both block and single-line ``require``)."""
    pairs: list[tuple[str, str]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()  # drop `// indirect` and comments
        if not line:
            continue
        if line.startswith("require (") or line == "require(":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        m = re.match(r"^(\S+)\s+v([0-9][\w.\-]*)", line)
        if m:
            pairs.append((m.group(1), m.group(2)))  # Go paths are case-sensitive
    return _unique_pairs(pairs)


def _parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    """Gemfile.lock, resolved gem specs (4-space indented ``name (version)``)."""
    pairs: list[tuple[str, str]] = []
    for raw in text.splitlines():
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)\s*$", raw)
        if m:
            pairs.append((m.group(1), m.group(2)))
    return _unique_pairs(pairs)


def _parse_composer_lock(text: str) -> list[tuple[str, str]]:
    """composer.lock, Packagist packages (runtime and dev)."""
    pairs: list[tuple[str, str]] = []
    data = _loads(text)
    if not isinstance(data, dict):
        return pairs
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            ver = str(entry.get("version", "")).lstrip("v").strip()
            if isinstance(name, str) and name and re.match(r"^\d", ver):
                pairs.append((name, ver))
    return _unique_pairs(pairs)


def _parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    """Pipfile.lock, default and develop dependency sections."""
    pairs: list[tuple[str, str]] = []
    data = _loads(text)
    if not isinstance(data, dict):
        return pairs
    for section in ("default", "develop"):
        for name, meta in _dict_section(data, section).items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version", "")).lstrip("=<>~ ").strip()
            if re.match(r"^\d", ver):
                pairs.append((name.lower(), ver))
    return _unique_pairs(pairs)


# Manifest/lock file name -> (ecosystem, parser). Lock files first so their exact,
# transitive versions win the per-(package, version) de-duplication below.
_PARSERS = {
    # Lock files first per ecosystem so a dependency present in both a lock file
    # and a manifest is reported at the (pinned, transitive) lock-file location.
    "poetry.lock": ("PyPI", _parse_poetry_lock),
    "Pipfile.lock": ("PyPI", _parse_pipfile_lock),
    "requirements.txt": ("PyPI", _parse_requirements),
    "package-lock.json": ("npm", _parse_package_lock),
    "yarn.lock": ("npm", _parse_yarn_lock),
    "package.json": ("npm", _parse_package_json),
    "go.mod": ("Go", _parse_go_mod),
    "Cargo.lock": ("crates.io", _parse_toml_packages),
    "Gemfile.lock": ("RubyGems", _parse_gemfile_lock),
    "composer.lock": ("Packagist", _parse_composer_lock),
}


def safe_parse(
    parser: Callable[[str], list[tuple[str, str]]], text: str, where: str
) -> list[tuple[str, str]]:
    """Run a manifest parser, treating any failure as "no packages in this file".

    The parsers type-check what they read, so this is a backstop: one malformed
    manifest in a hostile repository must not take down every consumer of the
    inventory (dependency, supply-chain and SBOM scanners alike).
    """
    try:
        return parser(text)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
        log.warning("could not parse %s (%s); skipping it", where, type(exc).__name__)
        return []


def collect_packages(project) -> list[tuple[str, str, str, str]]:
    """Return ``(ecosystem, manifest_path, package, version)`` for every dependency.

    Shared by the dependency scanner, SBOM generator, and supply-chain scanner.
    Lock files are processed first so pinned transitive versions win.
    """
    per_eco: dict[str, dict[tuple[str, str], tuple[str, str, str]]] = {}
    for manifest_name, (ecosystem, parser) in _PARSERS.items():
        for f in project.files_matching(manifest_name):
            for pkg, version in safe_parse(parser, f.text(), f.rel_path):
                bucket = per_eco.setdefault(ecosystem, {})
                bucket.setdefault((pkg, version), (f.rel_path, pkg, version))
    out: list[tuple[str, str, str, str]] = []
    for ecosystem, bucket in per_eco.items():
        for path, pkg, version in bucket.values():
            out.append((ecosystem, path, pkg, version))
    out.sort(key=lambda t: (t[0], t[2], t[3], t[1]))
    return out


def _dedupe_by_cve(advisories: list[dict]) -> list[dict]:
    """Collapse advisories that describe the same CVE, keeping the most severe.

    OSV often returns several records (e.g. a GHSA and a PYSEC entry) aliasing one
    CVE. Reporting them once, at the highest assessed severity, keeps the output
    clean. Advisories without a CVE are keyed by their own id and never merged.
    """
    best: dict[str, dict] = {}
    order: list[str] = []
    for adv in advisories:
        key = adv.get("cve") or adv.get("id", "")
        current = best.get(key)
        if current is None:
            best[key] = adv
            order.append(key)
        elif Severity.parse(adv.get("severity", "MEDIUM")) > Severity.parse(
            current.get("severity", "MEDIUM")
        ):
            best[key] = adv
    return [best[k] for k in order]


def _osv_to_dict(adv, ecosystem: str) -> dict:
    """Normalize an OSVAdvisory into the dict shape the finding builder consumes."""
    return {
        "id": adv.id,
        "cve": adv.cve,
        "severity": adv.severity,
        "summary": adv.summary,
        "title": adv.summary,
        "fixed": adv.fixed or "",
        "cwe": adv.cwe,
        "ecosystem": ecosystem,
        "references": adv.references,
        "affected_symbols": list(getattr(adv, "affected_symbols", []) or []),
        "malicious": bool(getattr(adv, "malicious", False)),
        "aliases": list(getattr(adv, "aliases", []) or []),
        "affected_versions": list(getattr(adv, "affected_versions", []) or []),
    }


def _annotate_reachability(
    finding: Finding,
    pkg: str,
    ecosystem: str,
    py_imports: set[str] | None,
    npm_imports: set[str] | None,
    py_symbols: set[str] | None = None,
    affected_symbols: list[str] | None = None,
) -> None:
    """Attach import-level (and optional symbol-level) reachability verdicts."""
    from nephilex.analysis import reachability
    from nephilex.analysis.symbol_reachability import (
        describe_symbol_verdict,
        symbol_verdict,
    )

    imported = False
    if ecosystem == "PyPI" and py_imports is not None:
        verdict = reachability.python_import_verdict(pkg, py_imports)
        imported = verdict == reachability.IMPORTED
    elif ecosystem == "npm" and npm_imports is not None:
        verdict = reachability.npm_import_verdict(pkg, npm_imports)
        imported = verdict == reachability.IMPORTED
    else:
        return

    finding.metadata["reachability"] = verdict
    finding.description = f"{finding.description}\n\n{reachability.describe(verdict)}"
    if verdict == reachability.NOT_IMPORTED:
        finding.likelihood = Likelihood.UNLIKELY

    if py_symbols is not None and affected_symbols is not None and ecosystem == "PyPI":
        sym = symbol_verdict(
            pkg,
            py_symbols,
            affected_symbols,
            imported=imported,
        )
        finding.metadata["symbol_reachability"] = sym
        extra = describe_symbol_verdict(sym)
        if extra:
            finding.description = f"{finding.description}\n\n{extra}"
        if sym == "symbol_reachable":
            finding.likelihood = max(finding.likelihood, Likelihood.LIKELY)


def _annotate_exploit_signals(finding: Finding, signal) -> None:
    """Attach EPSS and CISA KEV context to a CVE finding.

    Severity is deliberately left untouched: teams gate pipelines on it via
    ``--fail-on``, so it is a stable contract. KEV membership (confirmed exploited
    in the wild) does raise the *likelihood*, which sharpens prioritization and
    sort order without changing that contract. Likelihood is only ever raised,
    never lowered, so this composes safely with the reachability annotation.
    """
    if not signal.has_signal:
        return
    finding.metadata["kev"] = signal.kev
    bits: list[str] = []
    if signal.kev:
        bits.append("on the CISA KEV catalog (confirmed exploited in the wild)")
        if "kev" not in finding.tags:
            finding.tags.append("kev")
        if finding.likelihood < Likelihood.ALMOST_CERTAIN:
            finding.likelihood = Likelihood.ALMOST_CERTAIN
    if signal.epss is not None:
        finding.metadata["epss"] = round(signal.epss, 5)
        finding.metadata["epss_percentile"] = round(signal.percentile or 0.0, 4)
        pct = (signal.percentile or 0.0) * 100
        bits.append(f"EPSS {signal.epss:.1%} (higher than {pct:.0f}% of scored CVEs)")
    if bits:
        finding.description = f"{finding.description}\n\nExploit signals: " + "; ".join(bits) + "."


@scanner
class DependencyScanner(Scanner):
    name = "dependencies"
    category = "dependencies"
    description = "Flags dependencies with known published vulnerabilities."

    def applies_to(self, project) -> bool:
        return bool(project.files_matching(*_PARSERS.keys()))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        online = bool(opts.get("online", True))
        timeout = float(opts.get("timeout", 15.0))
        use_cache = bool(opts.get("cache", True))
        use_reachability = bool(opts.get("reachability", False))
        symbol_reachability = bool(opts.get("symbol_reachability", False))
        use_exploit = online and bool(opts.get("exploit_signals", True))
        counter = 0

        # Experimental import-level reachability: Python and npm for now.
        py_imports: set[str] | None = None
        npm_imports: set[str] | None = None
        py_symbols: set[str] | None = None
        if use_reachability or symbol_reachability:
            from nephilex.analysis import reachability

            py_imports = reachability.collect_python_imports(ctx.project)
            npm_imports = reachability.collect_npm_imports(ctx.project)
            if symbol_reachability:
                from nephilex.analysis.symbol_reachability import collect_python_symbols

                py_symbols = collect_python_symbols(ctx.project)

        # Collect declared dependencies per ecosystem via the shared inventory helper.
        per_eco: dict[str, dict[tuple[str, str], tuple[str, str, str]]] = {}
        for ecosystem, path, pkg, version in collect_packages(ctx.project):
            bucket = per_eco.setdefault(ecosystem, {})
            bucket.setdefault((pkg, version), (path, pkg, version))

        findings: list[Finding] = []
        for ecosystem, bucket in per_eco.items():
            entries = list(bucket.values())
            osv_map, source = self._resolve_source(ecosystem, entries, online, timeout, use_cache)
            for path, pkg, version in entries:
                if source == "osv":
                    advisories = [
                        _osv_to_dict(a, ecosystem) for a in osv_map.get((pkg, version), [])
                    ]
                else:
                    advisories = self._bundled_matches(ecosystem, pkg, version)
                malicious = [a for a in advisories if a.get("malicious")]
                if malicious:
                    # Malware, not a vulnerability: one finding that says to
                    # remove it. CVE advisories for the same release add nothing.
                    counter += 1
                    findings.append(
                        self._malicious_finding(malicious, counter, path, pkg, version, ecosystem)
                    )
                    continue
                for adv in _dedupe_by_cve(advisories):
                    counter += 1
                    finding = self._finding(adv, counter, path, pkg, version)
                    if use_reachability or symbol_reachability:
                        _annotate_reachability(
                            finding,
                            pkg,
                            ecosystem,
                            py_imports,
                            npm_imports,
                            py_symbols=py_symbols,
                            affected_symbols=adv.get("affected_symbols"),
                        )
                    findings.append(finding)

        # Enrich CVE findings with exploit signals in one batched pass, so the
        # EPSS query and KEV fetch happen once for the whole scan.
        if use_exploit:
            cves = {f.metadata.get("cve") for f in findings if f.metadata.get("cve")}
            if cves:
                from nephilex.scanners import exploit_signals

                signals = exploit_signals.enrich(
                    {c for c in cves if c}, timeout=timeout, use_cache=use_cache
                )
                for finding in findings:
                    sig = signals.get(finding.metadata.get("cve") or "")
                    if sig is not None:
                        _annotate_exploit_signals(finding, sig)

        yield from findings

    def _resolve_source(self, ecosystem, entries, online, timeout, use_cache=True):
        """Return (osv_map, source). Prefer live OSV; fall back to the bundled seed."""
        if not online:
            return {}, "bundled"
        # Pass every (package, version) pair, not a {package: version} dict. A
        # package pinned at two versions in a lock tree (routine in npm / Cargo /
        # composer) must be queried at BOTH; collapsing to a dict dropped one and
        # silently left it unscanned.
        pairs = [(pkg, version) for _, pkg, version in entries]
        from nephilex.scanners import osv

        try:
            return osv.query(ecosystem, pairs, timeout=timeout, use_cache=use_cache), "osv"
        except osv.OSVError as exc:
            # Offline/timeout/API problem: fall back to the bundled seed, but say so
            # , a silent fallback in a security tool hides reduced coverage.
            log.warning(
                "OSV lookup for %s failed (%s); falling back to the bundled advisory "
                "seed, which covers far fewer packages. Findings may be incomplete.",
                ecosystem,
                exc,
            )
            return {}, "bundled"
        except Exception as exc:  # unexpected bug: degrade, but surface it loudly
            log.error(
                "Unexpected error during OSV lookup for %s: %s; using the bundled advisory seed.",
                ecosystem,
                exc,
            )
            return {}, "bundled"

    @staticmethod
    def _bundled_matches(ecosystem: str, pkg: str, version: str) -> list[dict]:
        out = []
        for adv in _load_advisories():
            if (
                adv["ecosystem"] == ecosystem
                and adv["package"] == pkg
                and _matches_range(version, adv["vulnerable"])
            ):
                out.append(adv)
        return out

    def _malicious_finding(
        self,
        advisories: list[dict],
        index: int,
        path: str,
        pkg: str,
        version: str,
        ecosystem: str,
    ) -> Finding:
        """A known-malicious package from OSV (``MAL-`` records): remove, never upgrade."""
        ids = sorted({a["id"] for a in advisories} | {x for a in advisories for x in a["aliases"]})
        references: list[str] = []
        for a in advisories:
            references.extend(r for r in a.get("references", []) if r and r not in references)
        references.extend(f"https://osv.dev/vulnerability/{a['id']}" for a in advisories)
        summary = advisories[0].get("summary") or f"Malicious code in {pkg}"
        affected = sorted({v for a in advisories for v in a.get("affected_versions", [])})
        shown = ", ".join(affected[:12]) + (" ..." if len(affected) > 12 else "")
        return Finding(
            id=f"{self.name}:malicious:{ids[0] if ids else pkg}:{index}",
            rule_id="supply-chain.known-malicious",
            scanner=self.name,
            title=f"Known malicious package: {pkg} {version} ({', '.join(ids)})",
            description=(
                f"{summary}. OSV lists `{pkg}` ({ecosystem}) as malware, not as a "
                f"vulnerable release, and the installed version `{version}` is affected"
                + (f" (affected versions: {shown})" if shown else "")
                + ". There is no safe version to upgrade to."
            ),
            location=Location(path=path, snippet=f"{pkg}=={version}"),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.ALMOST_CERTAIN,
            cwe=["CWE-506"],
            owasp=["A08:2021-Software and Data Integrity Failures"],
            why_vulnerable=(
                f"{pkg} is a malicious package: its code was published to harm whoever "
                "installs or imports it, typically by stealing credentials or running a "
                "remote payload."
            ),
            attacker_perspective=(
                "The package's own code runs with the installing user's rights during "
                "install or import; nothing has to be exploited."
            ),
            business_impact=(
                "Compromise of developer machines, CI runners and every credential they hold."
            ),
            remediation=Remediation(
                summary=(
                    f"Remove {pkg}; no version is safe. If it was ever installed, treat that "
                    "environment as compromised and rotate its credentials."
                ),
                guidance=(
                    f"Delete {pkg} from the manifest and lock file and uninstall it. On every "
                    "machine or CI runner that installed it, rotate tokens, keys and passwords "
                    "it could read (environment variables, ~/.ssh, cloud and registry "
                    "credentials), review what ran, and rebuild the environment from a clean "
                    "image. Check how the dependency was introduced (a typo, a dependency of a "
                    "dependency, an AI suggestion)."
                ),
                references=references[:8],
            ),
            tags=["dependency", "supply-chain", "malicious", ecosystem.lower()],
            metadata={
                "ecosystem": ecosystem,
                "package": pkg,
                "version": version,
                "installed_version": version,
                "version_confirmed": True,
                "advisories": ids,
                "affected_versions": shown,
            },
        )

    def _finding(self, adv: dict, index: int, path: str, pkg: str, version: str) -> Finding:
        sev = Severity.parse(adv.get("severity", "MEDIUM"))
        cve = adv.get("cve", "")
        fixed = adv.get("fixed", "")
        references = [r for r in adv.get("references", []) if r] or [
            f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            f"https://github.com/advisories/{adv['id']}",
        ]
        return Finding(
            id=f"{self.name}:{adv['id']}:{index}",
            rule_id=f"{self.name}.{adv['id']}",
            scanner=self.name,
            title=f"Vulnerable dependency: {pkg} {version} ({cve})"
            if cve
            else f"Vulnerable dependency: {pkg} {version}",
            description=adv.get("summary", adv.get("title", "")),
            location=Location(path=path, snippet=f"{pkg}=={version}"),
            severity=sev,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.LIKELY,
            cwe=adv.get("cwe", ["CWE-1104"]),
            owasp=["A06:2021-Vulnerable and Outdated Components"],
            why_vulnerable=(
                f"{pkg} {version} is affected by {cve or adv['id']}: {adv.get('title', '')}."
            ),
            attacker_perspective=(
                "An attacker can use the public advisory/exploit for this known "
                "vulnerability directly against the running application."
            ),
            business_impact="Depends on the advisory; see the referenced CVE for the "
            "specific impact and exploitability.",
            remediation=Remediation(
                summary=f"Upgrade {pkg} to {fixed} or later."
                if fixed
                else f"Upgrade {pkg} to a patched version.",
                guidance=(
                    f"Update the pinned version of {pkg} to "
                    f"{fixed or 'the latest patched release'} and re-run tests. "
                    "Review the advisory for any required migration steps."
                ),
                references=references,
            ),
            tags=["dependency", adv.get("ecosystem", "")],
            metadata={"cve": cve, "fixed_version": fixed, "installed_version": version},
        )
