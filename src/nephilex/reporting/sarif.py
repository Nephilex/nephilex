"""SARIF 2.1.0 reporter.

SARIF is the interchange format GitHub Code Scanning and most enterprise security
platforms ingest. This produces a single run with one rule per Nephilex rule_id and
one result per finding, mapping Nephilex severities onto SARIF levels and attaching
``security-severity`` (the numeric score GitHub uses to bucket alerts).
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

from nephilex import __version__
from nephilex.core.models import ScanResult, Severity
from nephilex.core.plugin import Reporter, reporter

# Nephilex severity -> SARIF result level.
_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# Nephilex severity -> GitHub "security-severity" numeric bucket (CVSS-like).
_SECURITY_SEVERITY = {
    Severity.INFO: "0.0",
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}


# Locations that are not files in the repository: placeholders such as
# "(git history)" and URLs from dynamic scans.
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _is_file_path(path: str) -> bool:
    return bool(path) and not path.startswith("(") and not _URL.match(path)


def _artifact_uri(path: str) -> str:
    """Percent-encode a repo-relative path for SARIF ``artifactLocation.uri``.

    SARIF requires a valid URI reference; spaces, "#", "%" or non-ASCII
    characters in a raw path make consumers drop or misplace the result.
    """
    return quote(path.replace("\\", "/"), safe="/")


@reporter
class SARIFReporter(Reporter):
    name = "sarif"
    extension = "sarif"
    description = "SARIF 2.1.0 for GitHub Code Scanning and enterprise platforms."

    def render(self, result: ScanResult) -> str:
        rules: dict[str, dict] = {}
        results: list[dict] = []

        for f in result.sorted_findings():
            if f.rule_id not in rules:
                rules[f.rule_id] = self._rule(f)
            results.append(self._result(f))

        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Nephilex",
                            "informationUri": "https://github.com/nephilex/nephilex",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(doc, indent=2)

    def _rule(self, f) -> dict:
        rule: dict = {
            "id": f.rule_id,
            "name": f.rule_id.replace(".", "_"),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.why_vulnerable or f.description},
            "helpUri": f.docs_url,
            "defaultConfiguration": {"level": _LEVEL[f.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security", *(f.tags or [])],
            },
        }
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        if f.remediation:
            rule["help"] = {
                "text": f.remediation.guidance or f.remediation.summary,
            }
        return rule

    def _result(self, f) -> dict:
        region: dict = {}
        if f.location.start_line:
            region["startLine"] = f.location.start_line
        if f.location.end_line:
            region["endLine"] = f.location.end_line
        if f.location.snippet:
            region["snippet"] = {"text": f.location.snippet}

        path = f.location.path or ""
        location: dict
        if _is_file_path(path):
            physical: dict = {"artifactLocation": {"uri": _artifact_uri(path)}}
            if region:
                physical["region"] = region
            location = {"physicalLocation": physical}
        else:
            # Not a file (git history, a URL, ...): a physical location would
            # point at a path that does not exist in the repository.
            location = {"logicalLocations": [{"name": path or "(unknown)", "kind": "resource"}]}

        out: dict = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": self._message(f)},
            "locations": [location],
            "partialFingerprints": {"nephilexFingerprint": f.fingerprint()},
            "properties": {
                "confidence": f.confidence.label,
                "riskScore": f.risk_score(),
            },
        }
        if f.evidence is not None:
            out["properties"]["grade"] = f.evidence.grade
            flow = self._code_flow(f.evidence)
            if flow is not None:
                out["codeFlows"] = [flow]
        return out

    @staticmethod
    def _code_flow(evidence) -> dict | None:
        """The evidence path as one SARIF thread flow, when it has two or more steps.

        Each step becomes a location with its region, the code line as the
        snippet and ``role: note`` as the message. Steps outside the
        repository (placeholders, URLs) or without a line leave the flow out.
        """
        steps = [s for s in evidence.path if s.role != "elided"]
        if len(steps) < 2 or any(not _is_file_path(s.path) or not s.line for s in steps):
            return None
        locations = []
        for s in steps:
            region: dict = {"startLine": s.line}
            if s.column:
                region["startColumn"] = s.column
            if s.code:
                region["snippet"] = {"text": s.code}
            locations.append(
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(s.path)},
                            "region": region,
                        },
                        "message": {"text": f"{s.role}: {s.note}" if s.note else s.role},
                    },
                    "properties": {"role": s.role},
                }
            )
        return {
            "message": {"text": evidence.basis or "Evidence path"},
            "threadFlows": [{"locations": locations}],
        }

    @staticmethod
    def _message(f) -> str:
        parts = [f.title]
        if f.attacker_perspective:
            parts.append(f"Attack: {f.attacker_perspective}")
        if f.remediation:
            parts.append(f"Fix: {f.remediation.summary}")
        return ", ".join(parts)
