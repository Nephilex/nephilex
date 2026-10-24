"""JUnit and SARIF output stay valid for hostile paths and text."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.reporting.junit import _INVALID_XML, JUnitReporter
from nephilex.reporting.sarif import SARIFReporter


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(target="t", started_at=datetime.now(timezone.utc), findings=list(findings))


def _finding(path: str, title: str = "t", line: int | None = 1) -> Finding:
    return Finding(
        id="x",
        rule_id="r",
        scanner="s",
        title=title,
        description=title,
        location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


def test_junit_strips_characters_xml_cannot_hold():
    bad = "nul\x00 bell\x07 vt\x0b ff\x0c esc\x1b lone\ud800 ok\ttab"
    xml = JUnitReporter().render(_result(_finding(f"a{bad}.py", title=bad)))
    root = ET.fromstring(xml)  # raises on invalid characters
    failure = root.find("testcase/failure")
    assert failure is not None
    assert failure.get("message") == "nul bell vt ff esc lone ok\ttab"


def test_junit_strips_exactly_the_characters_outside_xml_char():
    # XML 1.0 Char: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    def allowed(cp: int) -> bool:
        return cp in (0x9, 0xA, 0xD) or 0x20 <= cp <= 0xD7FF or 0xE000 <= cp <= 0xFFFD

    for cp in range(0x10000):
        assert (_INVALID_XML.match(chr(cp)) is None) == allowed(cp), hex(cp)
    assert _INVALID_XML.match("\U0001f600") is None


def test_sarif_uri_is_percent_encoded():
    doc = json.loads(SARIFReporter().render(_result(_finding("src/my file#1%.py"))))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "src/my%20file%231%25.py"


def test_sarif_history_secret_uses_logical_location():
    doc = json.loads(SARIFReporter().render(_result(_finding("(git history)", line=None))))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in loc
    assert loc["logicalLocations"][0]["name"] == "(git history)"


def test_sarif_url_location_is_logical():
    doc = json.loads(SARIFReporter().render(_result(_finding("https://app.example/x", line=None))))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in loc
