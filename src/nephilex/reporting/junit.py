"""JUnit XML reporter for CI systems (spec §35)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from nephilex.core.models import ScanResult
from nephilex.core.plugin import Reporter, reporter

# Characters XML 1.0 does not allow at all: C0 controls other than tab/LF/CR,
# lone UTF-16 surrogates, and the U+FFFE/U+FFFF non-characters. ElementTree
# writes them through unchanged, producing a file CI parsers reject. A raw
# string, so each range is written as escapes the regex engine reads, not as
# the control characters themselves.
_INVALID_XML = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\uD800-\uDFFF\uFFFE\uFFFF]")


def _xml_text(value: object) -> str:
    return _INVALID_XML.sub("", "" if value is None else str(value))


@reporter
class JUnitReporter(Reporter):
    name = "junit"
    extension = "xml"
    description = "JUnit XML format for CI test result integration."

    def render(self, result: ScanResult) -> str:
        testsuite = ET.Element("testsuite")
        testsuite.set("name", "nephilex")
        testsuite.set("tests", str(len(result.findings)))
        testsuite.set("failures", str(len(result.findings)))
        for f in result.findings:
            case = ET.SubElement(testsuite, "testcase")
            case.set("name", _xml_text(f"{f.rule_id} ({f.location.as_ref()})"))
            case.set("classname", _xml_text(f.scanner))
            fail = ET.SubElement(case, "failure")
            fail.set("message", _xml_text(f.title))
            fail.text = _xml_text(f.description or f.why_vulnerable or f.title)
        return ET.tostring(testsuite, encoding="unicode")
