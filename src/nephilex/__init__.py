"""Nephilex, an open-source AI Security Engineer.

Nephilex maps an application, runs layered security analysis, explains each finding
in terms a developer can act on, and, where possible, proposes and verifies a fix.
"""

from nephilex.core.models import (
    Confidence,
    Finding,
    Location,
    Remediation,
    ScanResult,
    Severity,
)
from nephilex.core.project import Project

__version__ = "0.12.0rc1"

__all__ = [
    "Confidence",
    "Finding",
    "Location",
    "Project",
    "Remediation",
    "ScanResult",
    "Severity",
    "__version__",
]
