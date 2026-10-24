"""Weak-hash rule: non-security uses of MD5 / SHA-1.

``usedforsecurity=False`` is never reported; a hash that is evidently a
checksum, ETag or cache key is reported at low severity; anything that names
a password, secret, token, signature or salt keeps the rule's severity and the
KDF guidance.
"""

from __future__ import annotations

import pytest

from nephilex.analysis.repository import RepositoryAnalyzer
from nephilex.core.config import Config
from nephilex.core.models import Confidence, Severity
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project


def _hashes(tmp_path, code: str) -> list:
    (tmp_path / "util.py").write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return [
        f
        for f in registry.get_scanner("patterns")().scan(ctx)
        if f.rule_id == "patterns.weak-hash-md5-sha1"
    ]


@pytest.mark.parametrize(
    "code",
    [
        "import hashlib\nh = hashlib.md5(data, usedforsecurity=False).hexdigest()\n",
        "import hashlib\nh = hashlib.sha1(\n    data,\n    usedforsecurity=False,\n).hexdigest()\n",
    ],
)
def test_used_for_security_false_is_not_reported(tmp_path, code):
    assert not _hashes(tmp_path, code)


@pytest.mark.parametrize(
    "code",
    [
        'import hashlib\ndigest = hashlib.sha1(page_text.encode("utf-8")).hexdigest()\n',
        "import hashlib\netag = hashlib.md5(body).hexdigest()\n",
        "import hashlib\ndef cache_key(url):\n    return hashlib.md5(url.encode()).hexdigest()\n",
        "import hashlib\nchecksum = hashlib.md5(open(p, 'rb').read()).hexdigest()\n",
    ],
)
def test_checksum_and_cache_keys_are_low_severity(tmp_path, code):
    (f,) = _hashes(tmp_path, code)
    assert f.severity == Severity.LOW and f.confidence == Confidence.LOW
    assert f.metadata["hash_purpose"] == "checksum" and "non-security-hash" in f.tags


@pytest.mark.parametrize(
    "code",
    [
        "import hashlib\npw_digest = hashlib.md5(password.encode()).hexdigest()\n",
        "import hashlib\ndef hash_password(pw):\n    return hashlib.sha1(pw).hexdigest()\n",
        "import hashlib\ntoken = hashlib.md5(secret + str(now)).hexdigest()\n",
        "import hashlib\nsig = hashlib.sha1(key + msg).hexdigest()  # request signature\n",
        "import hashlib\nh = hashlib.md5(x).hexdigest()\n",
    ],
)
def test_security_or_unknown_uses_keep_the_rule_severity(tmp_path, code):
    (f,) = _hashes(tmp_path, code)
    assert f.severity == Severity.MEDIUM
    assert "hash_purpose" not in f.metadata
    assert "KDF" in f.remediation.summary
