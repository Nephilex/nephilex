"""Verify deterministic fixes with the project's own tests.

A rewrite counts as *rule-verified* when the detection no longer matches the
rewritten line. That says nothing about whether the application still works,
so ``nephilex fix --verify-with-tests`` also runs the project's test command:

1. A temporary git worktree is created from the scanned commit (HEAD), so
   nothing runs in the operator's own checkout.
2. The test command runs once there unchanged (the baseline). If it already
   fails, the fixes cannot be judged and none is reported as passing.
3. The fixes are applied in the worktree and the changed files are scanned
   again: each original finding must be gone and no new High or Critical
   finding may appear in those files. Fixes that fail this check are dropped.
4. The test command runs again on the remaining fixes. Their result is the
   outcome for every one of them; when several fixes are tested together and
   the run fails, the failing fix is not isolated.
5. The worktree is removed, also after an error or a timeout.

The test command is the operator's choice (``--test-command``, or
``autofix.test_command`` in a trusted project's config). It runs without a
shell, with a timeout, with its output capped, and with an environment from
which variables that look like credentials were removed. Its output is shown
to the operator only; it is never sent to an AI provider.

Running a project's tests runs that project's code. The controls above keep
the operator's checkout and credentials in the environment out of reach of an
accident; they are not a sandbox. Use this only on repositories you trust.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nephilex.core.models import Finding, Severity
from nephilex.core.project import Project
from nephilex.remediation import git_ops
from nephilex.remediation.applier import AppliedFix, apply_fixes

if TYPE_CHECKING:
    from nephilex.core.config import Config

#: Per-fix outcome of test verification, kept apart from the rule check.
TESTS_PASSED = "passed"
TESTS_FAILED = "failed"
TESTS_NOT_VERIFIED = "not_verified"

TEST_STATUS_LABELS = {
    TESTS_PASSED: "passed",
    TESTS_FAILED: "failed",
    TESTS_NOT_VERIFIED: "could not verify",
}

#: Default wall-clock limit for one run of the test command, in seconds.
DEFAULT_TEST_TIMEOUT = 600.0
#: Bytes of test output kept per run (the tail; earlier output is dropped).
MAX_TEST_OUTPUT = 1_000_000
#: Lines of output shown to the operator when a run fails.
OUTPUT_TAIL_LINES = 25

# The config keys under ``autofix`` (trusted projects only).
CONFIG_COMMAND_KEY = "test_command"
CONFIG_TIMEOUT_KEY = "test_timeout"


class TestCommandError(ValueError):
    """No usable test command was given (a usage error)."""

    __test__ = False  # not a pytest test class


# --- the command -----------------------------------------------------------
@dataclass(frozen=True)
class TestCommand:
    """The program and arguments to run, never a shell string."""

    __test__ = False

    argv: tuple[str, ...]
    timeout: float = DEFAULT_TEST_TIMEOUT
    source: str = "--test-command"

    def display(self) -> str:
        if sys.platform == "win32":
            return subprocess.list2cmdline(list(self.argv))
        return shlex.join(self.argv)


def split_command(command: str) -> list[str]:
    """Split a command line into arguments without involving a shell.

    POSIX uses :func:`shlex.split`. Windows uses the Microsoft C runtime
    rules every native program applies to its own command line, so
    ``C:\\tools\\run.exe "a b"`` keeps its backslashes. Raises ``ValueError``
    for an empty command or an unterminated quote.
    """
    args = _split_windows(command) if sys.platform == "win32" else shlex.split(command)
    if not args:
        raise ValueError("the test command is empty")
    return args


def _split_windows(command: str) -> list[str]:
    """Split like ``CommandLineToArgvW`` (backslashes are literal unless before a quote)."""
    args: list[str] = []
    buf: list[str] = []
    in_quotes = False
    have_arg = False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\":
            j = i
            while j < n and command[j] == "\\":
                j += 1
            count = j - i
            if j < n and command[j] == '"':
                # 2n backslashes + quote: n backslashes, then the quote toggles.
                # 2n+1 backslashes + quote: n backslashes and a literal quote.
                buf.append("\\" * (count // 2))
                if count % 2:
                    buf.append('"')
                    j += 1
            else:
                buf.append("\\" * count)
            have_arg = True
            i = j
        elif c == '"':
            if in_quotes and i + 1 < n and command[i + 1] == '"':
                buf.append('"')  # "" inside quotes is a literal quote
                i += 2
            else:
                in_quotes = not in_quotes
                i += 1
            have_arg = True
        elif c in " \t" and not in_quotes:
            if have_arg:
                args.append("".join(buf))
                buf, have_arg = [], False
            i += 1
        else:
            buf.append(c)
            have_arg = True
            i += 1
    if in_quotes:
        raise ValueError("unterminated quote in the test command")
    if have_arg:
        args.append("".join(buf))
    return args


def _argv_from_value(value: object, source: str) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            argv = split_command(value)
        except ValueError as exc:
            raise TestCommandError(f"{source}: {exc}") from exc
    elif isinstance(value, list) and value and all(isinstance(a, str) for a in value):
        argv = list(value)
    else:
        raise TestCommandError(
            f"{source}: expected a command string or a non-empty list of strings"
        )
    if not argv[0] or any("\0" in a for a in argv):
        raise TestCommandError(f"{source}: invalid program name or argument")
    return tuple(argv)


def _timeout_from_value(value: object, source: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise TestCommandError(f"{source}: expected a positive number of seconds")
    return float(value)


def resolve_test_command(
    cli_command: str | None,
    cli_timeout: float | None,
    config: Config,
) -> TestCommand:
    """Pick the test command from the CLI, else from a trusted project config.

    ``autofix.test_command`` and ``autofix.test_timeout`` are read only when
    ``config.trust_project_config`` is set: an untrusted repository must never
    choose a program Nephilex runs. Raises :class:`TestCommandError` when there
    is no usable command.
    """
    autofix: Mapping[str, Any] = (
        config.autofix if config.trust_project_config and isinstance(config.autofix, dict) else {}
    )
    if cli_timeout is not None:
        timeout = _timeout_from_value(cli_timeout, "--test-timeout")
    elif autofix.get(CONFIG_TIMEOUT_KEY) is not None:
        timeout = _timeout_from_value(autofix[CONFIG_TIMEOUT_KEY], f"autofix.{CONFIG_TIMEOUT_KEY}")
    else:
        timeout = DEFAULT_TEST_TIMEOUT

    if cli_command is not None:
        return TestCommand(_argv_from_value(cli_command, "--test-command"), timeout)
    configured = autofix.get(CONFIG_COMMAND_KEY)
    if configured is not None:
        source = f"autofix.{CONFIG_COMMAND_KEY}"
        return TestCommand(_argv_from_value(configured, source), timeout, source=source)
    raise TestCommandError(
        "--verify-with-tests needs a test command: pass --test-command "
        '(for example --test-command "python -m pytest -q"), or set '
        "autofix.test_command in the project's .nephilex.yml. The config key is "
        "read only for trusted projects, so an untrusted repository cannot "
        "choose the command."
    )


# --- the environment -------------------------------------------------------
# Never removed: what a child needs to find programs and start Python or Node.
_ALWAYS_KEEP = frozenset(
    {
        "PATH",
        "PATHEXT",
        "PWD",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
    }
)

# Names that look like credentials, matched against the upper-cased name.
_SECRET_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|PRIVATE|KEY|AUTH(?!OR)|COOKIE"
    r"|JWT|ASKPASS|(?:^|_)PASS(?:$|_)|(?:^|_)PWD$|(?:^|_)SESSION(?:$|_)"
)

# Whole families: hosting and CI providers, cloud SDKs, AI providers, secret
# managers, and Nephilex's own settings (which carry its tokens).
_SECRET_PREFIXES = (
    "NEPHILEX_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "GL_",
    "CI_JOB_",
    "ACTIONS_",
    "BITBUCKET_",
    "AWS_",
    "AMAZON_",
    "AZURE_",
    "ARM_",
    "MSI_",
    "IDENTITY_",
    "GOOGLE_",
    "GCLOUD_",
    "GCP_",
    "CLOUDSDK_",
    "ALIBABA_",
    "ALICLOUD_",
    "DIGITALOCEAN_",
    "HEROKU_",
    "VAULT_",
    "OP_",
    "DOPPLER_",
    "ANTHROPIC_",
    "OPENAI_",
    "TWINE_",
    "PYPI_",
    "NPM_CONFIG__",
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
)

# Exact names: files or sockets that hand out credentials, and git variables
# that would point the tests' own git calls at another repository.
_SECRET_EXACT = frozenset(
    {
        "KUBECONFIG",
        "DOCKER_CONFIG",
        "NETRC",
        "GPG_AGENT_INFO",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
    }
)

# Values that are credentials whatever the variable is called: userinfo in a
# URL, a PEM private key, or a well-known token prefix.
_SECRET_VALUE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]*:[^\s/@]+@"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{20,}"
    r"|xox[abposr]-[\w-]{10,}|sk-[\w-]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
    r"|AIza[\w-]{35}|npm_[A-Za-z0-9]{36}|pypi-[\w-]{20,})"
)


def _looks_secret(name: str, value: str) -> bool:
    upper = name.upper()
    if upper in _ALWAYS_KEEP:
        return False
    return bool(
        upper in _SECRET_EXACT
        or upper.startswith(_SECRET_PREFIXES)
        or _SECRET_NAME.search(upper)
        or _SECRET_VALUE.search(value)
    )


def scrub_environment(env: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """Return ``env`` without credential-like variables, and the names removed.

    This is a deny list by name and by value, so it is best effort: a secret in
    an innocently named variable with an unrecognised format gets through.
    PATH and the variables Python, Node and the platform need are kept.
    """
    kept: dict[str, str] = {}
    removed: list[str] = []
    for name, value in env.items():
        if _looks_secret(name, value):
            removed.append(name)
        else:
            kept[name] = value
    return kept, sorted(removed)


# --- running the command ---------------------------------------------------
@dataclass
class TestRun:
    """One run of the test command."""

    __test__ = False

    status: str  # "passed" | "failed" | "timeout" | "error"
    returncode: int | None = None
    duration: float = 0.0
    output: str = ""  # the last MAX_TEST_OUTPUT bytes, decoded
    truncated: bool = False
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def describe(self, timeout: float) -> str:
        if self.status == "passed":
            return f"passed in {self.duration:.1f}s"
        if self.status == "failed":
            return f"failed with exit code {self.returncode} after {self.duration:.1f}s"
        if self.status == "timeout":
            return f"timed out after {timeout:g}s and was stopped"
        return f"could not run: {self.error}"

    def tail(self, lines: int = OUTPUT_TAIL_LINES) -> str:
        return "\n".join(self.output.rstrip().splitlines()[-lines:])


def resolve_executable(program: str, cwd: Path, search_path: str | None) -> str | None:
    """Find ``program`` the way a shell would, without using the current directory.

    A program given with a directory part is resolved against ``cwd`` (the
    worktree). A bare name is searched only in the absolute entries of
    ``search_path``; empty and relative entries are skipped so that a file in
    the repository cannot shadow a program on PATH. On Windows the PATHEXT
    extensions are tried when the name has none of them.
    """
    if sys.platform == "win32":
        pathext = [
            e.lower() for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e
        ]
        exts = [""] if Path(program).suffix.lower() in pathext else pathext
    else:
        exts = [""]

    def first(base: str) -> str | None:
        for ext in exts:
            candidate = base + ext
            # The suffix comes from PATHEXT in the environment of whoever runs this.
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):  # nephilex-ignore: ast-path-traversal reason="PATH lookup; the PATHEXT suffixes come from the environment of whoever runs the command"  # fmt: skip
                return candidate
        return None

    separators = {"/", os.sep} | ({os.altsep} if os.altsep else set())
    if any(sep in program for sep in separators):
        return first(program if os.path.isabs(program) else str(cwd / program))
    for directory in (search_path or "").split(os.pathsep):
        if directory and os.path.isabs(directory):
            found = first(os.path.join(directory, program))
            if found:
                return found
    return None


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Stop the test process and everything it started."""
    if sys.platform == "win32":
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        taskkill = os.path.join(root, "System32", "taskkill.exe")
        with suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # nephilex-ignore: ast-command-injection reason="argv list, no shell; taskkill.exe from the operator's own SYSTEMROOT"
                [taskkill, "/F", "/T", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
    else:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
    with suppress(OSError):
        proc.kill()


def run_test_command(
    command: TestCommand, cwd: Path, env: Mapping[str, str] | None = None
) -> TestRun:
    """Run ``command`` in ``cwd`` without a shell, with a timeout and capped output.

    ``env`` defaults to the current environment with credentials scrubbed.
    stdout and stderr are merged; only the last :data:`MAX_TEST_OUTPUT` bytes
    are kept. On timeout the whole process tree is killed.
    """
    if env is None:
        env, _ = scrub_environment(os.environ)
    argv = list(command.argv)
    program = resolve_executable(argv[0], cwd, env.get("PATH", os.defpath))
    if program is None:
        return TestRun(status="error", error=f"program not found: {argv[0]}")
    argv[0] = program

    extra: dict[str, Any] = {}
    if sys.platform == "win32":
        extra["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        extra["start_new_session"] = True  # its own process group, killed as one
    started = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603  # nephilex-ignore: ast-command-injection reason="runs the operator's --test-command as an argv list, no shell; never from untrusted config"
            argv,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            **extra,
        )
    except OSError as exc:
        return TestRun(status="error", error=f"could not start {argv[0]}: {exc}")

    tail: deque[bytes] = deque()
    state = {"size": 0, "dropped": False}

    def _drain() -> None:
        assert proc.stdout is not None
        while chunk := proc.stdout.read(65536):
            tail.append(chunk)
            state["size"] += len(chunk)
            while state["size"] - len(tail[0]) >= MAX_TEST_OUTPUT and len(tail) > 1:
                state["size"] -= len(tail.popleft())
                state["dropped"] = True

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=command.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        with suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=30)
    finally:
        if sys.platform != "win32" and not timed_out:
            # Stop anything the tests left running in their process group.
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        reader.join(timeout=10)
    duration = time.monotonic() - started

    data = b"".join(tail)
    truncated = bool(state["dropped"]) or len(data) > MAX_TEST_OUTPUT
    output = data[-MAX_TEST_OUTPUT:].decode("utf-8", errors="replace")
    if timed_out:
        return TestRun("timeout", None, duration, output, truncated)
    status = "passed" if proc.returncode == 0 else "failed"
    return TestRun(status, proc.returncode, duration, output, truncated)


# --- the temporary worktree ------------------------------------------------
class WorktreeError(RuntimeError):
    """The temporary worktree could not be created."""


def _force_remove(func: Callable[..., Any], path: str, _exc: object) -> None:
    """rmtree error handler: clear the read-only bit (git objects on Windows) and retry."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _rmtree(path: Path) -> None:
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_remove)
    else:
        shutil.rmtree(path, onerror=_force_remove)


@contextmanager
def temporary_worktree(
    repo_root: Path, commit: str, notes: list[str] | None = None
) -> Iterator[Path]:
    """Yield a detached worktree of ``commit`` in a new temporary directory.

    The worktree is removed and unregistered when the block exits, whether it
    finishes, raises or is interrupted. A removal problem is added to
    ``notes`` instead of hiding the block's own exception.
    """
    parent = Path(tempfile.mkdtemp(prefix="nephilex-verify-"))
    tree = parent / "worktree"
    try:
        try:
            git_ops.add_worktree(repo_root, tree, commit)
        except git_ops.GitError as exc:
            raise WorktreeError(f"could not create a temporary worktree: {exc}") from exc
        yield tree
    finally:
        # Fails when the worktree was never registered or files are still in
        # use; the directory is then removed below and the registration pruned.
        with suppress(git_ops.GitError):
            git_ops.remove_worktree(repo_root, tree)
        if parent.exists():
            _rmtree(parent)
        with suppress(git_ops.GitError):
            git_ops.prune_worktrees(repo_root)
        if parent.exists() and notes is not None:
            notes.append(f"Could not fully remove the temporary worktree at {parent}.")


# --- verification ----------------------------------------------------------
@dataclass
class TestVerification:
    """What ``nephilex fix`` passes in to verify fixes with tests."""

    __test__ = False

    command: TestCommand
    #: The scan configuration, reused (with AI and caching off) for the rescan.
    config: Config
    progress: Callable[[str], None] | None = None


@dataclass
class VerificationReport:
    command: str
    timeout: float
    #: Candidate fixes as applied in the worktree, each with ``tests`` set.
    fixes: list[AppliedFix] = field(default_factory=list)
    baseline: TestRun | None = None
    after: TestRun | None = None
    #: Set when verification could not be carried out at all.
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    removed_env: list[str] = field(default_factory=list)
    #: Content digests of the files as tested, to check the real branch matches.
    tested_files: dict[str, str] = field(default_factory=dict)

    def passed_ids(self) -> set[str]:
        return {f.finding_id for f in self.fixes if f.tests == TESTS_PASSED}

    def counts(self) -> dict[str, int]:
        out = {TESTS_PASSED: 0, TESTS_FAILED: 0, TESTS_NOT_VERIFIED: 0}
        for f in self.fixes:
            out[f.tests or TESTS_NOT_VERIFIED] += 1
        return out


def content_digest(data: bytes) -> str:
    """Digest of file content with CRLF folded to LF (checkouts may differ only there)."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _copies(findings: Sequence[Finding]) -> list[Finding]:
    # The applier marks findings it fixed; the worktree runs must not touch the
    # caller's objects.
    return [f.model_copy(deep=True) for f in findings]


def _key(f: Finding) -> tuple[str, str, int | None]:
    return (f.rule_id, f.location.path, f.location.start_line)


def _rescan(root: Path, name: str, config: Config) -> tuple[list[Finding], list[str]]:
    from nephilex.core.engine import ScanEngine

    cfg = dataclasses.replace(
        config,
        ai=dataclasses.replace(config.ai, enabled=False),
        cache=False,
        audit_log=False,
        generate_patches=False,
    )
    result = ScanEngine(cfg).scan(Project.from_path(root, name=name))
    return result.findings, list(result.errors)


def _rescan_failures(
    fixes: list[AppliedFix],
    original: Sequence[Finding],
    rescanned: list[Finding],
) -> dict[str, str]:
    """Finding id -> reason, for fixes the rescan does not confirm."""
    still = {_key(f) for f in rescanned}
    before = {_key(f) for f in original}
    changed = {fix.path for fix in fixes}
    failures: dict[str, str] = {}
    for fix in fixes:
        if (fix.rule_id, fix.path, fix.line) in still:
            failures[fix.finding_id] = "the rescan still reports the finding"
    for f in rescanned:
        if f.location.path in changed and f.severity >= Severity.HIGH and _key(f) not in before:
            reason = (
                f"the rescan found a new {f.severity.label} finding "
                f"({f.rule_id}, line {f.location.start_line}) in {f.location.path}"
            )
            for fix in fixes:
                if fix.path == f.location.path:
                    failures.setdefault(fix.finding_id, reason)
    return failures


def _reset(tree: Path) -> None:
    git_ops.reset_hard(tree)
    git_ops.clean_untracked(tree)


def verify_fixes_with_tests(
    project: Project,
    findings: list[Finding],
    verification: TestVerification,
    *,
    commit: str,
    include_unverified: bool = False,
    only_rules: set[str] | None = None,
) -> VerificationReport:
    """Run the flow in the module docstring and return per-fix outcomes.

    ``commit`` is the scanned commit (HEAD of ``project.root``). Never raises
    for an expected problem: those end up in ``report.error``. The caller's
    findings are not modified.
    """
    command = verification.command
    progress = verification.progress or (lambda _msg: None)
    report = VerificationReport(command=command.display(), timeout=command.timeout)
    env, report.removed_env = scrub_environment(os.environ)
    prefix = git_ops.path_prefix(project.root)

    try:
        with temporary_worktree(project.root, commit, report.notes) as tree:
            root = tree / prefix if prefix else tree
            wt_project = Project.from_path(root, name=project.name)

            preview = apply_fixes(
                wt_project,
                _copies(findings),
                include_unverified=include_unverified,
                dry_run=True,
                only_rules=only_rules,
                audit=False,
            )
            by_id = {fix.finding_id: fix for fix in preview.fixes}
            report.fixes = list(preview.fixes)
            if not report.fixes:
                return report

            progress(f"Running the test command before any fix: {report.command}")
            report.baseline = run_test_command(command, root, env)
            if not report.baseline.passed:
                for fix in report.fixes:
                    fix.tests, fix.tests_reason = TESTS_NOT_VERIFIED, "the baseline test run failed"
                report.error = (
                    "The baseline test run, before any fix was applied, "
                    f"{report.baseline.describe(command.timeout)}, so the fixes cannot be "
                    "verified with tests. Nothing was committed. Make the tests pass on "
                    "the current commit (in a clean checkout) and run again."
                )
                return report

            candidates = set(by_id)
            final: list[AppliedFix] = []
            while candidates:
                _reset(tree)
                applied = apply_fixes(
                    wt_project,
                    _copies([f for f in findings if f.id in candidates]),
                    include_unverified=include_unverified,
                    only_rules=only_rules,
                    audit=False,
                )
                progress("Rescanning the fixed files...")
                try:
                    rescanned, errors = _rescan(root, project.name, verification.config)
                except Exception as exc:  # a crashed rescan proves nothing
                    errors, rescanned = [str(exc)], []
                if errors:
                    for fid in candidates:
                        by_id[fid].tests = TESTS_NOT_VERIFIED
                        by_id[fid].tests_reason = "the rescan of the fixed files failed"
                    report.notes.append("Rescan errors: " + "; ".join(errors[:3]))
                    candidates = set()
                    break
                failures = _rescan_failures(applied.fixes, findings, rescanned)
                failures.update(
                    {
                        fid: "the fix did not apply in the test worktree"
                        for fid in candidates - {fix.finding_id for fix in applied.fixes}
                    }
                )
                if not failures:
                    final = applied.fixes
                    break
                for fid, reason in failures.items():
                    by_id[fid].tests, by_id[fid].tests_reason = TESTS_FAILED, reason
                candidates -= set(failures)

            if not final:
                return report

            # Recorded before the run, which could itself change the files.
            tested = {fix.path: content_digest((root / fix.path).read_bytes()) for fix in final}
            progress(f"Running the test command with {len(final)} fix(es) applied...")
            report.after = run_test_command(command, root, env)
            together = len(final) > 1
            if report.after.passed:
                status, reason = TESTS_PASSED, "tests passed with the fix applied"
                report.tested_files = tested
            elif report.after.status == "failed":
                status = TESTS_FAILED
                reason = (
                    f"tests failed with {len(final)} fixes applied together; "
                    "the failing fix was not isolated"
                    if together
                    else "tests failed with the fix applied"
                )
            else:
                status = TESTS_NOT_VERIFIED
                reason = f"the test run after the fixes {report.after.describe(command.timeout)}"
            for fix in final:
                by_id[fix.finding_id].tests, by_id[fix.finding_id].tests_reason = status, reason
    except (WorktreeError, git_ops.GitError, OSError) as exc:
        for fix in report.fixes:
            if fix.tests is None:
                fix.tests, fix.tests_reason = TESTS_NOT_VERIFIED, "verification did not finish"
        report.error = f"Test verification failed: {exc}. Nothing was committed."
    return report
