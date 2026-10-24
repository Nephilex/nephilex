"""Configuration loading and defaults.

Config resolution order (later wins):

1. Built-in defaults.
2. ``.nephilex.yml`` / ``.nephilex.yaml`` found in the project root.
3. A file passed explicitly with ``--config``.
4. CLI flags.

Step 2 only happens for trusted targets; see :func:`load_project_config`,
which every command uses to make that decision.

Kept deliberately small, every field maps to something a user actually tunes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from nephilex.core import gitexec
from nephilex.core.models import Severity

if TYPE_CHECKING:
    from nephilex.context import ProjectContext
    from nephilex.core.project import Project

CONFIG_FILENAMES = (".nephilex.yml", ".nephilex.yaml")


class ConfigError(ValueError):
    """The configuration is invalid.

    Commands report this and exit 2 instead of scanning with a configuration
    that does not say what the user meant (a CI gate must fail closed).
    """


class ConfigFileNotFoundError(ConfigError, FileNotFoundError):
    """An explicitly requested config file does not exist."""


def _str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(
            f'{key}: expected a list of strings (e.g. {key}: ["value"]), got {value!r}'
        )
    return [v.strip() for v in value if v.strip()]


def _dict_list(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(f"{key}: expected a list of mappings, got {value!r}")
    return list(value)


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: expected a mapping, got {type(value).__name__}")
    return dict(value)


def _bool(data: dict[str, Any], key: str, default: bool, *, prefix: str = "") -> bool:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{prefix}{key}: expected true or false, got {value!r}")
    return value


def _non_negative_int(data: dict[str, Any], key: str, default: int, *, prefix: str = "") -> int:
    value = data.get(key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError(f"{prefix}{key}: expected a whole number >= 0, got {value!r}")
    return value


def _check_test_settings(autofix: dict[str, Any]) -> None:
    """Validate ``autofix.test_command`` and ``autofix.test_timeout`` when present.

    They are used by ``nephilex fix --verify-with-tests``, and only when the
    project config is trusted (see ``remediation.testverify``).
    """
    command = autofix.get("test_command")
    if command is not None and not (
        (isinstance(command, str) and command.strip())
        or (
            isinstance(command, list) and command and all(isinstance(a, str) and a for a in command)
        )
    ):
        raise ConfigError(
            "autofix.test_command: expected a command string or a non-empty list of "
            f"strings, got {command!r}"
        )
    timeout = autofix.get("test_timeout")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
    ):
        raise ConfigError(
            f"autofix.test_timeout: expected a positive number of seconds, got {timeout!r}"
        )


def _library_mode(value: Any, default: str) -> str:
    """``library_mode``: auto, on or off.

    YAML 1.1 reads a bare ``on`` / ``off`` as a boolean, so true and false are
    accepted as on and off.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, str) and value.strip().lower() in ("auto", "on", "off"):
        return value.strip().lower()
    raise ConfigError(f"library_mode: expected auto, on or off, got {value!r}")


def _severity(value: Any, key: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{key}: {exc}") from exc


@dataclass
class AIConfig:
    provider: str = "heuristic"  # heuristic | anthropic | openai | ollama
    model: str | None = None  # provider-specific; None uses the provider default
    enabled: bool = True  # if False, findings are not AI-enriched
    temperature: float = 0.0
    max_tokens: int = 4096
    # With a real model, only this many findings (highest risk first) are sent
    # to it; the rest get offline heuristic reasoning. Bounds cost and runtime
    # (up to three model calls per finding). Not applied to the heuristic
    # provider. 0 means no model calls at all.
    max_findings: int = 25


@dataclass
class Config:
    # Which scanners to run. Empty means "all that apply".
    scanners: list[str] = field(default_factory=list)
    # Scanners to explicitly skip.
    exclude_scanners: list[str] = field(default_factory=list)
    # Glob patterns to ignore in addition to the built-in ignore list.
    exclude_paths: list[str] = field(default_factory=list)
    # Minimum severity to report.
    min_severity: Severity = Severity.INFO
    # Enable Attack Simulation Mode (AI-generated, sandboxed demonstrations).
    attack_simulation: bool = False
    # Attempt to generate patches for findings.
    generate_patches: bool = False
    # Fail the process (non-zero exit) at/above this severity, for CI gating.
    fail_on: Severity | None = None
    # Fail when any scanner crashes. None (the default) means "fail on scanner
    # errors whenever a fail_on threshold gates the run": a crashed scanner
    # reports nothing, and a gate must not read that as a pass. Set False to
    # opt out explicitly.
    fail_on_error: bool | None = None
    # Reuse cached findings for unchanged files (file-local scanners only).
    cache: bool = True
    # Run scanners concurrently. Output stays deterministic either way.
    parallel: bool = True
    # Whether the scanned project's own contents are trusted. When False,
    # in-repo extension points (the .nephilex/rules convention dir) are NOT
    # honored, because a hostile repository could otherwise inject scanner
    # rules. Untrusted by default: load_project_config() sets it from the same
    # decision that gates the in-repo .nephilex.yml (local targets are trusted,
    # cloned remotes only with --trust-remote-config).
    trust_project_config: bool = False
    # Live target for dynamic checks, set only from operator input
    # (--live-target). Config files never populate it, so a scanned repository
    # cannot point the scanner at an internal address.
    dast_url: str | None = None

    ai: AIConfig = field(default_factory=AIConfig)

    # Per-scanner options, keyed by scanner name.
    scanner_options: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Committed allowlist: accepted findings kept outside the source. Each entry is
    # {rule?, path?, reason (required), until? (YYYY-MM-DD)}; see docs/triage.md.
    allow: list[dict[str, Any]] = field(default_factory=list)

    # Security policies evaluated by ``nephilex policy check``.
    policies: list[dict[str, Any]] = field(default_factory=list)

    # Autonomy ladder (Rung 3): which deterministic fix rules may be applied
    # automatically by `nephilex fix --auto`. Fixes still land on a branch/PR (never
    # a direct push), so they stay trivially revertible. `graduate`/`demote` are
    # lists of full rule ids that add to / remove from the conservative built-in
    # auto set, so a team promotes rules to automatic one at a time.
    autofix: dict[str, Any] = field(default_factory=dict)

    # Project context from .nephilex/context.yml (sanitizers, trusted sources,
    # internal paths, exposure, data classification). Never read from
    # .nephilex.yml: load_project_config() sets it under the same trust rule as
    # the rest of the in-repo config. None means "not loaded"; the engine then
    # loads it itself only when trust_project_config is True.
    context: ProjectContext | None = None

    # Append fix and suppression events to .nephilex/audit.log (trusted local
    # projects only; the NEPHILEX_AUDIT_LOG=off environment variable also
    # disables it). See docs/audit-log.md.
    audit_log: bool = True

    # Also scan untracked files that git ignores. Off by default: in a git
    # work tree, untracked ignored files (build output, local virtual
    # environments) are skipped, and tracked files are always scanned.
    # CLI: --include-ignored.
    include_ignored: bool = False

    # Honour inline `nephilex-ignore` comments on trusted projects. Set only from
    # operator input (`nephilex check --no-inline-ignores`, which the AI
    # assistant hooks use so an agent cannot silence a finding by adding a
    # comment); config files never change it.
    inline_ignores: bool = True

    # Library mode for Python taint analysis: "auto" (on for a project with a
    # package manifest and no recognized web application entry point), "on" or
    # "off". In library mode the parameters of public functions are sources and
    # their findings are tagged public-api; see nephilex.analysis.library.
    library_mode: str = "auto"

    @classmethod
    def load(cls, path: str | Path | None = None, project_root: str | Path | None = None) -> Config:
        """Load config from an explicit path or by discovery in the project root."""
        data: dict[str, Any] = {}
        chosen: Path | None = None
        if path:
            chosen = Path(path)
            # An explicit --config path that doesn't exist must fail loudly. Falling
            # back to defaults here silently drops fail_on/allow gating, which in CI
            # means a typo'd path turns the security gate off without any signal.
            if not chosen.exists():
                raise ConfigFileNotFoundError(f"config file not found: {chosen}")
        elif project_root:
            for name in CONFIG_FILENAMES:
                candidate = Path(project_root) / name
                if candidate.exists():
                    chosen = candidate
                    break
        if chosen and chosen.exists():
            with open(chosen, encoding="utf-8") as fh:
                return cls.from_yaml(fh.read(), source=str(chosen))
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, text: str, *, source: str = "config") -> Config:
        """Parse YAML config text; any problem is a :class:`ConfigError`."""
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
        except RecursionError as exc:
            raise ConfigError(f"{source}: invalid YAML: nested too deeply") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(
                f"{source}: expected a mapping of settings at the top level, "
                f"got {type(data).__name__}"
            )
        try:
            return cls.from_dict(data)
        except ConfigError as exc:
            raise ConfigError(f"{source}: {exc}") from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config from parsed settings, validating every field's type.

        Values are checked strictly rather than coerced: ``list("dist/*")`` is a
        list of characters (and ``*`` then excludes every file), and
        ``bool("false")`` is True. Either would silently change what the scan
        covers, so a wrong type is a :class:`ConfigError` instead.
        """
        cfg = cls()
        cfg.scanners = _str_list(data, "scanners")
        cfg.exclude_scanners = _str_list(data, "exclude_scanners")
        cfg.exclude_paths = _str_list(data, "exclude_paths")
        cfg.attack_simulation = _bool(data, "attack_simulation", cfg.attack_simulation)
        cfg.generate_patches = _bool(data, "generate_patches", cfg.generate_patches)
        cfg.cache = _bool(data, "cache", cfg.cache)
        cfg.parallel = _bool(data, "parallel", cfg.parallel)
        cfg.audit_log = _bool(data, "audit_log", cfg.audit_log)
        cfg.include_ignored = _bool(data, "include_ignored", cfg.include_ignored)
        if data.get("fail_on_error") is not None:
            cfg.fail_on_error = _bool(data, "fail_on_error", False)
        cfg.library_mode = _library_mode(data.get("library_mode"), cfg.library_mode)

        options = _mapping(data, "scanner_options")
        for name, value in options.items():
            if not isinstance(value, dict):
                raise ConfigError(
                    f"scanner_options.{name}: expected a mapping, got {type(value).__name__}"
                )
        cfg.scanner_options = {str(k): dict(v) for k, v in options.items()}
        cfg.allow = _dict_list(data, "allow")
        cfg.policies = _dict_list(data, "policies")
        cfg.autofix = _mapping(data, "autofix")
        _check_test_settings(cfg.autofix)

        if data.get("min_severity") not in (None, ""):
            cfg.min_severity = _severity(data["min_severity"], "min_severity")
        if data.get("fail_on") not in (None, ""):
            cfg.fail_on = _severity(data["fail_on"], "fail_on")

        ai = _mapping(data, "ai")
        if ai:
            try:
                cfg.ai = AIConfig(
                    provider=str(ai.get("provider", cfg.ai.provider)),
                    model=ai.get("model", cfg.ai.model),
                    enabled=_bool(ai, "enabled", cfg.ai.enabled, prefix="ai."),
                    temperature=float(ai.get("temperature", cfg.ai.temperature)),
                    max_tokens=int(ai.get("max_tokens", cfg.ai.max_tokens)),
                    max_findings=_non_negative_int(
                        ai, "max_findings", cfg.ai.max_findings, prefix="ai."
                    ),
                )
            except (TypeError, ValueError) as exc:
                if isinstance(exc, ConfigError):
                    raise
                raise ConfigError(f"ai: {exc}") from exc
        return cfg

    def options_for(self, scanner_name: str) -> dict[str, Any]:
        return self.scanner_options.get(scanner_name, {})

    def errors_fail_gate(self, gating: bool) -> bool:
        """Whether scanner errors should fail this run.

        ``gating`` says whether the run has a pass/fail threshold at all (a
        fail_on severity, a policy check). An explicit ``fail_on_error``
        always wins; otherwise errors fail exactly the runs that gate.
        """
        if self.fail_on_error is not None:
            return self.fail_on_error
        return gating


def load_project_config(
    project: Project,
    explicit_config: str | Path | None = None,
    *,
    trust_remote: bool = False,
    config_from_ref: str | None = None,
) -> Config:
    """Load the configuration for scanning ``project``, with one trust decision.

    Every command goes through this so the rules are the same everywhere:

    * With ``config_from_ref`` the config is read from that git ref and the
      working tree is untrusted (see :func:`load_config_from_ref`).
    * An explicit ``--config`` file is always honored (the user chose it).
    * The project's own ``.nephilex.yml`` and its in-repo extension points
      (``.nephilex/rules``, ``.nephilex/exceptions.yml``, ``.nephilex/context.yml``,
      inline ``nephilex-ignore`` comments) are trusted only for local targets,
      or for a cloned remote when the user passes ``trust_remote``
      (``--trust-remote-config``). A cloned repository is
      attacker-controlled: its config could exclude every path, drop
      scanners, allowlist its own findings, or declare its own sinks
      sanitized.

    The returned config always carries a ``context``: the project's when
    trusted, the one at ``config_from_ref`` in that mode, otherwise empty.
    """
    from nephilex.context import ProjectContext, load_context

    if config_from_ref:
        if trust_remote:
            raise ConfigError(
                "--config-from-ref and --trust-remote-config cannot be combined: "
                "reading config from a ref means the checked-out tree is untrusted"
            )
        return load_config_from_ref(project.root, config_from_ref, explicit_config)
    trusted = project.origin == "local" or trust_remote
    cfg = Config.load(
        path=explicit_config,
        project_root=project.root if trusted else None,
    )
    cfg.trust_project_config = trusted
    cfg.context = load_context(project.root) if trusted else ProjectContext()
    return cfg


_GIT_TIMEOUT = 30
# A config file is small; anything larger than this is not read.
_MAX_CONFIG_BYTES = 1_000_000


def _git(root: Path, *args: str) -> gitexec.GitResult:
    """Run git for --config-from-ref through the hardened runner.

    The checked-out tree is treated as untrusted here, so the untrusted
    profile is used: the repository's config cannot launch programs.
    """
    try:
        res = gitexec.run(
            root,
            *args,
            profile=gitexec.UNTRUSTED,
            timeout=_GIT_TIMEOUT,
            max_output=_MAX_CONFIG_BYTES,
            capture_stderr=True,
        )
    except gitexec.GitNotFoundError as exc:
        raise ConfigError("--config-from-ref needs git, which was not found on PATH") from exc
    except gitexec.GitExecError as exc:
        raise ConfigError(f"git {args[0]} failed: {exc}") from exc
    if res.truncated:
        raise ConfigError(f"git {args[0]} output exceeded {_MAX_CONFIG_BYTES} bytes")
    return res


def _validate_ref(ref: str) -> str:
    ref = ref.strip()
    # A leading "-" would be parsed by git as an option; ":" would let the
    # value pick a different path than the config file; whitespace and
    # control characters are never part of a valid ref.
    if (
        not ref
        or ref.startswith("-")
        or ":" in ref
        or any(ch.isspace() or ord(ch) < 32 for ch in ref)
    ):
        raise ConfigError(f"invalid git ref for --config-from-ref: {ref!r}")
    return ref


def load_config_from_ref(
    project_root: str | Path,
    ref: str,
    explicit_config: str | Path | None = None,
) -> Config:
    """Read the config from a git ref, and mark the working tree untrusted.

    Meant for CI on pull requests: the checked-out tree is the contributor's
    code, so its ``.nephilex.yml`` must not decide how it is checked. Reading
    the file from the base branch (``origin/main``) keeps the gate under the
    maintainers' control. ``explicit_config``, if given, names the file to
    read at that ref (resolved against the current directory, and it must be
    inside the repository); otherwise ``.nephilex.yml`` / ``.nephilex.yaml`` next to
    the scanned directory are used, and a ref without either gives defaults.

    The returned config always has ``trust_project_config=False``, so the
    tree's ``.nephilex/rules``, ``.nephilex/exceptions.yml`` and inline
    ``nephilex-ignore`` comments are ignored too. The project context
    (``.nephilex/context.yml``) is read from the same ref, next to the scanned
    directory, so the base branch decides which sanitizers are trusted, never
    the pull request. Any problem (unknown ref, git missing, named file
    absent at the ref, invalid context file) is a :class:`ConfigError`.
    """
    root = Path(project_root)
    ref = _validate_ref(ref)
    proc = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
    commit = proc.stdout.strip()
    if proc.returncode != 0 or not commit:
        raise ConfigError(
            f"--config-from-ref: cannot resolve {ref!r} to a commit in {root} "
            "(fetch it first, e.g. `git fetch origin main`)"
        )

    candidates: list[str]
    if explicit_config:
        top = _git(root, "rev-parse", "--show-toplevel")
        if top.returncode != 0:
            raise ConfigError(f"--config-from-ref: {root} is not inside a git repository")
        toplevel = Path(top.stdout.strip()).resolve()
        wanted = Path(explicit_config).resolve()
        try:
            rel = wanted.relative_to(toplevel).as_posix()
        except ValueError as exc:
            raise ConfigError(
                f"--config {explicit_config} is outside the repository, so it "
                "cannot be read from a git ref"
            ) from exc
        candidates = [rel]
    else:
        # "./name" is resolved by git relative to the -C directory, so the
        # lookup matches discovery in the scanned directory.
        candidates = [f"./{name}" for name in CONFIG_FILENAMES]

    for spec in candidates:
        if _git(root, "cat-file", "-e", f"{commit}:{spec}").returncode != 0:
            continue
        # cat-file blob prints the stored bytes and never runs textconv or
        # other filters configured in the repository.
        blob = _git(root, "cat-file", "blob", f"{commit}:{spec}")
        if blob.returncode != 0:
            raise ConfigError(
                f"--config-from-ref: could not read {spec} at {ref}: {blob.stderr.strip()}"
            )
        cfg = Config.from_yaml(blob.stdout, source=f"{ref}:{spec.removeprefix('./')}")
        break
    else:
        if explicit_config:
            raise ConfigError(f"--config: {candidates[0]} does not exist at {ref}")
        cfg = Config()
    cfg.trust_project_config = False
    cfg.context = _context_from_ref(root, commit, ref)
    return cfg


def _context_from_ref(root: Path, commit: str, ref: str) -> ProjectContext:
    """The ``.nephilex/context.yml`` stored at ``commit``, or an empty context."""
    from nephilex.context import ProjectContext, parse_context
    from nephilex.context.schema import context_ref_paths

    for spec in context_ref_paths():
        if _git(root, "cat-file", "-e", f"{commit}:{spec}").returncode != 0:
            continue
        blob = _git(root, "cat-file", "blob", f"{commit}:{spec}")
        if blob.returncode != 0:
            raise ConfigError(
                f"--config-from-ref: could not read {spec} at {ref}: {blob.stderr.strip()}"
            )
        return parse_context(blob.stdout, source=f"{ref}:{spec.removeprefix('./')}")
    return ProjectContext()
