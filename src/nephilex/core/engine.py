"""The scan engine: orchestrates a full analysis.

Pipeline:

1. **Analyze**, build the project model (languages, frameworks, architecture).
2. **Scan**, run every applicable scanner, collecting findings.
3. **Enrich**, run agents over each finding (reasoning, attack simulation,
   patch generation) according to config.
4. **Assemble**, filter by severity, sort, and package into a ``ScanResult``.

The engine returns a ``ScanResult`` and never modifies scanned source. It
writes to Nephilex's own cache directory (disable with ``--no-cache``) and, for a
trusted local project where a suppression hid or accepted a finding, appends
those events once each to ``.nephilex/audit.log`` (disable with
``audit_log: false`` or ``NEPHILEX_AUDIT_LOG=off``). Reporting and PR creation
are separate steps.

Project context (``.nephilex/context.yml``) reaches the scanners through
``config.context``; the AST taint tiers use its sanitizers and trusted
sources, and the engine applies its path settings after de-duplication. See
:mod:`nephilex.context`.

Performance: scanners run concurrently (they are independent by design), and
file-local scanners cache findings per file content hash so warm scans only
re-analyze changed files. Both are on by default and both preserve Nephilex's
determinism guarantee, findings, ids, and ordering are identical with or
without cache and parallelism.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
import re
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING, Any, cast

from nephilex import __version__
from nephilex.analysis.repository import RepositoryAnalyzer
from nephilex.core.config import Config, ConfigError
from nephilex.core.models import Finding, ScanResult
from nephilex.core.plugin import Scanner, ScannerContext, registry
from nephilex.core.project import Project

if TYPE_CHECKING:
    from nephilex.ai.base import AIProvider
    from nephilex.audit import AuditEvent
    from nephilex.context import ProjectContext
    from nephilex.core.config import AIConfig

# A callback the CLI uses to render progress. No-op by default.
ProgressFn = Callable[[str], None]

log = logging.getLogger("nephilex.engine")

# Scanners that consume the project context's sanitizers and trusted sources,
# and the context language each one reads. Their scan-cache key includes that
# part of the context, so editing context.yml re-analyzes the affected files.
_CONTEXT_LANGUAGE = {"ast-python": "python", "ast-js": "javascript"}
_CONTEXT_CLEARED_KEY = "context_cleared"


def build_provider(cfg: AIConfig) -> AIProvider:
    """The configured AI provider (see :func:`nephilex.ai.factory.build_provider`).

    Imported on use: the provider modules pull in model SDK and HTTP client
    imports that a run without AI enrichment never needs.
    """
    from nephilex.ai.factory import build_provider as build

    return build(cfg)


class _DeferredProvider:
    """The configured AI provider, built the first time anything uses it.

    With AI enrichment off the engine never calls a model, but scanners still
    receive ``ctx.ai``. Building it on first attribute access keeps the model
    clients out of runs that never touch it (``nephilex check`` among them),
    while a scanner that does use ``ctx.ai`` gets the same provider as before.
    """

    def __init__(self, cfg: AIConfig) -> None:
        self._cfg = cfg
        self._provider: AIProvider | None = None
        self._lock = threading.Lock()

    def _get(self) -> AIProvider:
        with self._lock:
            if self._provider is None:
                self._provider = build_provider(self._cfg)
            return self._provider

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)


class ScanEngine:
    def __init__(self, config: Config, progress: ProgressFn | None = None) -> None:
        self.config = config
        self._progress = progress or (lambda _msg: None)

    def scan(self, project: Project) -> ScanResult:
        started = datetime.now(timezone.utc)
        result = ScanResult(
            target=str(project.root),
            started_at=started,
            nephilex_version=__version__,
        )

        # 1. Analyze
        self._progress("Analyzing project structure...")
        project = self._working_copy(project)
        RepositoryAnalyzer().analyze(project)
        result.project_summary = project.summary()
        library = self._library_mode(project)
        if library is not None:
            result.project_summary["library_mode"] = library.as_dict()

        # AI provider (shared by all agents). Falls back to heuristic if needed.
        ai = self._provider()

        # 2. Scan. Scanners are independent, so they run concurrently; results
        # are merged in selection order to keep output deterministic. File-local
        # scanners consult the per-file cache so unchanged files skip re-analysis.
        scanners, failed, select_errors = self._select_scanners(project)
        result.scanners_run = [s.name for s in scanners]
        result.errors.extend(select_errors)
        context = self._resolve_context(project)
        scan_config = self.config
        if context is not self.config.context:
            # The engine's own view of the config; the caller's object is not
            # changed (the same reason the Project is copied).
            scan_config = dataclasses.replace(self.config, context=context)
        scan_ctx = ScannerContext(project=project, config=scan_config, ai=ai)
        cache = self._open_cache(project)
        project.files()  # materialize the file walk once before threads share it

        def run_one(scanner: Scanner) -> tuple[list[Finding], str | None]:
            try:
                if cache is not None and scanner.cacheable(scan_ctx):
                    return self._scan_cached(scanner, scan_ctx, cache), None
                findings = list(scanner.scan(scan_ctx))
                # Renumber file-local scanners the same way the cached path does,
                # so finding ids are identical whether or not the cache is used.
                if scanner.file_local:
                    findings = self._renumber(scanner.name, findings)
                return findings, None
            except Exception as exc:  # a broken scanner must not sink the scan
                return [], f"scanner '{scanner.name}' failed: {exc}"

        for s in scanners:
            self._progress(f"Running scanner: {s.name}")
        if self.config.parallel and len(scanners) > 1:
            with ThreadPoolExecutor(max_workers=min(len(scanners), 8)) as pool:
                outcomes = list(pool.map(run_one, scanners))
        else:
            outcomes = [run_one(s) for s in scanners]
        for scanner, (findings, error) in zip(scanners, outcomes, strict=True):
            for finding in findings:
                result.add(finding)
            if error:
                result.errors.append(error)
                failed.append(scanner.name)
        if failed:
            result.scanners_failed = failed
            result.scanners_run = [n for n in result.scanners_run if n not in failed]
        if cache is not None:
            cache.save()
        return self._finish(result, project, ai, context)

    def postprocess(
        self,
        result: ScanResult,
        project: Project,
        *,
        ai: AIProvider | None = None,
        dedupe: Callable[[list[Finding]], list[Finding]] | None = None,
    ) -> ScanResult:
        """Run the post-scan pipeline on findings that came from elsewhere.

        For findings produced outside :meth:`scan` (for example imported from
        another tool's SARIF), apply exactly what a scan applies after its
        scanners ran, in the same order: inline ``nephilex-ignore`` comments and
        exceptions (trusted projects only), the allowlist, AST preference and
        de-duplication, project context (``internal_paths``, ``exposure``,
        ``data_classification``), attack chains, the ``min_severity`` filter,
        enrichment, risk scoring, and the audit log's suppression events.
        Findings under ``exclude_paths`` are dropped first, since a scan never
        reads those files; placeholder locations such as ``(image)`` are kept.
        ``result.findings`` is replaced and the same ``result`` is returned.
        ``ai`` defaults to the configured provider when enrichment is on.

        ``dedupe``, when given, replaces the engine's cross-scanner
        de-duplication step; the SARIF importer uses it to fold duplicates
        into another finding and record who else reported them.
        """
        if ai is None:
            ai = self._provider()
        project = self._working_copy(project)
        result.findings = [
            f
            for f in result.findings
            if f.location.path.startswith("(") or not project._excluded(f.location.path)
        ]
        return self._finish(result, project, ai, self._resolve_context(project), dedupe=dedupe)

    def _finish(
        self,
        result: ScanResult,
        project: Project,
        ai: AIProvider,
        context: ProjectContext | None,
        *,
        dedupe: Callable[[list[Finding]], list[Finding]] | None = None,
    ) -> ScanResult:
        """Everything after the scanners ran; shared by scan() and postprocess()."""
        audit_events: list[AuditEvent] = []

        # Flows a context sanitizer or trusted source cleared come back from the
        # taint tiers as placeholders; they leave the findings here and are
        # listed in the summary so the effect of context.yml stays reviewable.
        cleared = [f for f in result.findings if _CONTEXT_CLEARED_KEY in f.metadata]
        if cleared:
            result.findings = [f for f in result.findings if _CONTEXT_CLEARED_KEY not in f.metadata]

        # 3. Prefer AST over regex where the AST tier is authoritative, de-duplicate
        # across scanners, filter, then enrich. Filtering first means agents (and any
        # paid model calls they make) only run on findings we will actually report.
        # Inline `nephilex-ignore` comments and .nephilex/exceptions.yml live inside the
        # scanned tree, so for an untrusted target they are written by whoever
        # controls that tree. Honor them only when the project is trusted;
        # otherwise a hostile repository could suppress its own findings.
        trusted = self.config.trust_project_config
        if trusted and self.config.inline_ignores:
            result.findings = self._apply_inline_suppressions(
                result.findings, project, events=audit_events
            )
        result.findings = self._apply_allowlist(result.findings, self.config, events=audit_events)
        result.findings = self._prefer_ast(result.findings, result.scanners_run)
        result.findings = (dedupe or self._dedupe)(result.findings)
        # Path-based context (internal paths, exposure, data classification)
        # adjusts severity/likelihood and records why on each finding.
        from nephilex.context import apply_context

        context_counts = apply_context(result.findings, context)
        if context is not None and (not context.is_empty() or cleared):
            result.project_summary["context"] = {
                "source": context.source or ".nephilex/context.yml",
                "digest": context.digest(),
                **context_counts,
                "cleared": [f.metadata[_CONTEXT_CLEARED_KEY] for f in cleared],
            }
        # Correlate the surviving findings into higher-impact attack chains, then
        # apply the severity filter to findings and chains together.
        from nephilex.analysis.attack_chains import find_chains

        result.findings.extend(c.to_finding() for c in find_chains(result.findings))
        result.findings = self._filter(result.findings)
        if self.config.ai.enabled:
            self._run_agents(result, project, ai)
        elif self.config.generate_patches:
            self._deterministic_patches(result)

        from nephilex.analysis.risk_engine import enrich_contextual_risk
        from nephilex.analysis.security_graph import build_security_graph
        from nephilex.analysis.verification import apply_verification_states
        from nephilex.core.evidence import attach_evidence
        from nephilex.exceptions import apply_exceptions, default_exceptions_path, load_exceptions
        from nephilex.observability.metrics import MetricsTimer, ScanMetrics

        timer = MetricsTimer()
        # Evidence first: its "confirmed" grade must see only the verification
        # states that scanners and verifiers recorded, not the defaults that
        # apply_verification_states fills in from confidence.
        attach_evidence(result.findings)
        apply_verification_states(result.findings)
        enrich_contextual_risk(result)
        result.project_summary["security_graph"] = build_security_graph(result)
        if trusted:
            excs = load_exceptions(default_exceptions_path(project.root))
            before = list(result.findings)
            result.findings, suppressed = apply_exceptions(result.findings, excs)
            if suppressed:
                result.project_summary["exceptions_applied"] = suppressed
            audit_events.extend(self._exception_events(excs, before))
        result.project_summary["metrics"] = ScanMetrics(
            scanners_run=result.scanners_run,
            findings_total=len(result.findings),
            duration_ms=timer.elapsed_ms(),
        ).to_dict()

        self._write_audit(project, audit_events, result)

        # 4. Assemble
        result.findings = result.sorted_findings()
        result.finished_at = datetime.now(timezone.utc)
        self._progress(
            f"Done: {len(result.findings)} finding(s), "
            f"highest severity {result.highest_severity().label}."
        )
        return result

    def _provider(self) -> AIProvider:
        """The AI provider for this run; deferred when enrichment is off."""
        if not self.config.ai.enabled:
            self._progress("AI enrichment: off")
            return cast("AIProvider", _DeferredProvider(self.config.ai))
        ai = build_provider(self.config.ai)
        self._progress(f"AI provider: {ai.name}" + ("" if ai.is_remote else " (local / offline)"))
        return ai

    # --- caching --------------------------------------------------------------
    def _open_cache(self, project: Project):
        """Open the per-project scan cache, or None when caching is off.

        Remote targets are cloned to a fresh temp dir every run, so a cache
        keyed on that path could never hit, skip it rather than litter the
        cache directory.
        """
        if not self.config.cache or project.origin != "local":
            return None
        from nephilex.core.cache import ScanCache

        try:
            return ScanCache(project.root, __version__)
        except Exception:  # cache trouble must never break a scan
            return None

    def _scan_cached(self, scanner: Scanner, ctx: ScannerContext, cache) -> list[Finding]:
        """Run a file-local scanner, reusing cached findings for unchanged files.

        Unchanged files (matched by content hash) contribute their cached
        findings; only changed/new files are re-scanned, via a filtered view of
        the project. Zero-finding files are cached too, that is most files.
        """
        from nephilex.core.cache import file_key, scanner_key

        options = dict(self.config.options_for(scanner.name))
        language = _CONTEXT_LANGUAGE.get(scanner.name)
        context = getattr(ctx.config, "context", None)
        if language and context is not None:
            digest = context.language_digest(language)
            if digest:
                options["__context__"] = digest
        if scanner.name == "ast-python":
            library = self._library_mode(ctx.project)
            if library is not None and library.active:
                options["__library_mode__"] = True  # different sources, different findings
        skey = scanner_key(scanner.name, options)
        files = ctx.project.files()
        keys = {f.rel_path: file_key(f.rel_path, f.text()) for f in files}

        hits: list[Finding] = []
        misses = []
        for f in files:
            cached = cache.lookup(skey, keys[f.rel_path])
            if cached is None:
                misses.append(f)
            else:
                hits.extend(cached)

        fresh: list[Finding] = []
        if misses:
            import copy

            subset = copy.copy(ctx.project)
            subset._files_cache = tuple(misses)
            sub_ctx = ScannerContext(project=subset, config=ctx.config, ai=ctx.ai)
            fresh = list(scanner.scan(sub_ctx))
            by_file: dict[str, list[Finding]] = {f.rel_path: [] for f in misses}
            for finding in fresh:
                by_file.setdefault(finding.location.path, []).append(finding)
            for f in misses:
                cache.store(skey, keys[f.rel_path], by_file.get(f.rel_path, []))
        cache.prune(skey, set(keys.values()))
        return self._renumber(scanner.name, hits + fresh)

    @staticmethod
    def _renumber(scanner_name: str, findings: list[Finding]) -> list[Finding]:
        """Re-assign per-scan counters in ``scanner:rule:N`` ids after a cache merge.

        Scanners allocate those counters in (file, line) order during a full
        scan; sorting the merged cached+fresh findings the same way and
        renumbering makes ids match what an uncached scan produces, keeping
        ids unique and reports reproducible. Ids keyed by path/line (taint and
        AST findings) are already stable and pass through untouched.
        """
        findings.sort(key=lambda f: (f.location.path, f.location.start_line or 0, f.rule_id, f.id))
        pattern = re.compile(rf"^{re.escape(scanner_name)}:([^:]+):(\d+)$")
        counter = 0
        for f in findings:
            m = pattern.match(f.id)
            if m:
                counter += 1
                f.id = f"{scanner_name}:{m.group(1)}:{counter}"
        return findings

    # --- steps --------------------------------------------------------------
    def _working_copy(self, project: Project) -> Project:
        """The engine's own copy of the caller's project, with config applied.

        The scan sets ``extra_ignores`` from ``exclude_paths`` and the analyzer
        fills in languages, frameworks, architecture and metadata. Doing that
        on the caller's object would leak one scan's config into the next use
        of the same Project (another engine, another config), so the engine
        works on a copy. Mutable containers are copied too, and the cached file
        list is reused only when the ignore globs and ``include_ignored`` are
        unchanged.
        """
        ignores = tuple(self.config.exclude_paths)
        include_ignored = self.config.include_ignored
        keep_files = ignores == project.extra_ignores and include_ignored == project.include_ignored
        return dataclasses.replace(
            project,
            extra_ignores=ignores,
            include_ignored=include_ignored,
            languages=dict(project.languages),
            frameworks=list(project.frameworks),
            architecture=dict(project.architecture),
            metadata=dict(project.metadata),
            _files_cache=project._files_cache if keep_files else None,
        )

    def _select_scanners(self, project: Project) -> tuple[list[Scanner], list[str], list[str]]:
        """Pick the scanners to run.

        Returns ``(selected, failed_names, errors)``. An explicitly requested
        scanner name that does not exist is a :class:`ConfigError`: silently
        skipping it (``--scanners secret`` for ``secrets``) used to run nothing
        and pass the gate. Excluding every requested scanner is an error for
        the same reason. A scanner whose ``applies_to`` check crashes (for
        example on a malformed manifest in a hostile repository) is recorded
        as a failed scanner instead of aborting the whole scan.
        """
        available = registry.scanners()
        chosen_names = list(dict.fromkeys(self.config.scanners)) or list(available)
        unknown = [n for n in chosen_names if n not in available]
        if unknown:
            raise ConfigError(
                f"unknown scanner(s): {', '.join(unknown)} "
                f"(available: {', '.join(sorted(available))})"
            )
        for name in self.config.exclude_scanners:
            if name not in available:
                self._progress(f"Ignoring unknown scanner '{name}' in exclusions.")
        names = [n for n in chosen_names if n not in self.config.exclude_scanners]
        if not names:
            raise ConfigError("no scanners selected: every requested scanner is excluded")
        selected: list[Scanner] = []
        failed: list[str] = []
        errors: list[str] = []
        for name in names:
            instance = available[name]()
            try:
                applies = instance.applies_to(project)
            except Exception as exc:  # a broken check must not sink the scan
                failed.append(name)
                errors.append(f"scanner '{name}' failed: {exc}")
                continue
            if applies:
                selected.append(instance)
            else:
                try:
                    reason = instance.unavailable_reason(project)
                except Exception:  # a broken hint must not sink the scan
                    reason = None
                self._progress(f"Skipping scanner '{name}' ({reason or 'not applicable'}).")
        return selected, failed, errors

    def _run_agents(self, result: ScanResult, project: Project, ai: AIProvider) -> None:
        from nephilex.agents import AgentContext, AttackSimulationAgent, EnrichmentAgent, PatchAgent

        agent_ctx = AgentContext(project=project, config=self.config, ai=ai)
        enrichment = EnrichmentAgent()
        simulator = AttackSimulationAgent()
        patcher = PatchAgent()

        # Each finding can cost up to three sequential model calls, so with a
        # real model only the highest-risk findings go to it (ai.max_findings).
        # The rest get the offline heuristic treatment, so every finding still
        # has reasoning and a big result set cannot stall CI for hours. The
        # heuristic provider itself is fast and local, so it is not capped.
        model_ids: set[int] | None = None
        fallback_ctx = agent_ctx
        if ai.name != "heuristic":
            from nephilex.ai.heuristic import HeuristicProvider

            ranked = sorted(
                range(len(result.findings)), key=lambda i: -result.findings[i].risk_score()
            )
            model_ids = set(ranked[: self.config.ai.max_findings])
            fallback_ctx = AgentContext(project=project, config=self.config, ai=HeuristicProvider())
            skipped = len(result.findings) - len(model_ids)
            if skipped:
                self._progress(
                    f"AI enrichment limited to the top {len(model_ids)} finding(s) "
                    f"by risk; {skipped} use offline reasoning (ai.max_findings)."
                )

        total = len(result.findings)
        for i, finding in enumerate(result.findings, start=1):
            self._progress(f"Enriching findings ({i}/{total})...")
            ctx = agent_ctx if model_ids is None or i - 1 in model_ids else fallback_ctx
            enrichment.process(finding, ctx)
            if self.config.attack_simulation:
                simulator.process(finding, ctx)
            if self.config.generate_patches:
                patcher.process(finding, ctx)

    def _deterministic_patches(self, result: ScanResult) -> None:
        """Attach Nephilex's deterministic, verified fixes when AI enrichment is off.

        ``--patches`` asks for fixes and ``--no-ai`` for no model; the
        rewrites in :mod:`nephilex.remediation.rewrites` need neither the
        provider nor the other agents, so they are attached regardless. Only
        findings a rewrite actually changes are touched, so the rest keep
        exactly the remediation their scanner gave them. This path imports
        neither the agents nor a model client, so ``nephilex check`` stays fast.
        """
        from nephilex.remediation.patches import attach_deterministic_patch

        for finding in result.findings:
            attach_deterministic_patch(finding)

    def _filter(self, findings: list[Finding]) -> list[Finding]:
        """Apply ``min_severity``, judged on the severity before any context downgrade.

        A finding the context file lowered (``internal_paths``) is never hidden
        by that: it stays in the report at its lowered severity.
        """
        from nephilex.context.apply import original_severity

        floor = self.config.min_severity
        return [f for f in findings if max(f.severity, original_severity(f)) >= floor]

    # --- project context and audit ------------------------------------------
    def _resolve_context(self, project: Project) -> ProjectContext | None:
        """The project context for this scan.

        ``load_project_config`` sets ``config.context`` under the trust rule
        (trusted tree, or the ``--config-from-ref`` ref). A config built some
        other way carries None; the context file is then read from the tree
        only when the project config is trusted, like ``.nephilex/exceptions.yml``.
        """
        if self.config.context is not None:
            return self.config.context
        if not self.config.trust_project_config:
            return None
        from nephilex.context import load_context

        return load_context(project.root)

    def _audit_allowed(self, project: Project) -> bool:
        from nephilex.audit import audit_enabled

        return (
            audit_enabled(self.config)
            and self.config.trust_project_config
            and project.origin == "local"
        )

    def _write_audit(self, project: Project, events: list[AuditEvent], result: ScanResult) -> None:
        """Append suppression events; trouble is a warning, never a failed scan."""
        if not events or not self._audit_allowed(project):
            return
        from nephilex.audit import AUDIT_PATH, append_events

        outcome = append_events(project.root, events)
        summary: dict[str, Any] = {
            "path": AUDIT_PATH,
            "recorded": outcome.written,
            "already_recorded": outcome.duplicates,
        }
        if outcome.warning:
            summary["warning"] = outcome.warning
            log.warning("%s", outcome.warning)
            self._progress(f"Warning: {outcome.warning}")
        result.project_summary["audit"] = summary

    @staticmethod
    def _exception_events(excs: list, before: list[Finding]) -> list[AuditEvent]:
        """Audit events for ``.nephilex/exceptions.yml``: each entry, and each match."""
        from nephilex.audit import suppression_added, suppression_matched

        events: list[AuditEvent] = []
        for ex in excs:
            events.append(
                suppression_added(
                    "exception",
                    f"fingerprint {ex.fingerprint}",
                    ex.reason,
                    status=ex.status,
                    owner=ex.owner,
                    expires_at=str(ex.expires_at) if ex.expires_at else None,
                )
            )
        for f in before:
            meta = f.metadata.get("exception")
            if not isinstance(meta, dict):
                continue
            events.append(
                suppression_matched(
                    "exception",
                    f,
                    str(meta.get("reason", "")),
                    status=meta.get("status"),
                    owner=meta.get("owner"),
                )
            )
        return events

    # Inline suppression comment, e.g.
    #   subprocess.run(cmd, shell=True)  # nephilex-ignore: python-shell-true reason="trusted"
    # The `reason` is required (so suppressions are documented). The rule id is
    # optional; without it every finding on the line is suppressed. An optional
    # `until=YYYY-MM-DD` makes the suppression expire so accepted risk resurfaces.
    # `#` and `//` comments are accepted in every file; the comment styles of
    # other languages only in files of that type (_INLINE_MARKERS), so a `;` or
    # `--` that is code elsewhere never starts a suppression.
    _INLINE_BODY = r"""\s*nephilex-ignore
            (?::\s*(?P<rule>[A-Za-z0-9_.\-]+))?
            [^\n]*?reason\s*=\s*['"](?P<reason>[^'"]+)['"]
            (?:[^\n]*?until\s*=\s*(?P<until>\d{4}-\d{2}-\d{2}))?
        """
    _INLINE_IGNORE = re.compile(r"(?:\#|//)" + _INLINE_BODY, re.VERBOSE)
    # Extra comment openers by file suffix (lower case).
    _INLINE_MARKERS: dict[str, tuple[str, ...]] = {
        # -- line comments: SQL, Lua, Haskell
        ".sql": ("--",),
        ".lua": ("--",),
        ".hs": ("--",),
        # <!-- --> comments: HTML, XML, Markdown
        ".html": ("<!--",),
        ".htm": ("<!--",),
        ".xhtml": ("<!--",),
        ".xml": ("<!--",),
        ".md": ("<!--",),
        ".markdown": ("<!--",),
        # ; line comments: INI, Lisp dialects
        ".ini": (";",),
        ".lisp": (";",),
        ".lsp": (";",),
        ".el": (";",),
        ".clj": (";",),
    }
    _INLINE_BY_SUFFIX: dict[str, re.Pattern[str]] = {}

    @classmethod
    def _inline_pattern(cls, path: str) -> re.Pattern[str]:
        """The nephilex-ignore pattern for a file, chosen by its suffix."""
        name = path.rsplit("/", 1)[-1].lower()
        suffix = name[name.rfind(".") :] if "." in name else ""
        extra = cls._INLINE_MARKERS.get(suffix)
        if not extra:
            return cls._INLINE_IGNORE
        pattern = cls._INLINE_BY_SUFFIX.get(suffix)
        if pattern is None:
            openers = "|".join(re.escape(m) for m in ("#", "//", *extra))
            pattern = re.compile(f"(?:{openers})" + cls._INLINE_BODY, re.VERBOSE)
            cls._INLINE_BY_SUFFIX[suffix] = pattern
        return pattern

    @staticmethod
    def _rule_matches(rule_id: str, target: str) -> bool:
        """A suppression rule id matches by full id, short id, or last segment."""
        return (
            rule_id == target or rule_id.endswith("." + target) or rule_id.split(".")[-1] == target
        )

    @classmethod
    def _apply_inline_suppressions(
        cls,
        findings: list[Finding],
        project: Project,
        *,
        events: list[AuditEvent] | None = None,
    ) -> list[Finding]:
        """Drop findings whose source line carries a matching nephilex-ignore comment.

        When ``events`` is given, each suppression is added to it as audit
        events (the comment, and the finding it hid).
        """
        needed = {f.location.path for f in findings if f.location.start_line is not None}
        lines_by_path: dict[str, list[str]] = {
            fref.rel_path: fref.lines() for fref in project.files() if fref.rel_path in needed
        }
        today = datetime.now(timezone.utc).date()
        kept: list[Finding] = []
        for finding in findings:
            line_no = finding.location.start_line
            lines = lines_by_path.get(finding.location.path)
            if line_no is None or lines is None or not 1 <= line_no <= len(lines):
                kept.append(finding)
                continue
            m = cls._inline_pattern(finding.location.path).search(lines[line_no - 1])
            if m is None:
                kept.append(finding)
                continue
            until = m.group("until")
            if until:
                try:
                    if date.fromisoformat(until) < today:
                        kept.append(finding)  # suppression expired: resurface it
                        continue
                except ValueError:
                    kept.append(finding)  # malformed date: do not suppress
                    continue
            rule = m.group("rule")
            if rule and not cls._rule_matches(finding.rule_id, rule):
                kept.append(finding)
                continue
            # otherwise: suppressed, drop it
            if events is not None:
                from nephilex.audit import suppression_added, suppression_matched

                reason = m.group("reason")
                path = finding.location.path
                events.append(
                    suppression_added(
                        "inline",
                        f"nephilex-ignore{':' + rule if rule else ''} in {path}",
                        reason,
                        rule=rule,
                        path=path,
                        until=until,
                    )
                )
                events.append(
                    suppression_matched(
                        "inline", finding, reason, selector=rule or "*", until=until
                    )
                )
        return kept

    @classmethod
    def _apply_allowlist(
        cls,
        findings: list[Finding],
        config: Config,
        *,
        events: list[AuditEvent] | None = None,
    ) -> list[Finding]:
        """Drop findings matched by a committed allowlist entry (config ``allow:``).

        Each entry is {rule?, path?, reason (required), until? (YYYY-MM-DD)}. A
        `reason` is required so acceptance is documented; an entry with neither a
        rule nor a path is rejected (it would suppress everything); an expired
        `until` no longer suppresses, so the finding resurfaces. When
        ``events`` is given, each active entry and each finding it hides are
        added to it as audit events.
        """
        entries = getattr(config, "allow", None)
        if not entries:
            return findings
        today = datetime.now(timezone.utc).date()
        active: list[dict] = []
        for e in entries:
            if not e.get("reason") or (not e.get("rule") and not e.get("path")):
                continue
            until = e.get("until")
            if until:
                try:
                    if date.fromisoformat(str(until)) < today:
                        continue
                except ValueError:
                    continue
            active.append(e)
        if not active:
            return findings
        if events is None:
            return [f for f in findings if not any(cls._allow_matches(f, e) for e in active)]
        from nephilex.audit import suppression_added, suppression_matched

        def selector(entry: dict) -> str:
            parts = [f"{k}={entry[k]}" for k in ("rule", "path", "until") if entry.get(k)]
            return "allow " + " ".join(parts)

        for e in active:
            events.append(
                suppression_added(
                    "allowlist",
                    selector(e),
                    str(e["reason"]),
                    rule=str(e["rule"]) if e.get("rule") else None,
                    path=str(e["path"]) if e.get("path") else None,
                )
            )
        kept: list[Finding] = []
        for f in findings:
            match = next((e for e in active if cls._allow_matches(f, e)), None)
            if match is None:
                kept.append(f)
                continue
            events.append(
                suppression_matched("allowlist", f, str(match["reason"]), selector=selector(match))
            )
        return kept

    @classmethod
    def _allow_matches(cls, finding: Finding, entry: dict) -> bool:
        rule = entry.get("rule")
        if rule and not cls._rule_matches(finding.rule_id, str(rule)):
            return False
        path = entry.get("path")
        if path:
            path = str(path)
            p = finding.location.path or ""
            name = p.rsplit("/", 1)[-1]
            if not (
                fnmatch.fnmatch(p, path)
                or fnmatch.fnmatch(name, path)
                or (path.endswith("/**") and p.startswith(path[:-2]))
            ):
                return False
        return True

    # Vulnerability classes the AST taint tiers analyze authoritatively via data
    # flow. Where an AST scanner ran over a file, the regex tier's guesses for these
    # classes are redundant (the AST tier already confirmed or cleared them), so
    # they are dropped to avoid false positives like flagging a sanitized innerHTML.
    #
    # Note: CWE-78 (command injection) is intentionally NOT here. The regex tier's
    # command-injection rules flag taint-independent smells such as
    # `subprocess(..., shell=True)` and `os.system(<dynamic>)`, which are dangerous
    # regardless of whether a tracked taint source reaches them, so the AST tier's
    # silence must not suppress them. Genuinely tainted cases where both tiers fire
    # are still collapsed by _dedupe, so this does not double-report.
    _AST_OWNED_CWE = {"CWE-89", "CWE-79", "CWE-22", "CWE-95"}
    _AST_LANG_EXT = {
        "ast-python": (".py",),
        "ast-js": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    }

    @classmethod
    def _prefer_ast(cls, findings: list[Finding], scanners_run: list[str]) -> list[Finding]:
        covered_ext = tuple(
            ext for name, exts in cls._AST_LANG_EXT.items() if name in scanners_run for ext in exts
        )
        if not covered_ext:
            return findings
        out: list[Finding] = []
        for f in findings:
            redundant = (
                f.scanner == "patterns"
                and any(c in cls._AST_OWNED_CWE for c in f.cwe)
                and f.location.path.endswith(covered_ext)
            )
            if not redundant:
                out.append(f)
        return out

    # Two different tiers reporting the same weakness within this many lines are
    # treated as one (e.g. the regex tier flags an unsafe query where it is built,
    # the AST tier flags it where it is executed a line later).
    _DEDUPE_WINDOW = 3

    @classmethod
    def _dedupe(cls, findings: list[Finding]) -> list[Finding]:
        """Collapse the same weakness reported by more than one scanner.

        When the regex ``patterns`` tier and the AST ``ast-python`` tier both catch
        one injection, often a line or two apart (construction vs. execution),
        keep the higher-confidence (then higher-severity) finding so the report is
        not doubled. On a tie, keep the finding that has a deterministic fix (so
        the verified patch is not lost), then the AST tier's, then the lower rule
        id: the choice never depends on the order scanners ran in, so ``scan`` and
        ``check`` agree. Only merges findings from *different* scanners with the
        same CWE in the same file within a small line window, so distinct issues
        and within-tier findings are preserved. Findings with no line or CWE pass
        through. A kept finding without a recorded data-flow path takes over the
        one the merged finding traced (evidence only; nothing else changes).
        """
        from nephilex.core.evidence import carry_path
        from nephilex.remediation.rewrites import has_rewrite

        def rank(f: Finding) -> tuple[Any, ...]:
            return (f.confidence, f.severity, has_rewrite(f.rule_id), f.scanner.startswith("ast-"))

        passthrough = [f for f in findings if f.location.start_line is None or not f.cwe]
        mergeable = [f for f in findings if f.location.start_line is not None and f.cwe]
        mergeable.sort(
            key=lambda f: (f.location.path, tuple(sorted(f.cwe)), f.location.start_line or 0)
        )
        kept: list[Finding] = []
        for f in mergeable:
            prev = kept[-1] if kept else None
            if (
                prev is not None
                and prev.scanner != f.scanner
                and prev.location.path == f.location.path
                and sorted(prev.cwe) == sorted(f.cwe)
                and (f.location.start_line or 0) - (prev.location.start_line or 0)
                <= cls._DEDUPE_WINDOW
            ):
                # f wins on rank, or on a full tie by having the lower rule id.
                if (rank(f), prev.rule_id) > (rank(prev), f.rule_id):
                    carry_path(f, prev)
                    kept[-1] = f
                else:
                    carry_path(prev, f)
                continue
            kept.append(f)
        return passthrough + kept

    # --- CI gating helper ---------------------------------------------------
    def fails_on_errors(self, result: ScanResult) -> bool:
        """True when scanner errors in ``result`` must fail the run."""
        gating = self.config.fail_on is not None
        return bool(result.errors) and self.config.errors_fail_gate(gating)

    def should_fail(self, result: ScanResult) -> bool:
        """Whether the run fails its gate.

        Library-mode findings (tagged ``public-api``) never fail ``fail_on``:
        their input is a public function's argument, so whether they are
        exploitable depends on how callers outside the project use the API.
        They are still reported, and ``min_severity`` still filters them.
        """
        if self.fails_on_errors(result):
            return True
        if self.config.fail_on is None:
            return False
        return result.gating_severity() >= self.config.fail_on

    def _library_mode(self, project: Project):
        """The library-mode decision for a Python project, or None without Python."""
        if not any(f.language == "Python" for f in project.files()):
            return None
        from nephilex.analysis.library import library_mode_for

        return library_mode_for(project, self.config.library_mode)
