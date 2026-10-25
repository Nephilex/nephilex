"""Plugin contracts and the registry.

Nephilex is plugin-based end to end. The three extension points are:

* :class:`Scanner` analyzes a project and yields findings.
* :class:`Reporter` serializes a scan result to some format.
* :class:`AIProvider` talks to a language model (defined in :mod:`nephilex.ai.base`).

Plugins register themselves against a process-global :class:`Registry`. Built-in
plugins register on import; third-party packages register through the
``nephilex.plugins`` entry-point group declared in ``pyproject.toml``. Adding a new
language, scanner, or report format therefore never requires editing the core.

Built-in reporters and AI providers are imported lazily:
:func:`nephilex.plugins.register_builtins` adds a loader per kind with
:meth:`Registry.add_loader`, and the first lookup of that kind runs it. A
command that never looks up reporters or AI providers (``nephilex check``) does
not import them, or the HTTP clients they pull in.

Third-party code should import these names from :mod:`nephilex.plugin_api`, the
stable, versioned surface. Every plugin class carries an ``api_version``; the
registry skips (and logs) a plugin built for a different
:data:`PLUGIN_API_VERSION` instead of loading code written against an
incompatible contract.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from importlib import metadata
from typing import TYPE_CHECKING, Any, ClassVar

from nephilex.core.models import Finding, ScanResult

if TYPE_CHECKING:
    from nephilex.ai.base import AIProvider
    from nephilex.core.config import Config
    from nephilex.core.project import Project


#: Version of the plugin contract in :mod:`nephilex.plugin_api`. It is bumped only
#: when a change would break existing plugins (a removed or renamed name, a
#: changed method signature). Additive changes keep the same number.
PLUGIN_API_VERSION = 1

logger = logging.getLogger("nephilex.plugins")

# One scan of the installed distributions' entry points per process, keyed by
# the function that produced it (so a test that replaces it gets a new scan).
# Each scan reads every distribution's metadata, which costs tens of
# milliseconds; plugin discovery and CLI command discovery share it.
_ENTRY_POINT_SCAN: tuple[object, Any] | None = None


def plugin_entry_points(group: str) -> list[metadata.EntryPoint]:
    """The installed entry points of ``group``."""
    global _ENTRY_POINT_SCAN
    scan = metadata.entry_points
    if _ENTRY_POINT_SCAN is None or _ENTRY_POINT_SCAN[0] is not scan:
        _ENTRY_POINT_SCAN = (scan, scan())
    eps: Any = _ENTRY_POINT_SCAN[1]
    select = getattr(eps, "select", None)
    if select is not None:
        return list(select(group=group))
    return [ep for ep in eps if getattr(ep, "group", None) == group]


class PluginVersionError(ValueError):
    """A plugin declares a plugin API version this Nephilex does not implement."""


def _api_major(value: object) -> int | None:
    """The major part of a declared ``api_version``, or None if unreadable.

    ``api_version`` is an integer. A string such as ``"1"`` or ``"1.2"`` is
    tolerated and read as its leading major number.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        head = value.strip().split(".", 1)[0]
        if head.isdigit():
            return int(head)
    return None


def check_api_version(kind: str, cls: type) -> None:
    """Raise :class:`PluginVersionError` unless ``cls`` targets this plugin API."""
    declared = getattr(cls, "api_version", None)
    if _api_major(declared) != PLUGIN_API_VERSION:
        label = getattr(cls, "name", "") or cls.__name__
        raise PluginVersionError(
            f"{kind} plugin {label!r} ({cls.__module__}.{cls.__qualname__}) "
            f"declares plugin API version {declared!r}, but this Nephilex implements "
            f"version {PLUGIN_API_VERSION}. Install a release of the plugin built "
            "for this plugin API version."
        )


@dataclass(eq=False)
class ScannerContext:
    """Everything a scanner needs, passed in so scanners stay side-effect-light.

    ``eq=False`` keeps identity comparison and hashing, as before this became a
    dataclass.
    """

    project: Project
    config: Config
    ai: AIProvider | None = None
    #: The whole project when ``project`` is a narrower view of it (the files
    #: that missed the per-file cache), else None. A scanner that reads other
    #: files to analyze one (cross-file taint) looks them up here.
    scope: Project | None = None
    #: State shared by the scanners of one scan (for example the parsed Python
    #: files), keyed by a name the owner chooses. Scanners run on separate
    #: threads, so an entry must be safe to share.
    shared: dict[str, Any] = field(default_factory=dict)


class Scanner(abc.ABC):
    """Base class for a security scanner.

    Subclasses set :attr:`name` and :attr:`category` and implement :meth:`scan`.
    ``applies_to`` lets a scanner opt out cheaply (e.g. a Terraform scanner on a
    project with no ``.tf`` files) so the engine can skip it.
    """

    #: Plugin API version this class was written against. Leave the default:
    #: it is the version of :mod:`nephilex.plugin_api` the plugin was built with.
    api_version: ClassVar[int] = PLUGIN_API_VERSION

    #: Unique, stable identifier (used in config, CLI flags, and finding ids).
    name: ClassVar[str] = ""
    #: Human-readable grouping, e.g. "secrets", "sast", "dependencies", "iac".
    category: ClassVar[str] = "general"
    #: One-line description shown in `nephilex scanners`.
    description: ClassVar[str] = ""
    #: True if every finding depends only on the content of a single file.
    #: File-local scanners get per-file result caching: between runs, unchanged
    #: files reuse their cached findings and only changed files are re-analyzed.
    #: Leave False for anything cross-file (dependency resolution, future
    #: cross-file taint), a wrong True here silently serves stale findings.
    file_local: ClassVar[bool] = False

    def applies_to(self, project: Project) -> bool:  # noqa: D401
        """Return True if this scanner is relevant to the project. Default: yes."""
        return True

    def unavailable_reason(self, project: Project) -> str | None:
        """Why this scanner is skipped although the project has files for it.

        Return None when it is skipped only because there is nothing for it to
        scan. The engine shows the reason, so a missing optional dependency is
        not mistaken for an empty project.
        """
        return None

    def cacheable(self, ctx: ScannerContext) -> bool:
        """Whether findings may be served from the per-file cache for this run.

        Defaults to :attr:`file_local`. A scanner overrides this to opt out when
        a run's options make results time-dependent rather than a pure function
        of file content, e.g. live secret verification, which must re-check the
        credential every run.
        """
        return self.file_local

    def cache_salt(self, ctx: ScannerContext) -> Mapping[str, str]:
        """Extra per-file cache key material, by relative path.

        A file-local scanner whose findings for a file also depend on other
        files (a helper imported from another module) returns a digest of
        those files here, so editing one of them invalidates the entry.
        Default: nothing extra.
        """
        return {}

    @abc.abstractmethod
    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        """Analyze the project and yield findings."""
        raise NotImplementedError


class Reporter(abc.ABC):
    """Base class for a report format."""

    #: Plugin API version this class was written against (see :class:`Scanner`).
    api_version: ClassVar[int] = PLUGIN_API_VERSION
    name: ClassVar[str] = ""
    #: Default file extension (without the dot).
    extension: ClassVar[str] = "txt"
    description: ClassVar[str] = ""

    @abc.abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render a scan result to a string."""
        raise NotImplementedError


class Registry:
    """Process-global registry of plugins, keyed by name within each kind."""

    def __init__(self) -> None:
        self._scanners: dict[str, type[Scanner]] = {}
        self._reporters: dict[str, type[Reporter]] = {}
        self._ai_providers: dict[str, type[AIProvider]] = {}
        # Plugins skipped for an incompatible api_version: (kind, name) -> reason.
        self._rejected: dict[tuple[str, str], str] = {}
        self._loaded_entrypoints = False
        # Deferred registrations per kind, run on the first lookup of that kind.
        self._loaders: dict[str, list[Callable[[], object]]] = {
            "Scanner": [],
            "Reporter": [],
            "AIProvider": [],
        }

    # --- lazy built-ins -----------------------------------------------------
    def add_loader(self, kind: str, loader: Callable[[], object]) -> None:
        """Run ``loader`` (which registers plugins) before the first lookup of ``kind``.

        ``kind`` is ``"Scanner"``, ``"Reporter"`` or ``"AIProvider"``. Used for
        Nephilex's built-ins so importing the CLI does not import every scanner,
        report format and model client up front.
        """
        if kind not in self._loaders:
            raise ValueError(f"unknown plugin kind {kind!r}")
        self._loaders[kind].append(loader)

    def _load(self, kind: str) -> None:
        loaders = self._loaders[kind]
        while loaders:
            loaders.pop(0)()

    @staticmethod
    def _is_builtin(cls: type) -> bool:
        return cls.__module__.split(".", 1)[0] == "nephilex"

    def _claim(self, kind: str, table: dict[str, type], cls: type) -> bool:
        """Whether ``cls`` may take its name in ``table``; raises on a real clash.

        Built-ins are registered lazily, so a third-party plugin from an entry
        point can register first. A built-in still wins its own name: the
        third-party class is dropped and recorded as rejected, the same
        outcome as when the built-ins were registered at import time and the
        plugin's registration failed.
        """
        name = getattr(cls, "name", "")
        existing = table.get(name)
        if existing is None or existing is cls:
            return True
        if self._is_builtin(cls) and not self._is_builtin(existing):
            reason = (
                f"{kind} name {name!r} belongs to the built-in "
                f"{cls.__module__}.{cls.__qualname__}; "
                f"dropped {existing.__module__}.{existing.__qualname__}"
            )
            self._rejected[(kind, name)] = reason
            logger.warning("Skipping %s", reason)
            return True
        self._reject_collision(kind, name, existing, cls)
        return False  # pragma: no cover - _reject_collision raises

    # --- registration -------------------------------------------------------
    @staticmethod
    def _reject_collision(kind: str, name: str, existing: type, cls: type) -> None:
        """Refuse a different class claiming an already-registered plugin name.

        Idempotent re-registration of the *same* class is allowed so importing
        built-ins twice (or reloading a module) is harmless. A third-party
        plugin silently replacing ``patterns`` / ``json`` / ``heuristic`` is not.
        """
        if existing is not cls:
            raise ValueError(
                f"{kind} name {name!r} is already registered by "
                f"{existing.__module__}.{existing.__qualname__}; "
                f"refusing {cls.__module__}.{cls.__qualname__}"
            )

    def _accepts(self, kind: str, cls: type) -> bool:
        """Whether ``cls`` targets this plugin API; log and record it if not.

        A mismatch is not raised: the class is left unregistered so the rest of
        the plugin package, and the scan, carry on without it.
        """
        try:
            check_api_version(kind, cls)
        except PluginVersionError as exc:
            self._rejected[(kind, getattr(cls, "name", "") or cls.__name__)] = str(exc)
            logger.warning("Skipping %s", exc)
            return False
        return True

    def rejected(self) -> dict[tuple[str, str], str]:
        """Plugins skipped for an incompatible API version, with the reason."""
        return dict(self._rejected)

    def register_scanner(self, cls: type[Scanner]) -> type[Scanner]:
        if not cls.name:
            raise ValueError(f"Scanner {cls.__name__} must define a name")
        if not self._accepts("Scanner", cls):
            return cls
        if self._claim("Scanner", self._scanners, cls):
            self._scanners[cls.name] = cls
        return cls

    def register_reporter(self, cls: type[Reporter]) -> type[Reporter]:
        if not cls.name:
            raise ValueError(f"Reporter {cls.__name__} must define a name")
        if not self._accepts("Reporter", cls):
            return cls
        if self._claim("Reporter", self._reporters, cls):
            self._reporters[cls.name] = cls
        return cls

    def register_ai_provider(self, cls: type[AIProvider]) -> type[AIProvider]:
        if not cls.name:
            raise ValueError(f"AIProvider {cls.__name__} must define a name")
        if not self._accepts("AIProvider", cls):
            return cls
        if self._claim("AIProvider", self._ai_providers, cls):
            self._ai_providers[cls.name] = cls
        return cls

    # --- lookup -------------------------------------------------------------
    def scanners(self) -> dict[str, type[Scanner]]:
        self._ensure("Scanner")
        return dict(self._scanners)

    def reporters(self) -> dict[str, type[Reporter]]:
        self._ensure("Reporter")
        return dict(self._reporters)

    def ai_providers(self) -> dict[str, type[AIProvider]]:
        self._ensure("AIProvider")
        return dict(self._ai_providers)

    def get_scanner(self, name: str) -> type[Scanner]:
        self._ensure("Scanner")
        if name not in self._scanners:
            raise KeyError(
                self._skipped_reason("Scanner", name)
                or f"Unknown scanner: {name!r}. Available: {sorted(self._scanners)}"
            )
        return self._scanners[name]

    def get_reporter(self, name: str) -> type[Reporter]:
        self._ensure("Reporter")
        if name not in self._reporters:
            raise KeyError(
                self._skipped_reason("Reporter", name)
                or f"Unknown reporter: {name!r}. Available: {sorted(self._reporters)}"
            )
        return self._reporters[name]

    def get_ai_provider(self, name: str) -> type[AIProvider]:
        self._ensure("AIProvider")
        if name not in self._ai_providers:
            raise KeyError(
                self._skipped_reason("AIProvider", name)
                or f"Unknown AI provider: {name!r}. Available: {sorted(self._ai_providers)}"
            )
        return self._ai_providers[name]

    def _skipped_reason(self, kind: str, name: str) -> str | None:
        reason = self._rejected.get((kind, name))
        return f"{name!r} is installed but was skipped: {reason}" if reason else None

    # --- discovery ----------------------------------------------------------
    def _ensure(self, kind: str) -> None:
        """Built-ins of ``kind`` first, then third-party entry points (once)."""
        self._load(kind)
        self._ensure_entrypoints()

    def _ensure_entrypoints(self) -> None:
        """Load plugins declared under the ``nephilex.plugins`` entry-point group.

        Each entry point is a zero-arg callable that receives nothing and is
        expected to register its plugins as a side effect (via this registry).
        Failures in one plugin never abort discovery of the others.
        """
        if self._loaded_entrypoints:
            return
        self._loaded_entrypoints = True
        try:
            eps = plugin_entry_points("nephilex.plugins")
        except Exception:  # pragma: no cover - environment dependent
            return
        for ep in eps:
            try:
                from nephilex.plugins.signing import verify_plugin_entry

                if not verify_plugin_entry(ep):
                    import warnings

                    warnings.warn(f"Blocked untrusted Nephilex plugin {ep.name!r}", stacklevel=2)
                    continue
                register = ep.load()
                register()
            except Exception as exc:  # pragma: no cover - defensive
                import warnings

                warnings.warn(f"Failed to load Nephilex plugin {ep.name!r}: {exc}", stacklevel=2)


#: The shared registry every part of Nephilex talks to.
registry = Registry()


# Decorator sugar so plugin modules read cleanly.
def scanner(cls: type[Scanner]) -> type[Scanner]:
    return registry.register_scanner(cls)


def reporter(cls: type[Reporter]) -> type[Reporter]:
    return registry.register_reporter(cls)


def ai_provider(cls: type[AIProvider]) -> type[AIProvider]:
    return registry.register_ai_provider(cls)
