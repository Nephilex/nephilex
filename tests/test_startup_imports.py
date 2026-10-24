"""Start-up stays light: the CLI imports scanners, reporters and model clients on use."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.plugin import Registry, Scanner

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _modules_after(code: str, cwd: Path | None = None) -> set[str]:
    """Run ``code`` in a fresh interpreter and return the modules it imported."""
    script = textwrap.dedent(code) + "\nimport json, sys\nprint(json.dumps(sorted(sys.modules)))\n"
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
        cwd=cwd,
        env={**_env(), "PYTHONPATH": SRC},
    )
    return set(json.loads(out.stdout.strip().splitlines()[-1]))


def _env() -> dict[str, str]:
    import os

    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def test_importing_the_cli_does_not_import_reporters_or_http_clients() -> None:
    loaded = _modules_after("import nephilex.cli.app")
    for heavy in ("httpx", "nephilex.reporting", "nephilex.ai.ollama_provider", "rich.table"):
        assert heavy not in loaded, heavy


def test_nephilex_check_does_not_import_http_clients_or_reporters(tmp_path: Path) -> None:
    (tmp_path / ".nephilex.yml").write_text("{}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import yaml\nyaml.load(s)\n", encoding="utf-8")
    loaded = _modules_after(
        """
        from typer.testing import CliRunner
        from nephilex.cli.main import app
        res = CliRunner().invoke(app, ["check", "app.py", "-q", "--no-cache"])
        assert res.exit_code == 1, res.output
        assert "python-yaml-load" in res.output
        """,
        cwd=tmp_path,
    )
    assert "nephilex.scanners" in loaded
    for heavy in ("httpx", "nephilex.reporting", "nephilex.ai.ollama_provider", "nephilex.agents"):
        assert heavy not in loaded, heavy


def test_supply_chain_imports_httpx_only_for_a_network_fetch() -> None:
    loaded = _modules_after(
        """
        import nephilex.supply_chain
        import nephilex.supply_chain.behavior
        import nephilex.supply_chain.intel
        import nephilex.supply_chain.sandbox
        import nephilex.scanners.supply_chain
        from nephilex.supply_chain.intel import is_malicious, typosquat_risk
        is_malicious("npm", "left-pad", online=False)
        typosquat_risk("reqeusts")
        """
    )
    assert "nephilex.supply_chain.intel" in loaded
    assert "httpx" not in loaded


def test_nephilex_scanners_lists_every_builtin() -> None:
    from nephilex.core.plugin import registry

    res = CliRunner().invoke(app, ["scanners"])
    assert res.exit_code == 0, res.output
    names = list(registry.scanners())
    assert len(names) >= 20
    for name in names:
        assert name in res.output
    for name in ("agent-config", "dependency-diff", "supply-chain", "dast"):
        assert name in names


def test_reporters_and_providers_load_on_first_lookup() -> None:
    from nephilex.core.plugin import registry

    assert "json" in registry.reporters()
    assert registry.get_ai_provider("heuristic").name == "heuristic"


def _scanner(name: str, module: str) -> type[Scanner]:
    cls = type(name, (Scanner,), {"name": name, "scan": lambda self, ctx: []})
    cls.__module__ = module
    return cls


def test_loaders_run_once_on_first_lookup_of_their_kind() -> None:
    reg = Registry()
    reg._loaded_entrypoints = True
    calls: list[str] = []
    reg.add_loader("Reporter", lambda: calls.append("reporter"))
    reg.add_loader("Scanner", lambda: calls.append("scanner"))
    assert calls == []
    reg.scanners()
    reg.scanners()
    assert calls == ["scanner"]
    reg.reporters()
    assert calls == ["scanner", "reporter"]
    with pytest.raises(ValueError):
        reg.add_loader("Nope", lambda: None)


def test_a_builtin_keeps_its_name_when_a_plugin_registered_first() -> None:
    reg = Registry()
    reg._loaded_entrypoints = True
    third_party = _scanner("patterns", "acme_plugin.scanners")
    reg.register_scanner(third_party)
    builtin = _scanner("patterns", "nephilex.scanners.patterns_fake")
    reg.add_loader("Scanner", lambda: reg.register_scanner(builtin))
    assert reg.get_scanner("patterns") is builtin
    assert ("Scanner", "patterns") in reg.rejected()


def test_two_third_party_plugins_with_one_name_still_clash() -> None:
    reg = Registry()
    reg._loaded_entrypoints = True
    reg.register_scanner(_scanner("dup", "acme_one"))
    with pytest.raises(ValueError, match="already registered"):
        reg.register_scanner(_scanner("dup", "acme_two"))


def test_disabled_ai_provider_is_built_on_first_use() -> None:
    from nephilex.core.config import AIConfig
    from nephilex.core.engine import _DeferredProvider

    deferred = _DeferredProvider(AIConfig())
    assert deferred._provider is None
    assert deferred.name == "heuristic"
    assert deferred._provider is not None
