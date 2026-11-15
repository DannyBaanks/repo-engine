from __future__ import annotations

from pathlib import Path

import pytest

from repo_engine import config


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Ningun test escribe en el registro real (state/registry.json). Antes de esto,
    cada corrida de la suite registraba su directorio temporal de pytest ahi."""
    path = tmp_path / "isolated-state" / "registry.json"
    monkeypatch.setattr(config, "REGISTRY_PATH", path)
    # Tampoco leen la config local (private_paths, concept_context de quien corre la suite).
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "isolated-state" / "no-config.json")
    return path
