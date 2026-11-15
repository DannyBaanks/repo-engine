from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "state"
# CI (ci/run-ci.sh) points this elsewhere so the runner never reads a local config.
CONFIG_PATH = Path(os.environ.get("REPO_ENGINE_CONFIG") or ROOT / "repo-engine.json")
REGISTRY_PATH = STATE_DIR / "registry.json"


def load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def config() -> dict:
    return load_json(CONFIG_PATH, {"policy_path": ""})


def registry() -> dict:
    return load_json(REGISTRY_PATH, {"repos": {}})


def register_repo(repo: Path) -> None:
    data = registry()
    data["repos"][str(repo.resolve())] = {"phase": "building"}
    save_json(REGISTRY_PATH, data)
