from pathlib import Path

import pytest

from repo_engine import audit


def test_blocks_when_private_policy_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        audit, "config", lambda: {"policy_path": str(tmp_path / "missing.md")}
    )
    with pytest.raises(RuntimeError, match="publication policy is unavailable"):
        audit.private_policy()
