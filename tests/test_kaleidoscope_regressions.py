from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

from repo_engine import audit, cli, git


def run_git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture()
def private_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    policy = tmp_path.parent / f"{tmp_path.name}-private-policy.md"
    policy.write_text("## Unique internal names\n- NeverPublishThis\n", encoding="utf-8")
    monkeypatch.setattr(audit, "private_policy", lambda: policy)
    return policy


def test_candidate_scan_covers_untracked_without_staging(
    tmp_path: Path, private_policy: Path
) -> None:
    run_git(tmp_path, "init")
    (tmp_path / "clean.txt").write_text("public material\n", encoding="utf-8")
    (tmp_path / "trace.py").write_text(
        'ROOT = r"C:\\' + 'Users\\alice\\private"\n', encoding="utf-8"
    )

    outcome = audit.candidate_outcome(tmp_path)

    assert outcome.status == "BLOCKED"
    assert outcome.mode == "git-candidate"
    assert outcome.candidates == outcome.scanned == 2
    assert any(finding.rule == "LOCAL_PATH_001" for finding in outcome.findings)
    assert run_git(tmp_path, "diff", "--cached", "--name-only") == ""


def test_unborn_outgoing_and_empty_staged_are_no_surface(
    tmp_path: Path, private_policy: Path
) -> None:
    run_git(tmp_path, "init")

    outgoing = audit.outgoing_outcome(tmp_path)
    staged = audit.staged_outcome(tmp_path)

    assert outgoing.status == "NO_SURFACE"
    assert outgoing.exit_code == 2
    assert staged.status == "NO_SURFACE"
    assert staged.exit_code == 2


def test_init_creates_git_repo_and_infers_research_demo(tmp_path: Path) -> None:
    (tmp_path / "KALEIDOSCOPE_SPEC.md").write_text("# Methodology\n", encoding="utf-8")
    (tmp_path / "evidence").mkdir()
    args = argparse.Namespace(
        repo=str(tmp_path),
        adopt_existing_hook=False,
        template=None,
        reconfigure=False,
    )

    assert cli.init_repo(args) == 0

    assert git.is_repo(tmp_path)
    assert 'template = "research-demo"' in (
        tmp_path / ".repo-engine.toml"
    ).read_text(encoding="utf-8")
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()
    assert (tmp_path / ".git" / "hooks" / "pre-push").is_file()
