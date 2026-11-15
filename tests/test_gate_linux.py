"""Regresiones de la compuerta en Linux, medidas con commits/pushes reales
(git-autosync tests/repo-engine-hooks.sh, 2026-11-15):

- el instalador dejaba los hooks sin bit de ejecucion -> git los ignoraba en silencio;
- pre-push auditaba HEAD contra su upstream, no las refs que se empujan -> fuga;
- NO_SURFACE (nada que auditar) bloqueaba amend de mensaje, --allow-empty y
  push de ramas sin commits nuevos -> friccion que empuja a --no-verify.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from repo_engine import audit, git
from repo_engine.hooks import install

ROOT = Path(__file__).resolve().parents[1]
# Token falso armado en partes para que este archivo no sea un hallazgo.
FAKE_TOKEN = "gh" + "p_" + "A" * 36
ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def sh(cwd: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=cwd, env=ENV, input=stdin, text=True, capture_output=True, check=False
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    policy = tmp_path / "policy.md"
    policy.write_text("## unique internal names\n", encoding="utf-8")
    monkeypatch.setattr(audit, "config", lambda: {"policy_path": str(policy)})
    ENV["GIT_CONFIG_GLOBAL"] = str(tmp_path / "gitconfig")
    (tmp_path / "gitconfig").write_text("[init]\n\tdefaultBranch = main\n")
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    sh(tmp_path, "git", "init", "-q", "--bare", str(remote))
    sh(tmp_path, "git", "init", "-q", str(work))
    sh(work, "git", "remote", "add", "origin", str(remote))
    (work / "README.md").write_text("base\n")
    sh(work, "git", "add", "-A")
    sh(work, "git", "commit", "-q", "-m", "base")
    sh(work, "git", "push", "-q", "-u", "origin", "main")
    return work


def commit(work: Path, name: str, content: str, msg: str) -> str:
    (work / name).write_text(content)
    sh(work, "git", "add", "-A")
    sh(work, "git", "commit", "-q", "--no-verify", "-m", msg)
    return sh(work, "git", "rev-parse", "HEAD").stdout.strip()


def test_install_makes_hooks_executable_and_not_writable_by_others(repo: Path) -> None:
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    for name, gate in (("pre-commit", "commit"), ("pre-push", "push")):
        stale = hooks / name  # hook gestionado heredado de Windows: 0666
        stale.write_text(f'#!/bin/sh\n"C:/python.exe" "C:/repo-engine.py" gate {gate}\n')
        stale.chmod(0o666)
    install(repo, adopt=False)
    for name in ("pre-commit", "pre-push"):
        assert (hooks / name).stat().st_mode & 0o777 == 0o755, name


def test_push_audits_the_refs_being_pushed_not_head(repo: Path) -> None:
    sh(repo, "git", "checkout", "-q", "-b", "mala")
    bad = commit(repo, "leak.txt", FAKE_TOKEN, "mala")
    sh(repo, "git", "checkout", "-q", "main")
    commit(repo, "ok.txt", "limpio\n", "limpio")  # HEAD limpio con salida propia
    updates = [("refs/heads/mala", bad, "refs/heads/mala", "0" * 40)]
    outcome = audit.outgoing_outcome(repo, updates)
    assert outcome.status == "BLOCKED"
    assert any(f.rule == "SECRET_001" for f in outcome.findings)


def test_push_of_already_published_commits_has_nothing_to_audit(repo: Path) -> None:
    head = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
    updates = [("refs/heads/copia", head, "refs/heads/copia", "0" * 40)]
    assert git.pushed_commits(repo, updates) == []


def test_branch_deletion_is_not_audited(repo: Path) -> None:
    head = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
    assert git.pushed_commits(repo, [("(delete)", "0" * 40, "refs/heads/x", head)]) == []


def run_gate(repo: Path, gate: str, stdin: str) -> subprocess.CompletedProcess:
    code = (
        "import sys; sys.argv=['repo-engine','gate',sys.argv[1],'--repo',sys.argv[2]];"
        "from repo_engine import audit, cli;"
        f"audit.config=lambda: {{'policy_path': {str(repo.parent / 'policy.md')!r}}};"
        "raise SystemExit(cli.main())"
    )
    return subprocess.run([sys.executable, "-c", code, gate, str(repo)], cwd=ROOT,
                          env=ENV, input=stdin, text=True, capture_output=True, check=False)


def test_commit_gate_passes_when_nothing_is_staged(repo: Path) -> None:
    result = run_gate(repo, "commit", "")
    assert result.returncode == 0, result.stdout + result.stderr


def test_push_gate_passes_when_nothing_new_is_pushed(repo: Path) -> None:
    head = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
    line = f"refs/heads/main {head} refs/heads/copia {'0' * 40}\n"
    result = run_gate(repo, "push", line)
    assert result.returncode == 0, result.stdout + result.stderr


def test_push_gate_blocks_secret_on_pushed_branch_with_clean_head(repo: Path) -> None:
    sh(repo, "git", "checkout", "-q", "-b", "mala")
    bad = commit(repo, "leak.txt", FAKE_TOKEN, "mala")
    sh(repo, "git", "checkout", "-q", "main")
    commit(repo, "ok.txt", "limpio\n", "limpio")
    line = f"refs/heads/mala {bad} refs/heads/mala {'0' * 40}\n"
    result = run_gate(repo, "push", line)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SECRET_001" in result.stdout


def test_push_to_another_remote_audits_commits_only_on_origin(repo: Path) -> None:
    # origin (p.ej. privado) ya tiene el secreto; empujar la misma rama a un fork
    # publico SI debe auditarlo.
    commit(repo, "leak.txt", FAKE_TOKEN, "secreto en origin")
    sh(repo, "git", "push", "-q", "--no-verify", "origin", "main")
    fork = repo.parent / "fork.git"
    sh(repo.parent, "git", "init", "-q", "--bare", str(fork))
    sh(repo, "git", "remote", "add", "fork", str(fork))
    head = sh(repo, "git", "rev-parse", "HEAD").stdout.strip()
    updates = [("refs/heads/main", head, "refs/heads/main", "0" * 40)]
    assert git.pushed_commits(repo, updates, "origin") == []
    assert head in git.pushed_commits(repo, updates, "fork")


def test_installed_pre_push_passes_the_destination_remote(repo: Path) -> None:
    install(repo, adopt=False)
    body = (repo / ".git" / "hooks" / "pre-push").read_text()
    assert '--remote "$1"' in body
    assert "--remote" not in (repo / ".git" / "hooks" / "pre-commit").read_text()
