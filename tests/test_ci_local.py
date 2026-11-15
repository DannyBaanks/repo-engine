"""Reproduccion local del check de CI: ejecuta ci/run-ci.sh (el MISMO script que usa
action.yml) sobre PRs simulados. Demuestra la logica del check; que GitHub lo exija
(ruleset) NO se demuestra aqui."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN_CI = ROOT / "ci" / "run-ci.sh"
SK_REAL = "s" + "k-" + "Zq8Lr2Wn5Vb7Kc1Xd4Mf6Hj9"
SK_FAKE = "s" + "k-" + "test-only-fixture-0000000"
PRIVATE = "/home" + "/alice/projects/x"


@pytest.fixture
def pr(tmp_path: Path):
    env = {k: v for k, v in os.environ.items() if k not in ("RE_POLICY", "REPO_ENGINE_CONFIG")}
    env.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=str(tmp_path / "gc"))
    (tmp_path / "gc").write_text("[init]\n\tdefaultBranch = main\n")
    repo = tmp_path / "repo"

    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=repo, env=env, text=True,
                              capture_output=True, check=True).stdout.strip()

    repo.mkdir()
    git("init", "-q")
    (repo / "README.md").write_text("base\n")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("checkout", "-q", "-b", "feature")

    def commit(name: str, content: str) -> str:
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        git("add", "-A")
        git("commit", "-q", "--no-verify", "-m", name)   # como un agente que salta los hooks
        return git("rev-parse", "HEAD")

    def ci(head: str, b: str | None = None, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([str(RUN_CI), b or base, head], cwd=repo, env={**env, **extra},
                              text=True, capture_output=True, check=False)

    return commit, ci, base


def test_ci_blocks_secret_that_skipped_hooks_with_no_verify(pr) -> None:
    commit, ci, _ = pr
    r = ci(commit("app/config.py", f'KEY = "{SK_REAL}"\n'))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "SECRET_002" in r.stdout and "policy: base-rules-only" in r.stdout


def test_ci_blocks_private_path_in_code(pr) -> None:
    commit, ci, _ = pr
    r = ci(commit("tool.py", f'ROOT = "{PRIVATE}"\n'))
    assert r.returncode == 1 and "LOCAL_PATH_001" in r.stdout


def test_ci_passes_notes_only(pr) -> None:
    commit, ci, _ = pr
    r = ci(commit("docs/setup.md", f"Example path: {PRIVATE}\n"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CLEAN_WITH_NOTES" in r.stdout and "[NOTE]" in r.stdout


def test_ci_passes_declared_synthetic_fixture_but_not_a_real_secret_beside_it(pr) -> None:
    commit, ci, _ = pr
    commit(".repo-engine-exceptions.toml",
           f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{SK_FAKE}"\n')
    ok = ci(commit("tests/t.py", f'K = "{SK_FAKE}"\n'))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = ci(commit("tests/t.py", f'K = "{SK_FAKE}"\nR = "{SK_REAL}"\n'))
    assert bad.returncode == 1 and "differs from the declared fixture" in bad.stdout


def test_ci_only_audits_the_pr_range(pr) -> None:
    commit, ci, _ = pr
    first = commit("app/old.py", f'KEY = "{SK_REAL}"\n')       # ya revisado en un PR anterior
    r = ci(commit("docs/x.md", "clean\n"), b=first)
    assert r.returncode == 0, r.stdout


def test_ci_fails_closed_without_a_base(pr) -> None:
    commit, ci, _ = pr
    r = ci(commit("a.md", "x\n"), b="0" * 40)
    assert r.returncode == 2 and "nothing was audited" in r.stderr


def test_ci_never_reads_the_local_config(pr) -> None:
    # Aunque esta maquina tiene repo-engine.json con la politica privada, CI corre sin ella.
    commit, ci, _ = pr
    r = ci(commit("a.md", "x\n"))
    assert r.returncode == 0 and "policy: base-rules-only" in r.stdout


def test_ci_blocks_a_real_secret_written_into_the_exceptions_file(pr) -> None:
    commit, ci, _ = pr
    r = ci(commit(".repo-engine-exceptions.toml",
                  f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{SK_REAL}"\n'))
    assert r.returncode == 1 and "SECRET_002" in r.stdout


def test_ci_extra_private_paths_input(pr) -> None:
    commit, ci, _ = pr
    head = commit("tool.py", 'P = "D:/work/' + 'client-x/secret"\n')
    assert ci(head).returncode == 0
    r = ci(head, RE_PRIVATE_PATHS="D:/work/client-x\n")
    assert r.returncode == 1 and "LOCAL_PATH_001" in r.stdout and "client-x" not in r.stdout
