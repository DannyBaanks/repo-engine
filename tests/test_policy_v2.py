"""Gates de la decision 2026-11-15 (severidades, fixtures de secretos, rango para CI).

Positivos: lo informativo no bloquea; un fixture sintetico declarado no bloquea.
Adversariales: lo critico y la politica privada siguen bloqueando; un secreto real en
la MISMA ruta de un fixture sigue bloqueando; excepciones amplias se rechazan.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from repo_engine import audit
from repo_engine.policy import is_blocking, is_synthetic_secret, load_exceptions, scan

# Armado en partes: este archivo no debe ser el mismo un hallazgo.
PRIV = b"/home" + b"/alice/projects/x"
GH = "gh" + "p_"
SK = "s" + "k-"
REALISH_GH = GH + "Zq8Lr2Wn5Vb7Kc1Xd4Mf6Hj9Pt3Ys0Ue8Ra"  # 36, alta entropia, sin marcador
REALISH_SK = SK + "proj7Hq2Lw9Zr4Nx1Vc8Bm5Kt3Yd6"
FAKE_SK = SK + "seam-machine-not-real"
FAKE_GH = GH + "A" * 36
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
SECTIONS = {"unique internal names": ["NeverPublishThis"], "internal phrases": ["secret sauce phrase"],
            "internal concept patterns": ["hyperloom"]}


def write_exc(repo: Path, body: str) -> None:
    (repo / ".repo-engine-exceptions.toml").write_text(body, encoding="utf-8")


def rules(findings) -> list[str]:
    return sorted(f.rule for f in findings)


# ── severidades ────────────────────────────────────────────────────────────────

def test_doc_and_envvar_paths_are_notes_not_blocking() -> None:
    doc = scan("README.md", b"see " + PRIV, {}, set())
    env = scan("cfg.py", b'X = os.environ.get("X", "' + PRIV + b'")', {}, set())
    assert rules(doc) == ["LOCAL_PATH_001_DOC"] and rules(env) == ["LOCAL_PATH_001_ENVVAR"]
    assert not any(is_blocking(f) for f in doc + env)


def test_env_fallback_does_not_downgrade_a_hardcoded_path_elsewhere_in_the_file() -> None:
    # Evasion real encontrada al publicar: la primera aparicion decidia la clase del archivo.
    blob = (b'A = os.environ.get("A", "' + PRIV + b'")\n' + b"\n" * 10 + b'B = "' + PRIV + b'"\n')
    f = scan("cfg.py", blob, {}, set())
    assert rules(f) == ["LOCAL_PATH_001"] and is_blocking(f[0])


def test_hardcoded_path_in_code_still_blocks() -> None:
    f = scan("tool.py", b'ROOT = "' + PRIV + b'"', {}, set())
    assert rules(f) == ["LOCAL_PATH_001"] and all(is_blocking(x) for x in f)


@pytest.mark.parametrize("blob,rule", [
    (REALISH_GH.encode(), "SECRET_001"),
    (REALISH_SK.encode(), "SECRET_002"),
    (PEM_HEADER.encode(), "SECRET_003"),
])
def test_secrets_still_block(blob: bytes, rule: str) -> None:
    f = scan("config.py", blob, {}, set())
    assert rule in rules(f) and all(is_blocking(x) for x in f)


def test_private_credential_filename_still_blocks() -> None:
    f = scan("deploy/id_rsa", b"x", {}, set())
    assert rules(f) == ["FILE_001"] and is_blocking(f[0])


@pytest.mark.parametrize("text,rule", [
    ("we ship NeverPublishThis", "POLICY_NAME"),
    ("this is our secret sauce phrase", "POLICY_PHRASE"),
    ("the hyperloom engine core", "POLICY_CONCEPT"),
])
def test_private_policy_rules_stay_blocking_stop_and_review(text: str, rule: str) -> None:
    # La politica privada dice "STOP and request human review": no se rebajan.
    f = scan("README.md", text.encode(), SECTIONS, set())
    assert rule in rules(f) and all(is_blocking(x) for x in f if x.rule == rule)


def test_outcome_with_only_notes_is_clean_with_notes_and_exit_zero() -> None:
    notes = scan("README.md", PRIV, {}, set())
    o = audit.Outcome(notes, "staged", 1, 1, [])
    assert o.status == "CLEAN_WITH_NOTES" and o.exit_code == 0 and o.notes and not o.blocking


def test_outcome_with_one_blocking_among_notes_blocks() -> None:
    f = scan("README.md", PRIV, {}, set()) + scan(
        "a.py", REALISH_SK.encode(), {}, set())
    o = audit.Outcome(f, "staged", 2, 2, [])
    assert o.status == "BLOCKED" and o.exit_code == 1


# ── fixtures de secretos ───────────────────────────────────────────────────────

def test_declared_synthetic_fixture_does_not_block(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{FAKE_SK}"\n')
    exc = load_exceptions(tmp_path)
    assert scan("tests/t.py", f'k = "{FAKE_SK}"'.encode(), {}, exc) == []


def test_real_secret_in_same_file_as_fixture_still_blocks(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{FAKE_SK}"\n')
    exc = load_exceptions(tmp_path)
    blob = f'fake = "{FAKE_SK}"\nreal = "{REALISH_SK}"\n'.encode()
    f = scan("tests/t.py", blob, {}, exc)
    assert rules(f) == ["SECRET_002"] and "differs from the declared fixture" in f[0].detail


def test_fixture_does_not_cover_other_files(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{FAKE_SK}"\n')
    exc = load_exceptions(tmp_path)
    assert rules(scan("src/app.py", f'"{FAKE_SK}"'.encode(), {}, exc)) == ["SECRET_002"]


def test_fixture_does_not_cover_other_rules(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{FAKE_SK}"\n')
    exc = load_exceptions(tmp_path)
    assert rules(scan("tests/t.py", REALISH_GH.encode(), {}, exc)) == ["SECRET_001"]


@pytest.mark.parametrize("path", ["tests/", "tests/*", "tests/**/*.py", ".", "../x.py", "tests/[ab].py"])
def test_directory_or_glob_secret_exceptions_are_rejected(tmp_path: Path, path: str) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "{path}"\nvalue = "{FAKE_SK}"\n')
    exc = load_exceptions(tmp_path)
    assert exc.secret_fixtures == []
    assert "exact file" in exc.rejected[("SECRET_002", path)]


def test_high_entropy_value_cannot_be_declared_a_fixture(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_002"\npath = "tests/t.py"\nvalue = "{REALISH_SK}"\n')
    exc = load_exceptions(tmp_path)
    assert exc.secret_fixtures == []
    f = scan("tests/t.py", REALISH_SK.encode(), {}, exc)
    assert rules(f) == ["SECRET_002"] and "not verifiably synthetic" in f[0].detail


def test_low_entropy_fixture_is_synthetic() -> None:
    assert is_synthetic_secret(FAKE_GH)
    assert not is_synthetic_secret(REALISH_GH)


def test_marker_must_be_a_word_not_buried_in_random_text() -> None:
    assert not is_synthetic_secret(SK + "Zq8Lr2WtestN5Vb7Kc1Xd4Mf6")
    assert is_synthetic_secret(SK + "test-only-key-0000000000")


def test_pem_header_only_fixture_ok_but_real_body_still_blocks(tmp_path: Path) -> None:
    write_exc(tmp_path, f'[[secret_fixture]]\nrule = "SECRET_003"\npath = "config/example.php"\nvalue = "{PEM_HEADER}"\n')
    exc = load_exceptions(tmp_path)
    header_only = f"$key = '{PEM_HEADER}\\n...\\n-----END PRIVATE KEY-----';".encode()
    assert scan("config/example.php", header_only, {}, exc) == []
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 3
    real = f"{PEM_HEADER}\n{body}\n-----END PRIVATE KEY-----\n".encode()
    f = scan("config/example.php", real, {}, exc)
    assert rules(f) == ["SECRET_003"] and "real key" in f[0].detail


def test_term_exceptions_keep_working(tmp_path: Path) -> None:
    write_exc(tmp_path, '[exceptions]\nnames = ["docs/a.md:NeverPublishThis"]\n')
    exc = load_exceptions(tmp_path)
    assert scan("docs/a.md", b"NeverPublishThis", SECTIONS, exc) == []
    assert rules(scan("docs/b.md", b"NeverPublishThis", SECTIONS, exc)) == ["POLICY_NAME"]


# ── rango para CI ──────────────────────────────────────────────────────────────

ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1"}


def git(cwd: Path, *a: str) -> str:
    return subprocess.run(["git", *a], cwd=cwd, env=ENV, text=True,
                          capture_output=True, check=True).stdout.strip()


@pytest.fixture
def pr_repo(tmp_path: Path) -> tuple[Path, str]:
    ENV["GIT_CONFIG_GLOBAL"] = str(tmp_path / "gc")
    (tmp_path / "gc").write_text("[init]\n\tdefaultBranch = main\n")
    r = tmp_path / "r"
    git(tmp_path, "init", "-q", str(r))
    (r / "a.txt").write_text("base\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "base")
    return r, git(r, "rev-parse", "HEAD")


def test_range_audits_exactly_the_pr_commits_without_private_policy(
    pr_repo: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    r, base = pr_repo
    monkeypatch.setattr(audit, "config", lambda: {"policy_path": "/nonexistent"})
    (r / "leak.py").write_text(f'K = "{REALISH_SK}"\n')
    git(r, "add", "-A")
    git(r, "commit", "-q", "--no-verify", "-m", "leak via --no-verify")
    o = audit.outgoing_outcome(r, rev_range=f"{base}..HEAD", policy_required=False)
    assert o.mode == "range" and o.policy == "base-rules-only"
    assert o.status == "BLOCKED" and rules(o.findings) == ["SECRET_002"]


def test_range_rejects_non_range_arguments(pr_repo: tuple[Path, str]) -> None:
    r, _ = pr_repo
    with pytest.raises(Exception, match="BASE..HEAD"):
        audit.git.range_commits(r, "--all")


# ── rutas privadas genericas ──────────────────────────────────────────────────

@pytest.mark.parametrize("blob", [
    b"/Us" + b"ers/carol/secret.txt",
    b"C:" + b"\\Users\\Bob\\x",
    b"C:" + b"/Us" + b"ers/bob/x",
])
def test_any_personal_home_is_a_private_path(blob: bytes) -> None:
    f = scan("tool.py", b'P = "' + blob + b'"', {}, set())
    assert rules(f) == ["LOCAL_PATH_001"]


@pytest.mark.parametrize("text", [
    b"see /home/user/project",            # nombre de ejemplo
    b"cd /home/runner/work/x",            # runner de CI
    b"https://api.github.com/users/octocat",   # URL, no una ruta local
    b"https://example.com/home/alice",    # URL con /home/ en el camino
])
def test_examples_and_urls_are_not_private_paths(text: bytes) -> None:
    assert scan("tool.py", text, {}, set()) == []


def test_configured_private_paths_extend_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    from repo_engine import config
    blob = b'P = "D:/work/' + b'client-x/secret"'
    assert scan("tool.py", blob, {}, set()) == []
    monkeypatch.setattr(config, "config", lambda: {"private_paths": ["D:/work/client-x"]})
    assert rules(scan("tool.py", blob, {}, set())) == ["LOCAL_PATH_001"]


def test_concept_context_words_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    from repo_engine import config
    sections = {"internal concept patterns": ["hyperloom"]}
    assert scan("a.md", b"the hyperloom substrate", sections, set()) == []
    monkeypatch.setattr(config, "config", lambda: {"concept_context": ["substrate"]})
    assert rules(scan("a.md", b"the hyperloom substrate", sections, set())) == ["POLICY_CONCEPT"]
    via_policy = {**sections, "concept context words": ["loom-core"]}
    monkeypatch.setattr(config, "config", lambda: {})
    assert rules(scan("a.md", b"hyperloom in loom-core", via_policy, set())) == ["POLICY_CONCEPT"]


def test_path_finding_never_prints_the_path() -> None:
    f = scan("tool.py", b'P = "' + PRIV + b'"', {}, set())
    assert f and all(b"alice" not in x.detail.encode() for x in f)
