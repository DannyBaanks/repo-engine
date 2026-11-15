from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def run(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        raise GitError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def is_repo(path: Path) -> bool:
    try:
        return run(path, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitError:
        return False


def staged_paths(repo: Path) -> list[str]:
    raw = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout
    return [
        item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item
    ]


def candidate_paths(repo: Path) -> list[str]:
    """Tracked and non-ignored untracked files without modifying the index."""
    raw = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout
    return [
        item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item
    ]


def index_blob(repo: Path, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f":{path}"], cwd=repo, capture_output=True, check=False
    )
    return result.stdout if result.returncode == 0 else b""


def outgoing_commits(repo: Path) -> list[str]:
    if run(repo, "rev-parse", "--verify", "HEAD", check=False).strip() == "":
        return []
    upstream = run(
        repo,
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
        check=False,
    ).strip()
    revision = f"{upstream}..HEAD" if upstream else "HEAD"
    return [item for item in run(repo, "rev-list", revision).splitlines() if item]


def _is_null(sha: str) -> bool:
    return not sha or set(sha) == {"0"}


def pushed_commits(
    repo: Path, updates: list[tuple[str, str, str, str]], remote: str | None = None
) -> list[str]:
    """Commits that a push would publish, from git's pre-push stdin lines
    (<local ref> <local sha> <remote ref> <remote sha>): everything reachable from
    the pushed shas that is not already on the destination (its remote-tracking
    refs when `remote` names a configured remote, or every remote when it is not
    given) nor in the destination's current tip. Deletions publish nothing."""
    include = [local for _, local, _, _ in updates if not _is_null(local)]
    if not include:
        return []
    # Con el nombre del remoto destino, solo sus refs cuentan como ya publicadas.
    # Un URL no tiene refs de seguimiento: no se excluye nada (mas auditoria, no menos).
    if remote and "/" not in remote and ":" not in remote:
        exclude = [f"--remotes={remote}"]
    elif remote:
        exclude = []
    else:
        exclude = ["--remotes"]
    for _, local, _, tip in updates:
        known = not _is_null(local) and not _is_null(tip) and run(
            repo, "rev-parse", "-q", "--verify", f"{tip}^{{commit}}", check=False
        ).strip()
        if known:
            exclude.append(tip)
    revs = [*include, "--not", *exclude] if exclude else include
    return [item for item in run(repo, "rev-list", *revs).splitlines() if item]


def range_commits(repo: Path, rev_range: str) -> list[str]:
    """Commits in BASE..HEAD (CI: exactly what a pull request adds)."""
    if ".." not in rev_range or rev_range.startswith("-"):
        raise GitError(f"expected BASE..HEAD, got {rev_range!r}")
    return [item for item in run(repo, "rev-list", rev_range).splitlines() if item]


def changed_paths(repo: Path, commit: str) -> list[str]:
    return [
        item
        for item in run(
            repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit
        ).splitlines()
        if item
    ]


def commit_blob(repo: Path, commit: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"], cwd=repo, capture_output=True, check=False
    )
    return result.stdout if result.returncode == 0 else b""
