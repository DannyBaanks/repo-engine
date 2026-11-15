from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import git
from .config import ROOT, config
from .policy import (
    Finding,
    is_blocking,
    load_exceptions,
    policy_sections,
    scan,
    scan_file,
)

SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    ".superpowers",
    ".worktrees",
    "build",
    "target",
}


@dataclass(frozen=True)
class Outcome:
    findings: list[Finding]
    mode: str
    candidates: int
    scanned: int
    skipped: list[dict[str, str]]
    policy: str = "private"

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if is_blocking(f)]

    @property
    def notes(self) -> list[Finding]:
        return [f for f in self.findings if not is_blocking(f)]

    @property
    def status(self) -> str:
        if self.blocking:
            return "BLOCKED"
        if self.candidates == 0:
            return "NO_SURFACE"
        if self.skipped:
            return "INCOMPLETE_COVERAGE"
        return "CLEAN_WITH_NOTES" if self.findings else "CLEAN"

    @property
    def exit_code(self) -> int:
        if self.status in ("CLEAN", "CLEAN_WITH_NOTES"):
            return 0
        if self.status == "BLOCKED":
            return 1
        return 2
SKIP_EXTS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".obj",
    ".lib",
    ".a",
    ".rlib",
    ".rmeta",
    ".pdb",
    ".ilk",
    ".exp",
}


def private_policy() -> Path:
    raw = config().get("policy_path", "")
    path = Path(raw) if raw else ROOT / "missing-private-policy"
    if not path.is_file():
        raise RuntimeError(
            "private publication policy is unavailable; publication is blocked"
        )
    return path


def _tracked_files(repo: Path) -> list[str]:
    return git.run(repo, "ls-files").splitlines()


def staged_outcome(repo: Path) -> Outcome:
    sections = policy_sections(private_policy())
    exceptions = load_exceptions(repo)
    findings: list[Finding] = []
    paths = git.staged_paths(repo)
    for path in paths:
        findings.extend(scan(path, git.index_blob(repo, path), sections, exceptions))
    return Outcome(findings, "staged", len(paths), len(paths), [])


def staged(repo: Path) -> list[Finding]:
    return staged_outcome(repo).findings


def outgoing_outcome(
    repo: Path,
    updates: list[tuple[str, str, str, str]] | None = None,
    remote: str | None = None,
    rev_range: str | None = None,
    policy_required: bool = True,
) -> Outcome:
    """Audit what leaves the machine. With `updates` (pre-push stdin) the exact
    pushed refs are audited; with `rev_range` (CI) exactly BASE..HEAD; otherwise
    HEAD against its upstream (manual use). Without the private policy (CI) only
    the base rules run, and the outcome says so."""
    if policy_required:
        sections, policy = policy_sections(private_policy()), "private"
    else:
        sections = _optional_sections()
        policy = "private" if sections else "base-rules-only"
    exceptions = load_exceptions(repo)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    if rev_range is not None:
        commits = git.range_commits(repo, rev_range)
    elif updates is not None:
        commits = git.pushed_commits(repo, updates, remote)
    else:
        commits = git.outgoing_commits(repo)
    paths = [(commit, path) for commit in commits for path in git.changed_paths(repo, commit)]
    for commit, path in paths:
        for finding in scan(
            path, git.commit_blob(repo, commit, path), sections, exceptions
        ):
            key = (commit, finding.rule, finding.path)
            if key not in seen:
                findings.append(
                    Finding(
                        finding.rule,
                        f"{commit[:8]}:{finding.path}",
                        finding.detail,
                        finding.severity,
                    )
                )
                seen.add(key)
    mode = "range" if rev_range is not None else "outgoing"
    return Outcome(findings, mode, len(paths), len(paths), [], policy)


def outgoing(repo: Path) -> list[Finding]:
    return outgoing_outcome(repo).findings


def _scan_paths(
    root: Path,
    paths: list[str],
    sections: dict[str, list[str]],
    exceptions: set[tuple[str, str]],
    mode: str,
) -> Outcome:
    findings: list[Finding] = []
    skipped: list[dict[str, str]] = []
    scanned = 0
    for rel in paths:
        full = root / rel
        if not full.is_file():
            skipped.append({"path": rel, "reason": "missing_or_not_file"})
            continue
        try:
            blob = full.read_bytes()
        except OSError:
            skipped.append({"path": rel, "reason": "read_error"})
            continue
        findings.extend(scan(rel, blob, sections, exceptions))
        scanned += 1
    return Outcome(findings, mode, len(paths), scanned, skipped)


def candidate_outcome(repo: Path, strict_policy: bool = True) -> Outcome:
    sections = policy_sections(private_policy()) if strict_policy else _optional_sections()
    paths = git.candidate_paths(repo)
    return _scan_paths(repo, paths, sections, load_exceptions(repo), "git-candidate")


def analyze(repo: Path) -> list[Finding]:
    sections = policy_sections(private_policy())
    exceptions = load_exceptions(repo)
    findings: list[Finding] = []
    for rel_path in _tracked_files(repo):
        full = repo / rel_path
        if any(part in SKIP_DIRS for part in full.parts):
            continue
        if full.suffix.lower() in SKIP_EXTS:
            continue
        if not full.is_file():
            continue
        try:
            size = full.stat().st_size
            if size > 1_000_000:
                continue
        except OSError:
            continue
        file_findings = scan_file(full, sections, exceptions, rel_path)
        for f in file_findings:
            findings.append(Finding(f.rule, rel_path, f.detail, f.severity))
    return findings


MAX_FILE_BYTES = 1_000_000


def _walk_files(root: Path):
    """Filesystem walk independent of Git; yields (full_path, rel_path)."""
    for full in sorted(root.rglob("*")):
        if not full.is_file():
            continue
        if any(part in SKIP_DIRS for part in full.parts):
            continue
        yield full, full.relative_to(root).as_posix()


def _optional_sections() -> dict[str, list[str]]:
    """Gnostic mode: base rules always run; policy terms apply only if configured."""
    try:
        return policy_sections(private_policy())
    except RuntimeError:
        return {}


def scan_filesystem_outcome(target: Path) -> Outcome:
    """Audit any file or directory without registration, hooks, or Git."""
    target = target.resolve()
    if target.is_file():
        exception_root = target.parent
        pairs = [(target, target.name)]
    else:
        exception_root = target
        pairs = list(_walk_files(target))
    sections = _optional_sections()
    exceptions = load_exceptions(exception_root)
    if target.is_file():
        root = target.parent
        paths = [target.name]
        mode = "file"
    else:
        root = target
        paths = [rel for _, rel in pairs]
        mode = "filesystem"
    return _scan_paths(root, paths, sections, exceptions, mode)


def scan_filesystem(target: Path) -> list[Finding]:
    return scan_filesystem_outcome(target).findings


def analyze_any_outcome(target: Path) -> Outcome:
    """Auto-detect the best strategy for an arbitrary target.

    Returns (findings, mode) where mode is 'git-tracked', 'filesystem', or 'file'.
    """
    target = target.resolve()
    if target.is_file():
        return scan_filesystem_outcome(target)
    if git.is_repo(target):
        return candidate_outcome(target, strict_policy=False)
    return scan_filesystem_outcome(target)


def analyze_any(target: Path) -> tuple[list[Finding], str]:
    outcome = analyze_any_outcome(target)
    return outcome.findings, outcome.mode


def history(repo: Path) -> list[Finding]:
    sections = policy_sections(private_policy())
    exceptions = load_exceptions(repo)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for commit in git.run(repo, "rev-list", "--all").splitlines():
        for path in git.changed_paths(repo, commit):
            for finding in scan(
                path, git.commit_blob(repo, commit, path), sections, exceptions
            ):
                key = (commit, finding.rule, finding.path)
                if key not in seen:
                    findings.append(
                        Finding(
                            finding.rule,
                            f"{commit[:8]}:{finding.path}",
                            finding.detail,
                            finding.severity,
                        )
                    )
                    seen.add(key)
    return findings
