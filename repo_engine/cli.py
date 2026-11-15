from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from . import audit, git, shell
from .config import CONFIG_PATH, config, register_repo, save_json
from .hooks import install
from .policy import SEVERITY, Finding
from .startup import health, install_task, notify
from .templates import all_templates, marker, select, summary


def repo_path(raw: str | None) -> Path:
    repo = Path(raw or ".").resolve()
    if not git.is_repo(repo):
        raise RuntimeError(f"not a Git repository: {repo}")
    return repo


def print_findings(
    findings: list[Finding], fmt: str = "text", mode: str | None = None
) -> int:
    if not findings:
        if fmt == "text":
            scope = f" ({mode})" if mode else ""
            print(f"REPO ENGINE: PASS{scope}")
        elif fmt == "json":
            print(
                json.dumps(
                    {
                        "mode": mode or "unknown",
                        "findings": [],
                        "summary": {"total": 0, "critical": 0, "warning": 0, "info": 0},
                    }
                )
            )
        elif fmt == "sarif":
            print(json.dumps(sarif_report(findings), indent=2))
        return 0

    if fmt == "text":
        scope = f" ({mode})" if mode else ""
        print(f"REPO ENGINE: BLOCKED{scope}\n")
        for finding in findings:
            sev = finding.severity.upper()
            print(f"[{sev}] {finding.rule:<16} {finding.path}\n  {finding.detail}")
        print("\nNothing was published. Resolve the findings or request human review.")
        return 1

    if fmt == "json":
        summary_counts = {"critical": 0, "warning": 0, "info": 0}
        for f in findings:
            summary_counts[f.severity] += 1
        print(
            json.dumps(
                {
                    "mode": mode or "unknown",
                    "findings": [
                        {
                            "rule": f.rule,
                            "path": f.path,
                            "detail": f.detail,
                            "severity": f.severity,
                        }
                        for f in findings
                    ],
                    "summary": {"total": len(findings), **summary_counts},
                }
            )
        )
        return 1

    if fmt == "sarif":
        print(json.dumps(sarif_report(findings), indent=2))
        return 1

    return 1


def print_outcome(outcome: audit.Outcome, fmt: str = "text") -> int:
    summary_counts = {"critical": 0, "warning": 0, "info": 0}
    for finding in outcome.findings:
        summary_counts[finding.severity] += 1
    coverage = {
        "candidates": outcome.candidates,
        "scanned": outcome.scanned,
        "skipped": outcome.skipped,
    }
    if fmt == "json":
        print(
            json.dumps(
                {
                    "status": outcome.status,
                    "mode": outcome.mode,
                    "policy": outcome.policy,
                    "blocking": len(outcome.blocking),
                    "coverage": coverage,
                    "findings": [
                        {
                            "rule": finding.rule,
                            "path": finding.path,
                            "detail": finding.detail,
                            "severity": finding.severity,
                        }
                        for finding in outcome.findings
                    ],
                    "summary": {
                        "total": len(outcome.findings),
                        **summary_counts,
                    },
                }
            )
        )
        return outcome.exit_code
    if fmt == "sarif":
        report = sarif_report(outcome.findings)
        report["runs"][0]["properties"] = {
            "status": outcome.status,
            "mode": outcome.mode,
            "coverage": coverage,
        }
        print(json.dumps(report, indent=2))
        return outcome.exit_code

    print(f"REPO ENGINE: {outcome.status} ({outcome.mode}, policy: {outcome.policy})")
    print(
        f"Coverage: candidates={outcome.candidates} "
        f"scanned={outcome.scanned} skipped={len(outcome.skipped)}"
    )
    for skipped in outcome.skipped:
        print(f"[SKIPPED] {skipped['path']} ({skipped['reason']})")
    blocking = outcome.blocking
    if outcome.findings:
        print()
        for finding in blocking + outcome.notes:
            tag = finding.severity.upper() if finding in blocking else "NOTE"
            print(f"[{tag}] {finding.rule:<16} {finding.path}\n  {finding.detail}")
    if blocking:
        print("\nNothing was published. Resolve the findings or request human review.")
    elif outcome.findings:
        print("\nNo blocking findings; the notes above do not stop publication.")
    elif outcome.status == "NO_SURFACE":
        print("No candidate content was audited; public-boundary cleanliness is not established.")
    elif outcome.status == "INCOMPLETE_COVERAGE":
        print("Some candidate content was not audited; public-boundary cleanliness is not established.")
    return outcome.exit_code


def sarif_report(findings: list[Finding]) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Repo Engine",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/DannyBaanks/repo-engine",
                        "rules": [
                            {
                                "id": rule,
                                "shortDescription": {"text": rule},
                                "defaultConfiguration": {"level": sev},
                            }
                            for rule, sev in SEVERITY.items()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule,
                        "level": f.severity,
                        "message": {"text": f.detail},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": f.path}}}
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }


def check_links(repo: Path) -> list[str]:
    problems: list[str] = []
    for markdown in repo.rglob("*.md"):
        if ".git" in markdown.parts:
            continue
        text = markdown.read_text(encoding="utf-8", errors="replace")
        for target in re.findall(r"\]\(([^)#]+)(?:#[^)]+)?\)", text):
            if "://" not in target and not (markdown.parent / target).exists():
                problems.append(
                    f"broken local link: {markdown.relative_to(repo)} -> {target}"
                )
    return problems


def project_checks(repo: Path) -> list[str]:
    failures: list[str] = []
    if (repo / "pyproject.toml").exists():
        commands = [[sys.executable, "-m", "pytest", "-q"]]
        if shutil.which("ruff"):
            commands.append(["ruff", "check", "."])
        for command in commands:
            result = subprocess.run(
                command, cwd=repo, text=True, capture_output=True, check=False
            )
            if result.returncode:
                failures.append(
                    f"failed: {' '.join(command)}\n{result.stdout}{result.stderr}".strip()
                )
    failures.extend(check_links(repo))
    return failures


def init_repo(args: argparse.Namespace) -> int:
    repo = Path(args.repo or ".").resolve()
    if not repo.is_dir():
        raise RuntimeError(f"repository directory does not exist: {repo}")
    template = select(args.template, repo)
    if not git.is_repo(repo):
        git.run(repo, "init")
    marker_path = repo / ".repo-engine.toml"
    if marker_path.exists() and not args.reconfigure:
        raise RuntimeError(
            f"{marker_path} already exists; rerun with --reconfigure to change its template"
        )
    install(repo, args.adopt_existing_hook)
    marker_path.write_text(marker(template), encoding="utf-8")
    register_repo(repo)
    print(f"REPO ENGINE: registered {repo}\n{summary(template)}")
    return 0


def list_templates(_: argparse.Namespace) -> int:
    for template in all_templates().values():
        print(summary(template))
        print()
    return 0


def push_updates() -> list[tuple[str, str, str, str]] | None:
    """Lines git feeds to pre-push on stdin; None when not run as a hook."""
    if sys.stdin is None or sys.stdin.isatty():
        return None
    updates = []
    for line in sys.stdin.read().splitlines():
        fields = line.split()
        if len(fields) == 4:
            updates.append((fields[0], fields[1], fields[2], fields[3]))
    return updates or None


def gate(args: argparse.Namespace) -> int:
    repo = repo_path(args.repo)
    outcome = (
        audit.staged_outcome(repo)
        if args.gate == "commit"
        else audit.outgoing_outcome(repo, push_updates(), getattr(args, "remote", None))
    )
    fmt = getattr(args, "format", "text")
    if outcome.status == "NO_SURFACE" and fmt == "text":
        # Nothing staged / nothing new leaves the machine: there is no content that
        # could leak. Blocking here only teaches people to use --no-verify.
        print(f"REPO ENGINE: PASS (nothing to audit: {outcome.mode})")
        return 0
    return print_outcome(outcome, fmt)


def audit_cmd(args: argparse.Namespace) -> int:
    repo = repo_path(args.repo)
    required = args.policy == "required"
    if args.staged:
        outcome = audit.staged_outcome(repo)
    else:
        outcome = audit.outgoing_outcome(
            repo, rev_range=args.range, policy_required=required
        )
    return print_outcome(outcome, args.format)


def history_cmd(args: argparse.Namespace) -> int:
    repo = repo_path(args.repo)
    findings = audit.history(repo)
    return print_findings(findings, args.format)


def startup(args: argparse.Namespace) -> int:
    if args.install_task:
        method = install_task()
        print(f"REPO ENGINE: startup registration installed via {method}")
        return 0
    problems = health()
    if problems:
        message = "REPO ENGINE HEALTH: ATTENTION\n\n" + "\n".join(problems)
        print(message)
        notify(message)
        return 1
    return 0


def package_repo(args: argparse.Namespace) -> int:
    repo = repo_path(args.repo)
    out = shell.package(repo)
    print(f"REPO ENGINE: dashboard written to {out}")
    return 0


def analyze_repo(args: argparse.Namespace) -> int:
    raw = getattr(args, "path", None) or getattr(args, "repo", None)
    target = Path(raw or ".").resolve()
    if not target.exists():
        raise RuntimeError(f"target does not exist: {target}")
    if getattr(args, "git_only", False) and git.is_repo(target):
        outcome = audit.candidate_outcome(target, strict_policy=False)
    else:
        outcome = audit.analyze_any_outcome(target)
    return print_outcome(outcome, args.format)


def doctor(args: argparse.Namespace) -> int:
    repo = repo_path(args.repo)
    print(f"REPO ENGINE DOCTOR: {repo}")
    print()

    # Config
    cfg = config()
    pol = cfg.get("policy_path", "")
    print(f"  Policy path: {pol if pol else 'NOT SET'}")
    print(f"  Policy exists: {Path(pol).exists() if pol else False}")

    # Marker
    marker_path = repo / ".repo-engine.toml"
    marker_ok = marker_path.exists()
    if marker_ok:
        print(f"  Marker: {marker_path.read_text(encoding='utf-8').strip()}")
    else:
        print("  Marker: NOT FOUND")

    # Hooks
    pre_commit = repo / ".git" / "hooks" / "pre-commit"
    pre_push = repo / ".git" / "hooks" / "pre-push"
    hooks_ok = pre_commit.exists() and pre_push.exists()
    print(f"  pre-commit hook: {'installed' if pre_commit.exists() else 'MISSING'}")
    print(f"  pre-push hook: {'installed' if pre_push.exists() else 'MISSING'}")

    # Exceptions
    exc_path = repo / ".repo-engine-exceptions.toml"
    if exc_path.exists():
        print(f"  Exceptions file: {exc_path} (exists)")
    else:
        print("  Exceptions file: not present")

    # Tracked files count
    tracked = git.run(repo, "ls-files").splitlines()
    print(f"  Tracked files: {len(tracked)}")

    # Candidate scan includes tracked and non-ignored untracked files without staging.
    outcome = audit.candidate_outcome(repo)
    crit = sum(1 for f in outcome.findings if f.severity == "critical")
    warn = sum(1 for f in outcome.findings if f.severity == "warning")
    info = sum(1 for f in outcome.findings if f.severity == "info")
    print(f"  Audit status: {outcome.status} ({outcome.mode})")
    print(
        f"  Coverage: {outcome.scanned}/{outcome.candidates} scanned, "
        f"{len(outcome.skipped)} skipped"
    )
    print(
        f"  Findings: {len(outcome.findings)} total "
        f"(critical: {crit}, warning: {warn}, info: {info})"
    )

    if crit:
        print("\n  CRITICAL findings:")
        for f in outcome.findings:
            if f.severity == "critical":
                print(f"    [{f.rule}] {f.path} - {f.detail}")
    if not marker_ok or not hooks_ok:
        return 2
    return outcome.exit_code


def configure(args: argparse.Namespace) -> int:
    data = config()
    data["policy_path"] = str(Path(args.policy_path).resolve())
    save_json(CONFIG_PATH, data)
    print("REPO ENGINE: private policy configured")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="repo-engine")
    sub = parser.add_subparsers(dest="command", required=True)

    configure_parser = sub.add_parser("configure")
    configure_parser.add_argument("--policy-path", required=True)
    configure_parser.set_defaults(func=configure)

    init_parser = sub.add_parser("init")
    init_parser.add_argument("repo", nargs="?")
    init_parser.add_argument("--adopt-existing-hook", action="store_true")
    init_parser.add_argument("--template")
    init_parser.add_argument("--reconfigure", action="store_true")
    init_parser.set_defaults(func=init_repo)

    templates_parser = sub.add_parser("templates")
    templates_parser.set_defaults(func=list_templates)

    gate_parser = sub.add_parser("gate")
    gate_parser.add_argument("gate", choices=("commit", "push"))
    gate_parser.add_argument("--repo")
    gate_parser.add_argument("--remote", help="push destination (pre-push passes $1)")
    gate_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    gate_parser.set_defaults(func=gate)

    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--staged", action="store_true")
    audit_parser.add_argument("--repo")
    audit_parser.add_argument(
        "--range", help="audit exactly BASE..HEAD (CI: the commits a pull request adds)"
    )
    audit_parser.add_argument(
        "--policy", choices=("required", "optional"), default="required",
        help="optional: run base rules when the private policy is not available (CI)",
    )
    audit_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    audit_parser.set_defaults(func=audit_cmd)

    history_parser = sub.add_parser("history")
    history_parser.add_argument("--repo")
    history_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    history_parser.set_defaults(func=history_cmd)

    startup_parser = sub.add_parser("startup")
    startup_parser.add_argument("--install-task", action="store_true")
    startup_parser.set_defaults(func=startup)

    package_parser = sub.add_parser("package")
    package_parser.add_argument("--repo")
    package_parser.set_defaults(func=package_repo)

    analyze_parser = sub.add_parser(
        "analyze",
        help="audit any file or directory; Git-aware when inside a repository",
    )
    analyze_parser.add_argument("path", nargs="?", help="file or folder to audit (default: cwd)")
    analyze_parser.add_argument("--repo", help="deprecated alias for positional path")
    analyze_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    analyze_parser.add_argument(
        "--git-only", action="store_true",
        help="only audit git-tracked files (skip filesystem walk)"
    )
    analyze_parser.set_defaults(func=analyze_repo)

    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--repo")
    doctor_parser.set_defaults(func=doctor)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (RuntimeError, git.GitError) as error:
        print(f"REPO ENGINE: ERROR\n{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
