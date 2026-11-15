from __future__ import annotations

from pathlib import Path

from .config import ROOT


def hook_body(gate: str, repo: Path) -> str:
    python = Path(__import__("sys").executable).as_posix()
    entrypoint = (ROOT / "repo-engine.py").as_posix()
    # pre-push recibe el remoto destino en $1: solo lo que ya esta en ESE remoto
    # se considera publicado (un fork publico no hereda lo de un origin privado).
    remote = ' --remote "$1"' if gate == "push" else ""
    return (
        f'#!/bin/sh\n"{python}" "{entrypoint}" gate {gate} --repo "{repo.as_posix()}"{remote}\n'
    )


def install(repo: Path, adopt: bool) -> None:
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    for name, gate in (("pre-commit", "commit"), ("pre-push", "push")):
        target = hooks_dir / name
        legacy = hooks_dir / f"{name}.repo-engine-legacy"
        if target.exists() and not legacy.exists():
            existing = target.read_text(encoding="utf-8", errors="replace")
            managed = "repo-engine.py" in existing and f"gate {gate}" in existing
            if not adopt and not managed:
                raise RuntimeError(
                    f"{target} already exists; rerun with --adopt-existing-hook"
                )
            if not managed:
                target.rename(legacy)
        body = hook_body(gate, repo)
        if legacy.exists():
            body += f'"{legacy.as_posix()}" "$@"\n'
        target.write_text(body, encoding="utf-8", newline="\n")
        # Sin bit de ejecucion git ignora el hook en silencio (Linux/macOS). 0755 fijo:
        # un hook escribible por otros (p.ej. 0666 heredado de Windows) es inyectable.
        target.chmod(0o755)
