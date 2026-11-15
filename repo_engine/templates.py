from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import ROOT


def all_templates() -> dict[str, dict]:
    templates = {}
    for path in sorted((ROOT / "templates").glob("*.json")):
        template = json.loads(path.read_text(encoding="utf-8"))
        templates[template["id"]] = template
    return templates


def infer(repo: Path) -> dict | None:
    """Infer only when the repository contains direct product evidence."""
    templates = all_templates()
    markdown = []
    for path in repo.rglob("*.md"):
        if ".git" in path.parts:
            continue
        try:
            markdown.append(path.read_text(encoding="utf-8", errors="replace")[:262144])
        except OSError:
            continue
    text = "\n".join(markdown).lower()
    if "hackathon" in text:
        return templates["hackathon"]
    has_evidence = any(
        path.is_dir() and path.name.lower() == "evidence"
        for path in repo.rglob("evidence")
    )
    has_method = any(
        "spec" in path.name.lower() or "method" in path.name.lower()
        for path in repo.rglob("*.md")
        if ".git" not in path.parts
    )
    if has_evidence and has_method:
        return templates["research-demo"]
    return None


def select(template_id: str | None, repo: Path | None = None) -> dict:
    templates = all_templates()
    if template_id:
        if template_id in templates:
            return templates[template_id]
        raise RuntimeError(
            f"unknown template '{template_id}'; run repo-engine templates"
        )
    inferred = infer(repo) if repo is not None else None
    if inferred is not None:
        return inferred
    if not sys.stdin.isatty():
        raise RuntimeError(
            "choose a template with --template; run repo-engine templates"
        )
    choices = list(templates.values())
    print("Choose a Repo Engine template:")
    for index, template in enumerate(choices, start=1):
        print(f"  {index}. {template['label']} - {template['purpose']}")
    try:
        return choices[int(input("Template number: ")) - 1]
    except (ValueError, IndexError) as error:
        raise RuntimeError("invalid template selection") from error


def marker(template: dict) -> str:
    requirements = ", ".join(f'"{item}"' for item in template["required_artifacts"])
    return (
        "[repo_engine]\n"
        f'template = "{template["id"]}"\n'
        'phase = "building"\n'
        f'visual_language = "{template["visual_language"]}"\n'
        f"required_artifacts = [{requirements}]\n"
    )


def summary(template: dict) -> str:
    return (
        f"{template['label']}\n"
        f"Purpose: {template['purpose']}\n"
        f"Visual language: {template['visual_language']}\n"
        f"Required: {', '.join(template['required_artifacts'])}\n"
        f"Release checks: {', '.join(template['release_checks'])}"
    )
