from __future__ import annotations

from pathlib import Path

import pytest

from repo_engine.shell import artifact_status, read_marker, render_dashboard


@pytest.fixture()
def fake_repo(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text("# Test", encoding="utf-8")
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "index.html").write_text("<html></html>", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push", encoding="utf-8")
    (tmp_path / ".repo-engine.toml").write_text(
        '[repo_engine]\ntemplate = "hackathon"\nphase = "building"\n'
        'visual_language = "evidence dashboard"\n'
        'required_artifacts = ["README.md", "demo", "evidence", ".github/workflows"]\n',
        encoding="utf-8",
    )
    return tmp_path


def test_read_marker(fake_repo: Path) -> None:
    marker = read_marker(fake_repo)
    assert marker["template"] == "hackathon"
    assert marker["phase"] == "building"


def test_artifact_status(fake_repo: Path) -> None:
    results = artifact_status(
        fake_repo, ["README.md", "demo", "evidence", ".github/workflows"]
    )
    names = {r["name"]: r["present"] for r in results}
    assert names["README.md"] is True
    assert names["demo"] is True
    assert names["evidence"] is False
    assert names[".github/workflows"] is True


def test_render_dashboard(fake_repo: Path) -> None:
    marker = read_marker(fake_repo)
    from repo_engine.templates import all_templates

    template = all_templates()["hackathon"]
    html = render_dashboard(fake_repo, marker, template)
    assert "hackathon" in html.lower() or "Hackathon" in html
    assert "README.md" in html
    assert "evidence missing" in html.lower() or "missing" in html
