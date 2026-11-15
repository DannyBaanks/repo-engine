from __future__ import annotations

from pathlib import Path

import pytest

from repo_engine.policy import policy_sections, scan_file


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.md"
    p.write_text(
        "## Unique internal names\n"
        "- ExampleTerm5\n"
        "- ExampleTerm4\n\n"
        "## Internal phrases\n"
        "- ExampleTerm2\n"
        "- ExampleTerm1\n\n"
        "## Internal concept patterns\n"
        "- ExampleTerm3\n",
        encoding="utf-8",
    )
    return p


def test_policy_sections(policy_file: Path) -> None:
    sections = policy_sections(policy_file)
    assert "unique internal names" in sections
    assert "ExampleTerm5" in sections["unique internal names"]
    assert "ExampleTerm2" in sections["internal phrases"]


def test_scan_detects_unique_name(tmp_path: Path) -> None:
    f = tmp_path / "readme.md"
    f.write_text("This uses ExampleTerm5 internally", encoding="utf-8")
    sections = {
        "unique internal names": ["ExampleTerm5"],
        "internal phrases": [],
        "internal concept patterns": [],
    }
    findings = scan_file(f, sections, set())
    assert any(f.rule == "POLICY_NAME" for f in findings)


def test_scan_ignores_generic_word(tmp_path: Path) -> None:
    f = tmp_path / "readme.md"
    f.write_text("We use a registry pattern here", encoding="utf-8")
    sections = {
        "unique internal names": [],
        "internal phrases": [],
        "internal concept patterns": [],
    }
    findings = scan_file(f, sections, set())
    assert findings == []


def test_scan_detects_phrase(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("from internal_engine import something", encoding="utf-8")
    sections = {
        "unique internal names": [],
        "internal phrases": ["internal_engine"],
        "internal concept patterns": [],
    }
    findings = scan_file(f, sections, set())
    assert any(f.rule == "POLICY_PHRASE" for f in findings)


def test_scan_concept_requires_context(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("The ExampleTerm3 engine runs here", encoding="utf-8")
    sections = {
        "unique internal names": [],
        "internal phrases": [],
        "internal concept patterns": ["ExampleTerm3"],
    }
    findings = scan_file(f, sections, set())
    assert any(f.rule == "POLICY_CONCEPT" for f in findings)


def test_scan_concept_without_context(tmp_path: Path) -> None:
    f = tmp_path / "readme.md"
    f.write_text("This is a pipeline for data", encoding="utf-8")
    sections = {
        "unique internal names": [],
        "internal phrases": [],
        "internal concept patterns": ["ExampleTerm3"],
    }
    findings = scan_file(f, sections, set())
    assert findings == []


def test_scan_file_skips_directories(tmp_path: Path) -> None:
    sections = {
        "unique internal names": ["ExampleTerm5"],
        "internal phrases": [],
        "internal concept patterns": [],
    }
    findings = scan_file(tmp_path, sections, set())
    assert findings == []
