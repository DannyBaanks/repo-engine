from repo_engine.policy import scan
from repo_engine.templates import marker

# Armados por partes: el propio repo de la compuerta no debe contener rutas privadas
# ni tokens con forma real como literales.
WIN_PRIVATE = b"C:\\" + b"Users\\alice\\private"
LINUX_PRIVATE = b"/home" + b"/alice/private"
GH_TOKEN_SHAPE = b"gh" + b"p_abcdefghijklmnopqrstuvwxyz123456"

SECTIONS = {
    "unique internal names": ["Example Private Name"],
    "internal phrases": [],
    "internal concept patterns": [],
}


def test_scans_unique_policy_name() -> None:
    findings = scan(
        "README.md",
        b"This exposes Example Private Name.",
        SECTIONS,
        set(),
    )
    assert findings[0].rule == "POLICY_NAME"


def test_scans_private_workstation_paths() -> None:
    # Desde a5724a63 (2026-08-31) la regla se subclasifica por contexto: en codigo
    # es critica, en documentacion es info. En ambos casos se detecta y bloquea.
    code = scan("tool.py", WIN_PRIVATE, {}, set())
    assert [(f.rule, f.severity) for f in code] == [("LOCAL_PATH_001", "critical")]
    doc = scan("notes.txt", WIN_PRIVATE, {}, set())
    assert [(f.rule, f.severity) for f in doc] == [("LOCAL_PATH_001_DOC", "info")]
    linux = scan("run.sh", LINUX_PRIVATE, {}, set())
    assert [f.rule for f in linux] == ["LOCAL_PATH_001"]


def test_scans_secret_like_content() -> None:
    findings = scan(
        "config.txt", b"token=" + GH_TOKEN_SHAPE, {}, set()
    )
    assert findings[0].rule == "SECRET_001"


def test_skips_explicit_exception() -> None:
    assert (
        scan(
            "docs/example.md",
            b"Example Private Name",
            SECTIONS,
            {("docs/example.md", "Example Private Name")},
        )
        == []
    )


def test_ignores_generic_words() -> None:
    findings = scan("code.py", b"We use a registry here", {}, set())
    assert findings == []


def test_template_marker_contains_its_public_contract() -> None:
    contract = {
        "id": "hackathon",
        "visual_language": "evidence dashboard",
        "required_artifacts": ["README.md", "demo"],
    }
    assert 'template = "hackathon"' in marker(contract)
    assert 'required_artifacts = ["README.md", "demo"]' in marker(contract)
