from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import config as _config


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    detail: str
    severity: str = "warning"


SEVERITY = {
    "FILE_001": "critical",
    "SECRET_001": "critical",
    "SECRET_002": "critical",
    "SECRET_003": "critical",
    "LOCAL_PATH_001": "critical",
    "LOCAL_PATH_001_ENVVAR": "warning",
    "LOCAL_PATH_001_DOC": "info",
    "POLICY_NAME": "warning",
    "POLICY_PHRASE": "warning",
    "POLICY_CONCEPT": "info",
}


# Que bloquea (decision 2026-11-15, aplicando la regla de la politica privada):
# todo bloquea salvo estas notas. Secretos, rutas privadas en codigo y las reglas de
# la politica privada (nombre / frase / concepto: "STOP and request human review")
# siguen bloqueando aunque su severidad no sea "critical".
NON_BLOCKING_RULES = frozenset({"LOCAL_PATH_001_DOC", "LOCAL_PATH_001_ENVVAR"})


def is_blocking(finding: Finding) -> bool:
    return finding.rule not in NON_BLOCKING_RULES


SECRET_PATTERNS = (
    ("SECRET_001", re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("SECRET_002", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SECRET_003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
# Rutas privadas, sin nada especifico de nadie en el codigo:
# 1) cualquier carpeta personal: /home/<usuario>, /Users/<usuario>, C:\Users\<usuario>
#    (salvo nombres de ejemplo), y
# 2) las rutas extra de la config local ("private_paths" en repo-engine.json).
# Todo se compara en minusculas.
_HOME_RE = re.compile(
    r"(?:(?<![a-z0-9._~-])/home/|(?<![a-z0-9._~-])/users/|(?<![a-z0-9])[a-z]:[\\/]+users[\\/]+)"
    r"(?P<user>[a-z0-9][a-z0-9._-]*)"
)
PLACEHOLDER_USERS = frozenset({
    "user", "username", "usuario", "you", "your", "yourname", "your-name", "your_name",
    "me", "name", "example", "runner", "ubuntu", "vscode", "node", "app", "admin",
    "default", "public", "shared", "guest", "test", "tester", "foo", "bar", "someone",
    "john", "jane", "johndoe", "dev", "developer", "linuxbrew", "all users",
})


def _configured(key: str) -> list[str]:
    values = _config.config().get(key, [])
    return [v.lower() for v in values if isinstance(v, str) and v.strip()]


def private_path_terms(text_lower: str) -> list[str]:
    """Private paths present in an already-lowercased text, as exception terms."""
    terms = [p for p in _configured("private_paths") if p in text_lower]
    for m in _HOME_RE.finditer(text_lower):
        if m.group("user") in PLACEHOLDER_USERS:
            continue
        if m.group(0) not in terms:
            terms.append(m.group(0))
    return terms


FORBIDDEN_NAMES = (".env", "id_rsa", "id_ed25519")
FORBIDDEN_SUFFIXES = (".pem", ".key", ".p12", ".pfx")

# Un concepto de la politica solo cuenta si el texto habla de implementacion. Palabras
# genericas; cada quien agrega las suyas con "concept_context" en la config local o con
# una seccion "## Concept context words" en su politica.
DEFAULT_CONCEPT_CONTEXT = ("engine", "orchestrat", "pipeline", "capability")


def _concept_context(sections: dict[str, list[str]]) -> re.Pattern:
    words = [*DEFAULT_CONCEPT_CONTEXT, *_configured("concept_context"),
             *(w.lower() for w in sections.get("concept context words", []))]
    return re.compile(r"(?i)\b(?:" + "|".join(re.escape(w) for w in words) + r")\b")

_LOCAL_PATH_ENVVAR = re.compile(
    r"os\.environ\.(?:get|__getitem__)\s*\(\s*[\"']", re.IGNORECASE
)
_LOCAL_PATH_DOC_EXTS = {".md", ".rst", ".txt"}


def _classify_local_path(text: str, path: str, term: str) -> tuple[str, str]:
    """Classify a LOCAL_PATH_001 finding by context.

    Returns (rule, severity):
      - LOCAL_PATH_001         (critical): hardcoded path in executable code
      - LOCAL_PATH_001_ENVVAR  (warning):  inside os.environ.get() fallback
      - LOCAL_PATH_001_DOC     (info):     in documentation / evidence
    """
    # Cada aparicion se clasifica por separado y gana la mas grave: antes el archivo
    # entero tomaba la clase de la PRIMERA aparicion, y un os.environ.get() cerca de
    # ella rebajaba tambien las rutas escritas a fuego en el resto del archivo.
    is_doc = Path(path).suffix.lower() in _LOCAL_PATH_DOC_EXTS
    lines = text.splitlines()
    classes = set()
    for i, line in enumerate(lines):
        if term not in line.lower():
            continue
        ctx = "\n".join(lines[max(0, i - 2) : i + 3])  # esta linea y ±2 (llamadas multilinea)
        if _LOCAL_PATH_ENVVAR.search(ctx):
            classes.add("LOCAL_PATH_001_ENVVAR")
        elif is_doc:
            classes.add("LOCAL_PATH_001_DOC")
        else:
            classes.add("LOCAL_PATH_001")
    for rule in ("LOCAL_PATH_001", "LOCAL_PATH_001_ENVVAR", "LOCAL_PATH_001_DOC"):
        if rule in classes:
            return (rule, SEVERITY[rule])
    # La ruta cruza lineas o solo aparece normalizada: tratarla como codigo.
    return ("LOCAL_PATH_001", SEVERITY["LOCAL_PATH_001"])


# Contenido sintetico verificable para fixtures de secretos: un marcador explicito
# como palabra (no incrustado en base62 aleatorio) o un cuerpo de muy baja entropia.
_SYNTHETIC_MARKER = re.compile(
    r"(?i)(?:^|[^a-z])(?:fake|dummy|example|sample|placeholder|redacted|test|"
    r"notreal|not[-_]real|not[-_]a[-_]real)(?:[^a-z]|$)"
)
_SECRET_PREFIX = re.compile(r"^(?:ghp_|gho_|github_pat_|sk-)")
_PEM_REAL_BODY = 64  # caracteres base64 tras la cabecera a partir de los cuales parece una clave real


def is_synthetic_secret(value: str) -> bool:
    body = _SECRET_PREFIX.sub("", value)
    return bool(_SYNTHETIC_MARKER.search(value)) or len(set(body)) <= 4


class Exceptions(set):
    """(path, term) pairs as before, plus narrow secret fixtures."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.secret_fixtures: list[dict[str, str]] = []
        self.rejected: dict[tuple[str, str], str] = {}


def _validate_fixture(item: object) -> tuple[dict[str, str] | None, str]:
    if not isinstance(item, dict):
        return None, "entry is not a table"
    rule, path, value = item.get("rule"), item.get("path"), item.get("value")
    if not (isinstance(rule, str) and isinstance(path, str) and isinstance(value, str)
            and rule and path and value):
        return None, "rule, path and value are all required"
    patterns = dict(SECRET_PATTERNS)
    if rule not in patterns:
        return None, f"{rule} is not a secret rule"
    if (
        any(ch in path for ch in "*?[]")
        or path.endswith("/")
        or path in (".", "")
        or ".." in Path(path).parts
    ):
        return None, "path must be one exact file (no globs, no directories)"
    if not patterns[rule].fullmatch(value):
        return None, f"value is not a {rule} match"
    if rule != "SECRET_003" and not is_synthetic_secret(value):
        return None, "value is not verifiably synthetic (needs a marker word or low entropy)"
    return {"rule": rule, "path": path, "value": value}, ""


def load_exceptions(repo: Path) -> Exceptions:
    exc_path = repo / ".repo-engine-exceptions.toml"
    if not exc_path.exists():
        return Exceptions()
    with open(exc_path, "rb") as f:
        data = tomllib.load(f)
    exc = Exceptions()
    for item in data.get("secret_fixture", []):
        fixture, reason = _validate_fixture(item)
        if fixture:
            exc.secret_fixtures.append(fixture)
        elif isinstance(item, dict):
            exc.rejected[(str(item.get("rule")), str(item.get("path")))] = reason
    for items in data.get("exceptions", {}).values():
        for item in items:
            if ":" in item:
                path, term = item.split(":", 1)
                exc.add((path, term))
            else:
                exc.add((item, ""))
    return exc


def policy_sections(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    sections: dict[str, list[str]] = {}
    current = "default"
    for line in path.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^##\s+(.+)", line)
        if heading:
            current = heading.group(1).strip().lower()
            sections[current] = []
            continue
        item = re.match(r"^-\s+(.+?)\s*$", line)
        if item and current in sections:
            sections[current].append(item.group(1))
    return sections


def scan(
    path: str,
    blob: bytes,
    sections: dict[str, list[str]],
    exceptions: set[tuple[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    name = Path(path).name.lower()
    if name in FORBIDDEN_NAMES or name.endswith(FORBIDDEN_SUFFIXES):
        findings.append(
            Finding(
                "FILE_001", path, "private credential filename", SEVERITY["FILE_001"]
            )
        )

    text = blob.decode("utf-8", "replace")
    lower = text.lower()
    # El detalle nunca incluye la ruta: en CI de un repo publico el log es publico.
    for local_path in private_path_terms(lower):
        if (path, local_path) not in exceptions:
            rule, sev = _classify_local_path(text, path, local_path)
            findings.append(Finding(rule, path, "private workstation path", sev))
    for rule, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            verdict = _fixture_verdict(rule, path, text, match, exceptions)
            if verdict is True:
                continue
            detail = "credential-like content"
            if verdict:
                detail += f" (exception rejected: {verdict})"
            findings.append(Finding(rule, path, detail, SEVERITY[rule]))
            break

    for term in sections.get("unique internal names", []):
        if term.lower() in lower and (path, term) not in exceptions:
            findings.append(
                Finding(
                    "POLICY_NAME",
                    path,
                    f"private policy name: {term}",
                    SEVERITY["POLICY_NAME"],
                )
            )

    for phrase in sections.get("internal phrases", []):
        if phrase.lower() in lower and (path, phrase) not in exceptions:
            findings.append(
                Finding(
                    "POLICY_PHRASE",
                    path,
                    f"private policy phrase: {phrase}",
                    SEVERITY["POLICY_PHRASE"],
                )
            )

    concepts = sections.get("internal concept patterns", [])
    context = _concept_context(sections) if concepts else None
    for concept in concepts:
        if (
            concept.lower() in lower
            and (path, concept) not in exceptions
            and context is not None
            and context.search(text)
        ):
            findings.append(
                Finding(
                    "POLICY_CONCEPT",
                    path,
                    f"private policy concept: {concept}",
                    SEVERITY["POLICY_CONCEPT"],
                )
            )

    return findings


def _fixture_verdict(
    rule: str, path: str, text: str, match: re.Match, exceptions: set
) -> bool | str | None:
    """True = declared synthetic fixture; str = why an exception does not apply;
    None = no exception declared for this rule and file."""
    validated = getattr(exceptions, "secret_fixtures", [])
    if path == ".repo-engine-exceptions.toml" and any(
        f["rule"] == rule and f["value"] == match.group(0) for f in validated
    ):
        return True  # the declaration itself; only values that passed validation
    rejected = getattr(exceptions, "rejected", {}).get((rule, path))
    fixtures = [
        f for f in getattr(exceptions, "secret_fixtures", [])
        if f["rule"] == rule and f["path"] == path
    ]
    if not fixtures:
        return rejected
    if not any(f["value"] == match.group(0) for f in fixtures):
        return "value differs from the declared fixture"
    if rule == "SECRET_003":
        end = text.find("-----END", match.end())
        body = text[match.end() : end if end != -1 else len(text)]
        if len(re.sub(r"[^A-Za-z0-9+/=]", "", body)) >= _PEM_REAL_BODY:
            return "PEM body looks like a real key"
    return True


def scan_file(
    path: Path,
    sections: dict[str, list[str]],
    exceptions: set[tuple[str, str]],
    rel_path: str | None = None,
) -> list[Finding]:
    if not path.is_file():
        return []
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    return scan(rel_path or str(path), blob, sections, exceptions)
