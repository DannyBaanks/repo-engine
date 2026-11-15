# Repo Engine

Compuerta de publicación para repositorios Git: revisa lo que entra en cada commit y lo que
sale en cada push, y bloquea credenciales, rutas privadas de tu máquina y términos que
declaraste como "no publicar". También corre en CI sobre lo que agrega cada pull request.

> Los hooks locales son defensa adicional: `git commit --no-verify` y `git push --no-verify`
> los saltan. La garantía es el check de CI exigido por un ruleset de GitHub (ver abajo).

## Qué bloquea y qué no

| Regla | Ejemplo | ¿Bloquea? |
|---|---|---|
| `SECRET_001/002/003` | tokens de GitHub, claves `sk-…`, claves privadas PEM | sí |
| `FILE_001` | `.env`, `id_rsa`, `*.pem`, `*.key` … | sí |
| `LOCAL_PATH_001` | ruta privada escrita en código | sí |
| `POLICY_NAME` / `POLICY_PHRASE` / `POLICY_CONCEPT` | términos de tu política privada | sí ("STOP and request human review") |
| `LOCAL_PATH_001_DOC` | ruta privada en documentación | no: nota |
| `LOCAL_PATH_001_ENVVAR` | ruta como valor por defecto de una variable de entorno | no: nota |

Sin nada que auditar (amend solo de mensaje, push de una rama sin commits nuevos) la
compuerta pasa.

## Uso local

```sh
python3 repo-engine.py configure --policy-path /ruta/a/politica-privada.md
python3 repo-engine.py init /ruta/al/repo --template research-demo   # instala pre-commit y pre-push (0755)
python3 repo-engine.py analyze /cualquier/carpeta                      # auditoría sin registrar nada
python3 repo-engine.py audit --repo . --range BASE..HEAD --policy optional
```

`pre-push` audita exactamente las refs que se empujan (no `HEAD`) y considera publicado
solo lo que ya está en el remoto destino.

## Rutas privadas

Se detecta cualquier carpeta personal: `/home/<usuario>`, `/Users/<usuario>`,
`C:\Users\<usuario>` (salvo nombres de ejemplo como `user` o `runner`, y URLs). Para
rutas que no viven en tu home (un disco de trabajo, la carpeta de un cliente), agrégalas a
la config local:

```json
{ "policy_path": "/ruta/a/politica.md", "private_paths": ["D:/clientes/acme"] }
```

El hallazgo nunca imprime la ruta (los logs de CI de un repo público son públicos).

## Política privada

Un Markdown fuera de cualquier repo, con secciones `## Unique internal names`,
`## Internal phrases` e `## Internal concept patterns` (una entrada `- término` por línea).
Un concepto solo cuenta si el texto habla de implementación (`engine`, `pipeline`,
`capability`, `orchestrat…`); amplía esas palabras con `## Concept context words` en la
política o `"concept_context": [...]` en la config.
Nunca se publica: los hallazgos nombran el término, así que **el CI corre sin ella** por
defecto y la salida lo dice (`policy: base-rules-only`).

## Excepciones (`.repo-engine-exceptions.toml` en la raíz del repo)

```toml
[exceptions]                      # términos o rutas por archivo: "ruta:término"
docs = ["docs/arquitectura.md:NombreInterno"]

[[secret_fixture]]                # fixtures de prueba con forma de credencial
rule = "SECRET_002"
path = "tests/test_sanitize.py"   # UN archivo exacto: sin globs ni directorios
value = "sk-test-only-fixture-0000"
```

Un `secret_fixture` cubre una regla, un archivo y un valor exacto, y el valor debe ser
sintético verificable (una palabra-marcador como `test`, `fake`, `example`, `not-real`, o
entropía mínima). Un secreto real en el mismo archivo sigue bloqueando; las excepciones
que no cumplen se rechazan y el hallazgo dice por qué.

## CI

`action.yml` es una acción compuesta que corre `ci/run-ci.sh BASE HEAD`:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: DannyBaanks/repo-engine@<sha>
  with:
    base: ${{ github.event.pull_request.base.sha || github.event.before }}
    head: ${{ github.event.pull_request.head.sha || github.sha }}
```

Plantillas listas en `templates/ci/` (workflow y ruleset que exige PR + este check).
Detalles, decisiones y riesgos residuales: [`ci/README.md`](ci/README.md).

## Pruebas

```sh
python3 -m pytest -q                       # unidad, gates adversariales y CI local
tests/repo-engine-hooks.sh                 # commits y pushes reales en un sandbox
```
