# Repo Engine en CI — diseño (2026-11-15)

Los hooks locales son defensa adicional: `git commit --no-verify` y `git push --no-verify`
los saltan (medido: `tests/repo-engine-hooks.sh`, H10). La
garantía tiene que vivir en GitHub: un check que corre en el servidor y un ruleset que
lo exige antes de integrar a la rama por defecto.

## Piezas

| Pieza | Archivo | Qué hace |
|---|---|---|
| Script | `ci/run-ci.sh BASE HEAD` | audita exactamente los commits de `BASE..HEAD`; exit 0 sin bloqueantes, 1 bloqueado, 2 no se pudo auditar (cierra en falso) |
| Acción | `action.yml` | acción compuesta que llama a `run-ci.sh` |
| Workflow | `templates/ci/repo-engine.yml` | se copia a `.github/workflows/` de cada repo; job `repo-engine` en cada PR y push a la rama por defecto |
| Ruleset | `templates/ci/ruleset.json` | rama por defecto: sin borrado, sin force-push, PR obligatorio, check `repo-engine` obligatorio |
| Reproducción local | `tests/test_ci_local.py` | ejecuta el MISMO `run-ci.sh` sobre PRs simulados |

## Política privada en CI: por defecto NO

Los hallazgos de la política (`ISYCO_NAME`, `ISYCO_PHRASE`, `ISYCO_CONCEPT`) imprimen el
término, y en un repo público los logs de Actions son públicos: el CI publicaría
justo la lista de "no publicar". Por eso el CI corre con las **reglas base**: secretos,
rutas privadas y archivos de credenciales. La salida lo dice (`policy: base-rules-only`).
Los términos privados siguen cubiertos por los hooks locales. `inputs.policy` existe
para repos privados, desde un secreto de Actions, si algún día se decide.

## Requisitos sin resolver (decisión de Danny)

1. **Dónde vive la acción:** este repo (`DannyBaanks/repo-engine`), fijado por SHA.
2. **Rulesets en repos privados.** En una cuenta personal gratuita, los rulesets y la
   protección de ramas solo se aplican a repos públicos; OpenISy-v2 es privado.
3. **Aplicar el ruleset** es un cambio en GitHub: `gh api repos/OWNER/REPO/rulesets -X
   POST --input templates/ci/ruleset.json`, repo por repo, solo con autorización.

## Riesgos residuales

- El CI **detecta**; no impide que un push a una rama de feature ya deje el secreto en
  GitHub. Para eso: *secret scanning push protection* de GitHub (gratis en repos
  públicos; cubre formatos de token conocidos, no rutas ni nombres).
- Un administrador puede saltar el ruleset si se agrega a `bypass_actors` (el JSON lo
  deja vacío).
- `run-ci.sh` con base cero (primer push de una rama a la rama por defecto) sale con 2 y
  no audita: cierra en falso, el check queda rojo.
- Contenido introducido solo en la resolución de un merge (un merge "malvado") no se
  audita: `diff-tree` no muestra cambios propios de un merge.
