#!/bin/sh
# Repo Engine en CI: audita exactamente los commits que agrega un PR (BASE..HEAD).
# Lo usan action.yml y la reproduccion local (tests/test_ci_local.py): el mismo script.
#
#   run-ci.sh BASE HEAD        (cwd = checkout del repo, con historia completa)
#
# Politica privada: solo si RE_POLICY trae su contenido. Por defecto NO: en repos
# publicos los logs de CI son publicos y los hallazgos de politica nombran el termino.
# Sin ella corren las reglas base (secretos, rutas privadas, archivos de credenciales).
# exit 0 = sin bloqueantes (puede haber notas), 1 = bloqueado, 2 = no se pudo auditar.
set -eu
base=${1:-}; head=${2:-}
engine=$(cd "$(dirname "$0")/.." && pwd)/repo-engine.py
case "$base" in ""|0000000000000000000000000000000000000000)
  echo "repo-engine: no base commit (first push of a branch?); nothing was audited." >&2; exit 2 ;;
esac
git cat-file -e "$base^{commit}" 2>/dev/null || { echo "repo-engine: base $base not in this checkout (use fetch-depth: 0)" >&2; exit 2; }
git cat-file -e "$head^{commit}" 2>/dev/null || { echo "repo-engine: head $head not in this checkout" >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -n "${RE_POLICY:-}" ]; then
  printf '%s\n' "$RE_POLICY" >"$tmp/policy.md"
  printf '{"policy_path": "%s"}\n' "$tmp/policy.md" >"$tmp/config.json"
fi
REPO_ENGINE_CONFIG="$tmp/config.json" python3 -B "$engine" audit --repo "$(pwd)" --range "$base..$head" --policy optional
