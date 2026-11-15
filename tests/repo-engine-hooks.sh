#!/usr/bin/env bash
# Gates de comportamiento de los hooks de repo-engine con commits y pushes REALES,
# en repos y remotos aislados (sandbox). Usa el repo-engine real y su politica real
# (solo lectura). Nunca toca repositorios reales.
#
#   repo-engine-hooks.sh [ruta-a-repo-engine-dir]
set -u
RE=$(readlink -f "${1:-$(dirname "$(readlink -f "$0")")/..}")
T=$(mktemp -d "${TMPDIR:-/tmp}/re-hooks.XXXXXXXX")
cd / || exit 1
export GIT_CONFIG_GLOBAL="$T/gitconfig" GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
printf '[init]\n\tdefaultBranch = main\n[advice]\n\tdetachedHead = false\n' >"$GIT_CONFIG_GLOBAL"
# Politica vacia del sandbox: sin ella la compuerta cierra en falso ("publication is blocked").
# Los hooks heredan REPO_ENGINE_CONFIG; nunca se lee la configuracion local de la maquina.
: >"$T/policy.md"; printf '{"policy_path": "%s"}\n' "$T/policy.md" >"$T/re-config.json"
export REPO_ENGINE_CONFIG="$T/re-config.json"
PASS=0; FAIL=0; OBS=()
ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "condicion falsa: $2"; fi; }
obs() { OBS+=("$1"); printf '  OBS   %s\n' "$1"; }   # comportamiento medido, sin veredicto

# Token falso con forma de PAT de GitHub (SECRET_001); se arma en partes para que
# este archivo no sea el mismo un hallazgo.
FAKE_TOKEN="gh""p_""$(printf 'A%.0s' {1..36})"
PRIV_PATH="/home""/alice/private"

# mkrepo NAME [writer]: repo + remoto bare, hooks instalados por el instalador OFICIAL
mkrepo() {
  local n=$1 d="$T/$1"
  git init -q --bare "$T/$n.git"; git init -q "$d"; git -C "$d" remote add origin "$T/$n.git"
  echo base >"$d/README.md"; git -C "$d" add -A; git -C "$d" commit -q --no-verify -m base
  git -C "$d" push -q -u origin main 2>/dev/null
  ( cd "$RE" && python3 -B -c "import sys; from pathlib import Path; from repo_engine.hooks import install; install(Path(sys.argv[1]), adopt=False)" "$d" )
}
commit_try() { git -C "$T/$1" add -A >/dev/null 2>&1; git -C "$T/$1" commit -q -m "${2:-c}" >"$T/out.txt" 2>&1; }
rhead() { git -C "$T/$1.git" rev-parse main 2>/dev/null; }

echo "repo-engine: $RE"; echo "sandbox: $T"

echo "H1 instalador oficial: permisos del hook"
mkrepo h1; perm=$(stat -c %A "$T/h1/.git/hooks/pre-commit")
echo "$FAKE_TOKEN" >"$T/h1/leak.txt"; commit_try h1; rc=$?
obs "instalador oficial deja pre-commit con permisos $perm"
check "H1 un hook recien instalado bloquea un secreto (si falla: git lo ignoro por falta de +x)" '[ $rc != 0 ]'
git -C "$T/h1" reset -q --soft HEAD~1 2>/dev/null; git -C "$T/h1" rm -q --cached leak.txt 2>/dev/null; rm -f "$T/h1/leak.txt"

fixperm() { chmod +x "$T/$1/.git/hooks/pre-commit" "$T/$1/.git/hooks/pre-push"; }

echo "H2-H5 pre-commit con +x"
mkrepo h2; fixperm h2
echo "hola" >"$T/h2/ok.txt"; commit_try h2 limpio; rc=$?; check "H2 commit limpio pasa" '[ $rc = 0 ] && [ "$(git -C "$T/h2" log -1 --format=%s)" = limpio ]'
before=$(git -C "$T/h2" rev-parse HEAD)
echo "$FAKE_TOKEN" >"$T/h2/leak.txt"; commit_try h2 secreto
check "H3 commit con token bloqueado y no creado" '[ "$(git -C "$T/h2" rev-parse HEAD)" = "$before" ] && grep -q "BLOCKED" "$T/out.txt"'
git -C "$T/h2" rm -q --cached leak.txt; rm "$T/h2/leak.txt"
printf 'X = "%s"\n' "$PRIV_PATH" >"$T/h2/conf.py"; commit_try h2 rutapy
check "H4a ruta privada en codigo (.py) bloqueada" '[ "$(git -C "$T/h2" rev-parse HEAD)" = "$before" ]'
git -C "$T/h2" rm -q --cached conf.py; rm "$T/h2/conf.py"
printf 'ver %s\n' "$PRIV_PATH" >"$T/h2/notas.md"; commit_try h2 rutamd
if [ "$(git -C "$T/h2" rev-parse HEAD)" = "$before" ]; then obs "H4b ruta privada en .md (severidad info) TAMBIEN bloquea el commit"; else obs "H4b ruta privada en .md (info) NO bloquea"; git -C "$T/h2" reset -q --soft HEAD~1; fi
git -C "$T/h2" rm -q --cached notas.md; rm "$T/h2/notas.md"
git -C "$T/h2" commit -q --amend -m "solo cambio el mensaje" >"$T/out.txt" 2>&1; rc=$?
if [ $rc = 0 ]; then obs "H5 amend solo de mensaje (nada staged) pasa"; else obs "H5 amend solo de mensaje BLOQUEADO (exit del gate sin superficie): $(grep -m1 -E 'NO_SURFACE|REPO ENGINE' "$T/out.txt")"; fi
git -C "$T/h2" commit -q --allow-empty -m vacio >"$T/out.txt" 2>&1; rc=$?
if [ $rc = 0 ]; then obs "H5b commit --allow-empty pasa"; else obs "H5b commit --allow-empty BLOQUEADO (NO_SURFACE)"; fi

echo "H6-H9 pre-push con +x"
mkrepo h6; fixperm h6
echo a >"$T/h6/a.txt"; commit_try h6 a; rb=$(rhead h6)
git -C "$T/h6" push -q origin main >"$T/out.txt" 2>&1
check "H6 push limpio con un commit nuevo llega al remoto" '[ "$(rhead h6)" != "$rb" ] && [ "$(rhead h6)" = "$(git -C "$T/h6" rev-parse HEAD)" ]'
r0=$(rhead h6); echo "$FAKE_TOKEN" >"$T/h6/leak.txt"; git -C "$T/h6" add -A; git -C "$T/h6" commit -q --no-verify -m "saltado con --no-verify"
check "H10a --no-verify salta el pre-commit (limite de los hooks locales)" '[ "$(git -C "$T/h6" log -1 --format=%s)" = "saltado con --no-verify" ]'
git -C "$T/h6" push -q origin main >"$T/out.txt" 2>&1
check "H7 pre-push bloquea el secreto que entro con --no-verify; remoto intacto" '[ "$(rhead h6)" = "$r0" ] && grep -q BLOCKED "$T/out.txt"'
git -C "$T/h6" push -q --no-verify origin main >"$T/out.txt" 2>&1
check "H10b push --no-verify salta tambien el pre-push (solo una proteccion remota lo impide)" '[ "$(rhead h6)" != "$r0" ]'

mkrepo h8; fixperm h8
git -C "$T/h8" push -q origin HEAD:refs/heads/copia >"$T/out.txt" 2>&1; rc=$?
if [ $rc = 0 ]; then obs "H8 push de una rama nueva sin commits nuevos pasa"; else obs "H8 push de una rama nueva sin commits nuevos BLOQUEADO: $(grep -m1 -E 'NO_SURFACE|REPO ENGINE' "$T/out.txt")"; fi

mkrepo h9; fixperm h9
git -C "$T/h9" checkout -q -b mala; echo "$FAKE_TOKEN" >"$T/h9/leak.txt"; git -C "$T/h9" add -A; git -C "$T/h9" commit -q --no-verify -m mala
git -C "$T/h9" checkout -q main; echo limpio >"$T/h9/l.txt"; commit_try h9 limpio
check "H9 precondicion: main tiene un commit limpio saliente (si no, el gate bloquearia por NO_SURFACE y la prueba no diria nada)" '[ "$(git -C "$T/h9" log -1 --format=%s)" = limpio ]'
git -C "$T/h9" push -q origin mala >"$T/out.txt" 2>&1
if git -C "$T/h9.git" rev-parse -q --verify refs/heads/mala >/dev/null; then
  obs "H9 FUGA: con HEAD en main limpio, 'git push origin mala' subio un secreto (el gate audita HEAD, no lo que se empuja)"
  bad "H9 pre-push audita las refs que realmente se empujan" "el remoto recibio refs/heads/mala con el token"
else
  ok "H9 pre-push audita las refs que realmente se empujan"
fi

echo
echo "RESULTADO: $PASS PASS, $FAIL FAIL, ${#OBS[@]} observaciones"
echo "sandbox: $T"
[ $FAIL = 0 ]
