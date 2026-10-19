#!/bin/sh
# Runs the real installer preflight against recording candidate and installed
# controller fixtures. No live installation, process, network or route is used.
# 0.20 is a clean base: a <=0.19 layout must refuse in BOTH modes before the
# candidate runs, so the old updater's own dry-run stops before its apply.
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
NATIVE_LINKS=1
case "$(uname -s)" in MINGW*|MSYS*) NATIVE_LINKS=0 ;; esac
# The installed-controller probe is bounded with ulimit -f. Hosts without it
# (Windows Git Bash) cannot run the probe at all; their probe cases are skipped
# and printed, never reported as passed.
BOUNDED_PROBES=1
(ulimit -f 128) >/dev/null 2>&1 || BOUNDED_PROBES=0
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-legacy-layout.XXXXXX")"
cleanup() {
  case "$TEST_ROOT" in
    "$TMP_BASE"/razvilka-legacy-layout.*) rm -rf "$TEST_ROOT" ;;
    *) echo "Refusing unsafe legacy-layout test cleanup" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

REFUSAL='Pre-0.20 RAZVILKA installation found; 0.20 installs only on a clean base; installation unchanged'
BUNDLE="$TEST_ROOT/bundle"
mkdir -p "$BUNDLE/scripts" "$BUNDLE/dist" "$BUNDLE/configs"
cp "$ROOT/scripts/upgrade-entware.sh" "$BUNDLE/scripts/upgrade-entware.sh"
for NAME in S99razvilka rollback-entware.sh; do
  printf '#!/bin/sh\nexit 97\n' >"$BUNDLE/scripts/$NAME"
done
for NAME in service-catalog community-catalog sources config.example; do
  printf '{}\n' >"$BUNDLE/configs/$NAME.json"
done
# The candidate records every invocation; a refusal case must leave none.
cat >"$BUNDLE/dist/razvilka-linux-amd64" <<'CANDIDATE'
#!/bin/sh
printf '%s\n' "$*" >>"$TEST_CANDIDATE_CAPTURE"
case "$1" in
  -self-update-read-version)
    printf 'flag provided but not defined: -self-update-read-version\n' >&2; exit 2 ;;
  -check-node-history-state) printf '{"ok":true}\n' ;;
  -version) printf '0.20.0\n' ;;
  -check) printf '{"ok": true}\n' ;;
  *) exit 99 ;;
esac
CANDIDATE
chmod 700 "$BUNDLE/dist/razvilka-linux-amd64"
(cd "$BUNDLE" && sha256sum dist/razvilka-linux-amd64 >dist/SHA256SUMS)
TEST_CANDIDATE_CAPTURE="$TEST_ROOT/candidate-calls"
TEST_INSTALLED_CAPTURE="$TEST_ROOT/installed-calls"
RAZVILKA_ARCH=amd64
export TEST_CANDIDATE_CAPTURE TEST_INSTALLED_CAPTURE RAZVILKA_ARCH

new_base() {
  BASE="$TEST_ROOT/$1/opt"
  mkdir -p "$BASE/sbin" "$BASE/var/lib"
  printf '#!/bin/sh\nexit 98\n' >"$BASE/sbin/start-stop-daemon"
  chmod 700 "$BASE/sbin/start-stop-daemon"
  printf '%s\n' keep-other-app >"$BASE/var/lib/other-app.conf"
}

# Go flag ABI: a <=0.19 controller does not define the 0.20 reader flag; a
# 0.20 controller answers its exact reader version.
install_controller() {
  mkdir -p "$BASE/bin"
  cat >"$BASE/bin/razvilka" <<CONTROLLER
#!/bin/sh
printf '%s\n' "\$*" >>"\$TEST_INSTALLED_CAPTURE"
[ "\$#" -eq 1 ] && [ "\$1" = -self-update-read-version ] || exit 98
if [ "$1" = legacy ]; then
  printf 'flag provided but not defined: -self-update-read-version\n' >&2
  printf 'Usage of razvilka:\n' >&2
  exit 2
fi
printf '4\n'
CONTROLLER
  chmod 700 "$BASE/bin/razvilka"
}

# Snapshot every name, type and byte below the fixture base.
tree_image() (
  cd "$1"
  find . -print | LC_ALL=C sort | while IFS= read -r ENTRY; do
    if [ -L "$ENTRY" ]; then printf 'L %s\n' "$ENTRY"
    elif [ -d "$ENTRY" ]; then printf 'D %s\n' "$ENTRY"
    else printf 'F %s %s\n' "$ENTRY" "$(sha256sum "$ENTRY" | awk '{print $1}')"
    fi
  done
)

run_installer() {
  rm -f "$TEST_CANDIDATE_CAPTURE" "$TEST_INSTALLED_CAPTURE"
  CODE=0
  RAZVILKA_BASE="$BASE" sh "$BUNDLE/scripts/upgrade-entware.sh" "$1" --without-components \
    >"$TEST_ROOT/output" 2>&1 || CODE=$?
}

TOTAL=0
SKIPPED=0
assert_refused() {
  FOUND="$1"
  EXPECT_INSTALLED="$2"
  tree_image "$BASE" >"$TEST_ROOT/before"
  for MODE in --dry-run --apply; do
    run_installer "$MODE"
    [ "$CODE" -eq 1 ] && grep -Fxq "$REFUSAL" "$TEST_ROOT/output" &&
      grep -Fxq "  found: $FOUND" "$TEST_ROOT/output" &&
      grep -Fq 'docs/INSTALL_RU.md' "$TEST_ROOT/output" || {
      echo "Pre-0.20 layout was not refused exactly ($MODE, exit $CODE): $FOUND" >&2
      cat "$TEST_ROOT/output" >&2
      exit 1
    }
    [ ! -e "$TEST_CANDIDATE_CAPTURE" ] || {
      echo "Candidate ran against a pre-0.20 layout ($MODE)" >&2; cat "$TEST_CANDIDATE_CAPTURE" >&2; exit 1;
    }
    if [ "$EXPECT_INSTALLED" = probe ]; then
      [ "$(cat "$TEST_INSTALLED_CAPTURE")" = -self-update-read-version ] || {
        echo "Installed controller was not probed exactly once, read-only ($MODE)" >&2; exit 1;
      }
    else
      [ ! -e "$TEST_INSTALLED_CAPTURE" ] || { echo "Installed controller executed ($MODE)" >&2; exit 1; }
    fi
    tree_image "$BASE" >"$TEST_ROOT/after"
    cmp -s "$TEST_ROOT/before" "$TEST_ROOT/after" || {
      echo "Pre-0.20 refusal changed the installation tree ($MODE)" >&2
      diff -u "$TEST_ROOT/before" "$TEST_ROOT/after" >&2 || true
      exit 1
    }
    TOTAL=$((TOTAL+1))
  done
}

# The retained <=0.19 state directory alone is decisive, even without a binary.
new_base legacy-state-directory
mkdir "$BASE/var/lib/razvilka"
printf '%s\n' legacy-settings >"$BASE/var/lib/razvilka/state-marker"
assert_refused "$BASE/var/lib/razvilka" none

# Any object at that name is ambiguous; never inspect or replace it.
new_base legacy-state-file
printf '%s\n' unknown >"$BASE/var/lib/razvilka"
assert_refused "$BASE/var/lib/razvilka" none

if [ "$NATIVE_LINKS" -eq 1 ]; then
  new_base legacy-state-link
  mkdir "$TEST_ROOT/foreign"
  printf '%s\n' foreign >"$TEST_ROOT/foreign/marker"
  ln -s "$TEST_ROOT/foreign" "$BASE/var/lib/razvilka"
  assert_refused "$BASE/var/lib/razvilka" none
  [ "$(cat "$TEST_ROOT/foreign/marker")" = foreign ] || { echo "Foreign link target changed" >&2; exit 1; }
  new_base legacy-state-broken-link
  ln -s "$TEST_ROOT/missing" "$BASE/var/lib/razvilka"
  assert_refused "$BASE/var/lib/razvilka" none
fi

if [ "$BOUNDED_PROBES" -eq 1 ]; then
  # A pre-0.20 controller whose state directory was moved is still refused.
  new_base legacy-controller
  install_controller legacy
  assert_refused "$BASE/bin/razvilka" probe

  # Controls: a clean base and an installed 0.20 controller still pass the
  # read-only preflight; the legacy guard only reads the reader ABI.
  new_base clean
  run_installer --dry-run
  [ "$CODE" -eq 0 ] && grep -Fxq 'Dry-run complete: no files or services were changed.' "$TEST_ROOT/output" || {
    echo "Clean base was refused" >&2; cat "$TEST_ROOT/output" >&2; exit 1;
  }
  [ ! -e "$TEST_INSTALLED_CAPTURE" ] && [ ! -e "$BASE/bin" ] && [ ! -e "$BASE/etc" ] || {
    echo "Clean preflight touched a controller or created installation files" >&2; exit 1;
  }
  TOTAL=$((TOTAL+1))

  new_base current-controller
  install_controller current
  run_installer --dry-run
  [ "$CODE" -eq 0 ] && [ "$(cat "$TEST_INSTALLED_CAPTURE")" = -self-update-read-version ] || {
    echo "Installed 0.20 controller was refused by the pre-0.20 guard" >&2; cat "$TEST_ROOT/output" >&2; exit 1;
  }
  ! grep -Fq "$REFUSAL" "$TEST_ROOT/output" || { echo "0.20 controller reported as pre-0.20" >&2; exit 1; }
  TOTAL=$((TOTAL+1))
else
  SKIPPED=3
  echo "SKIP: bounded controller probes need ulimit -f (legacy-controller, clean, current-controller)"
fi
printf 'Pre-0.20 layout guard tests: PASS cases=%s skipped=%s\n' "$TOTAL" "$SKIPPED"
