#!/usr/bin/env bash
# Coordinator-only disposable VM helper. The external browser client is separate.
# Requires matching clean-0.20 Main defaults from internal/installpath.
set +x
set -Eeuo pipefail
umask 077

fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }
trusted_path() {
  local target="$1" part='/' component mode
  local -a components
  [[ "$target" == /* && "$(realpath -e -- "$target")" == "$target" ]] || return 1
  IFS='/' read -r -a components <<<"${target#/}"
  for component in "${components[@]}"; do
    part="${part%/}/$component"
    [[ ! -L "$part" && "$(stat -c %u -- "$part")" == 0 ]] || return 1
    mode="$(stat -c %a -- "$part")"
    (( (8#$mode & 8#022) == 0 )) || return 1
  done
}

private_directory() {
  trusted_path "$1" && [[ -d "$1" && "$(stat -c %a -- "$1")" == 700 ]]
}
readonly -a app_paths=(/opt/razvilka /opt/razvilka/state /opt/razvilka/run /opt/razvilka/cache /opt/razvilka/log)

inside() {
  local run="$1" port="$2" lifetime="$3" parent_namespace="$4" target
  [[ "$(readlink /proc/self/ns/mnt)" != "$parent_namespace" ]] || fail PRIVATE_NAMESPACE_REQUIRED
  trusted_path "$run" && [[ -f "$run/razvilka" ]] || fail PRIVATE_RUN_INVALID
  for target in "$run/config" "$run/app" "$run/app/state" "$run/app/run" "$run/app/cache" "$run/app/log"; do
    private_directory "$target" || fail PRIVATE_RUN_INVALID
  done
  exec 2>>"$run/launcher.log"
  local server_pid='' server_start='' cleanup_done=0 deadline
  local -a mounted=()
  owned_server() {
    local line; local -a fields
    [[ -n "$server_pid" && -r "/proc/$server_pid/stat" ]] || return 1
    line="$(<"/proc/$server_pid/stat")"
    read -r -a fields <<<"${line##*) }"
    [[ "${fields[1]:-}" == "$$" && "${fields[19]:-}" == "$server_start" ]]
  }
  cleanup() {
    local exit_status="$1" index
    (( cleanup_done == 0 )) || return
    cleanup_done=1
    trap - EXIT INT TERM
    if [[ -n "$server_pid" ]]; then
      if owned_server; then
        kill -TERM "$server_pid" 2>/dev/null || true
        deadline=$((SECONDS + 8))
        while owned_server && ((SECONDS < deadline)); do sleep 0.2; done
        if owned_server; then kill -KILL "$server_pid" 2>/dev/null || true; fi
      fi
      # Join only the child launched by this shell before releasing its mounts.
      wait "$server_pid" 2>/dev/null || true
    fi
    for ((index=${#mounted[@]}-1; index>=0; index--)); do
      if ! umount -- "${mounted[index]}"; then exit_status=1; fi
    done
    if ! stat -Lc '%n %d:%i' -- /opt/etc/razvilka "${app_paths[@]}" /opt/bin/razvilka >"$run/mountpoints.after" ||
       ! cmp -s -- "$run/mountpoints.before" "$run/mountpoints.after"; then exit_status=1; fi
    printf 'STOPPED exit=%s joined=true\n' "$exit_status" >"$run/lifecycle.status"
    printf 'QA_STOPPED status=%s\n' "$exit_status"
    exit "$exit_status"
  }
  trap 'cleanup "$?"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf '%s\n' "$$" >"$run/launcher.pid"
  local launcher_line; local -a launcher_fields
  launcher_line="$(<"/proc/$$/stat")"; read -r -a launcher_fields <<<"${launcher_line##*) }"
  printf '%s\n' "${launcher_fields[19]}" >"$run/launcher.starttime"
  readlink /proc/self/ns/mnt >"$run/mount.namespace"
  stat -Lc '%n %d:%i' -- /opt/etc/razvilka "${app_paths[@]}" /opt/bin/razvilka >"$run/mountpoints.before"
  mount --bind "$run/config" /opt/etc/razvilka; mounted+=(/opt/etc/razvilka)
  # Isolate every mutable App path, including run/cache/log and recovery leaves.
  mount --bind "$run/app" /opt/razvilka; mounted+=(/opt/razvilka)
  [[ "$(stat -Lc '%d:%i' /opt/razvilka)" == "$(stat -Lc '%d:%i' "$run/app")" ]] || fail APP_BIND_MISMATCH
  mount --bind "$run/razvilka" /opt/bin/razvilka; mounted+=(/opt/bin/razvilka)
  mount -o remount,bind,ro /opt/bin/razvilka
  [[ "$(stat -Lc '%d:%i' /opt/bin/razvilka)" == "$(stat -Lc '%d:%i' "$run/razvilka")" ]] || fail BINARY_BIND_MISMATCH
  python3 - "$$" "$port" >"$run/server.log" 2>&1 <<'PY' &
import ctypes, os, signal, sys
# Arm parent death before exec; reject the race where the owning shell exited.
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(ctypes.c_int(1), ctypes.c_ulong(signal.SIGTERM), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0 or os.getppid() != int(sys.argv[1]):
    raise SystemExit('QA_PARENT_IDENTITY_UNAVAILABLE')
os.execve('/opt/bin/razvilka', ['/opt/bin/razvilka', '-listen', '127.0.0.1:' + sys.argv[2]], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin', 'GOMAXPROCS': '2'})
PY
  server_pid=$!
  local line; local -a fields
  [[ -r "/proc/$server_pid/stat" ]] || fail SERVER_EXITED_EARLY
  line="$(<"/proc/$server_pid/stat")"; read -r -a fields <<<"${line##*) }"; server_start="${fields[19]}"
  printf '%s\n' "$server_pid" >"$run/server.pid"
  printf '%s\n' "$server_start" >"$run/server.starttime"
  deadline=$((SECONDS + 45))
  while ((SECONDS < deadline)); do
    owned_server || fail SERVER_EXITED_EARLY
    if curl --silent --fail --max-time 1 --noproxy '*' "http://127.0.0.1:$port/api/v1/auth/status" >/dev/null 2>&1; then
      [[ "$(stat -Lc '%d:%i' "/proc/$server_pid/exe")" == "$(stat -Lc '%d:%i' /opt/bin/razvilka)" ]] || fail PROCESS_INODE_MISMATCH
      break
    fi
    sleep 0.25
  done
  ((SECONDS < deadline)) || fail HTTP_READINESS_TIMEOUT
  printf 'READY pid=%s port=%s lifetime=%s\n' "$server_pid" "$port" "$lifetime" >"$run/lifecycle.status"
  printf 'QA_READY port=%s\n' "$port"
  deadline=$((SECONDS + lifetime))
  while ((SECONDS < deadline)); do owned_server || fail SERVER_EXITED; sleep 1; done
  printf 'QA_LIFETIME_COMPLETE\n'
  cleanup 0
}

[[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || fail LINUX_ROOT_REQUIRED
for command in realpath stat readlink mount umount unshare ss curl python3 install mktemp cmp sha256sum cut; do
  command -v "$command" >/dev/null || fail MISSING_DEPENDENCY
done
if [[ "${1:-}" == __inside ]]; then
  [[ "$#" == 5 ]] || fail INVALID_INSIDE_ARGUMENTS
  inside "$2" "$3" "$4" "$5"
  exit
fi
binary='' repository='' parent='' expected_sha='' port=18852 lifetime=900
while (($#)); do
  (($# >= 2)) || fail INVALID_ARGUMENTS
  case "$1" in
    --binary) binary="$2";;
    --repository) repository="$2";;
    --run-parent) parent="$2";;
    --binary-sha256) expected_sha="$2";;
    --port) port="$2";;
    --lifetime-seconds) lifetime="$2";;
    *) fail INVALID_ARGUMENTS;;
  esac
  shift 2
done
[[ "$port" =~ ^[1-9][0-9]{3,4}$ ]] && ((port >= 1024 && port <= 65535)) || fail INVALID_PORT
[[ "$lifetime" =~ ^[1-9][0-9]{1,3}$ ]] && ((lifetime >= 60 && lifetime <= 3600)) || fail INVALID_LIFETIME
[[ "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || fail BINARY_SHA_REQUIRED
trusted_path "$binary" && [[ -f "$binary" && -x "$binary" ]] || fail BINARY_PATH_INVALID
trusted_path "$repository" && [[ -d "$repository/configs" ]] || fail REPOSITORY_PATH_INVALID
trusted_path "$parent" && [[ -d "$parent" ]] || fail RUN_PARENT_INVALID
for target in /opt/etc/razvilka "${app_paths[@]}" /opt/bin/razvilka; do trusted_path "$target" || fail CANONICAL_MOUNTPOINT_INVALID; done
for target in "${app_paths[@]}"; do private_directory "$target" || fail CANONICAL_PRIVATE_DIRECTORY_INVALID; done
[[ -d /opt/etc/razvilka && -f /opt/bin/razvilka ]] || fail CANONICAL_MOUNTPOINT_INVALID
[[ -z "$(ss -H -ltn "sport = :$port")" ]] || fail QA_PORT_OCCUPIED
[[ "$(sha256sum -- "$binary" | cut -d' ' -f1)" == "$expected_sha" ]] || fail BINARY_SHA_MISMATCH
run="$(mktemp -d "$parent/ui-linux-qa.XXXXXXXX")"
exec 2>>"$run/launcher.log"
install -m 0700 -d -- "$run/config" "$run/app" "$run/app/state" "$run/app/run" "$run/app/cache" "$run/app/log"
install -m 0700 -- "$binary" "$run/razvilka"
[[ "$(sha256sum -- "$run/razvilka" | cut -d' ' -f1)" == "$expected_sha" ]] || fail BINARY_COPY_MISMATCH
python3 - "$repository" "$run/config" <<'PY'
import json, pathlib, sys
source, target = pathlib.Path(sys.argv[1]) / 'configs', pathlib.Path(sys.argv[2])
for name, output in [('config.example.json', 'config.json'), ('service-catalog.json', 'service-catalog.json'), ('sources.json', 'sources.json'), ('community-catalog.json', 'community-catalog.json')]:
    path = source / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit('PUBLIC_FIXTURE_INVALID')
    value = json.loads(path.read_text(encoding='utf-8'))
    if name == 'config.example.json':
        if value.get('safe_mode') is not True or value.get('services') or value.get('applied_services'):
            raise SystemExit('EMPTY_SAFE_MODE_CONFIG_REQUIRED')
    if name == 'service-catalog.json':
        ids = {row['id'] for row in value['services']}
        for key, label in [('chatgpt', 'ChatGPT'), ('claude', 'Claude'), ('gemini', 'Gemini')]:
            identifier = 'ui-ai-' + key
            if identifier in ids:
                raise SystemExit('AI_FIXTURE_ID_EXISTS')
            value['services'].append({'id': identifier, 'name': label + ' · UI fixture', 'category': 'AI', 'description': 'Disposable QA catalog definition; no access proof.', 'domains': [key + '.ui.invalid'], 'strategy': ['nfqws2']})
    (target / output).write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
PY
printf '%s\n' "$expected_sha" >"$run/binary.sha256"
printf 'QA_RUN_DIR=%s\n' "$run"
namespace="$(readlink /proc/self/ns/mnt)"
exec unshare --mount --propagation private -- /bin/bash --noprofile --norc "$(realpath -e -- "${BASH_SOURCE[0]}")" __inside "$run" "$port" "$lifetime" "$namespace"
