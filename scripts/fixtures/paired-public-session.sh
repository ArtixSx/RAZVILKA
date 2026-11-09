#!/bin/sh
set -eu
umask 077
work=$1
repo=$2
stage=$3
case "$stage" in outer|inner) ;; *) exit 2 ;; esac
# This script is entered only by the disposable unshare/tini harness. Check
# original outer namespaces before the first mount, not just an environment bit.
python3 - "$stage" <<'SCOPE'
import fcntl,os,sys
namespaces=[(3,'net',0x40000000),(4,'mnt',0x00020000)]
if sys.argv[1]=='inner': namespaces.append((5,'pid',0x20000000))
for fd,name,kind in namespaces:
    if fcntl.ioctl(fd,0xb703)!=kind: raise SystemExit('held original descriptor is not the required namespace')
    outer=os.fstat(fd);inner=os.stat('/proc/self/ns/'+name)
    if (outer.st_dev,outer.st_ino)==(inner.st_dev,inner.st_ino): raise SystemExit('fixture did not isolate '+name)
SCOPE
mount --make-rprivate /
if grep -E ' (shared|master|propagate_from):[0-9]+' /proc/self/mountinfo; then exit 2; fi
if test "$stage" = outer; then
 # Initialize actual per-network queue state while /proc/1 still names the
 # outer PID namespace. No hook references this queue during its real Start.
 /usr/sbin/iptables-legacy -t mangle -N RZV_CI_NFQ_BOOTSTRAP
 /usr/sbin/iptables-legacy -t mangle -A RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
 /usr/sbin/iptables-legacy -t mangle -D RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
 /usr/sbin/iptables-legacy -t mangle -X RZV_CI_NFQ_BOOTSTRAP
 /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
 RAZVILKA_MANAGED_PROBE_FIXTURE_WORK="$work" python3 "$repo/scripts/native-managed-probe-queue-init.py"
 exec unshare --mount --pid --fork --mount-proc /usr/bin/tini -g -- /bin/sh "$repo/scripts/fixtures/paired-public-session.sh" "$work" "$repo" inner
fi
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
mkdir -p /opt/bin /opt/sbin /opt/etc/init.d /opt/etc/razvilka /opt/razvilka/state /opt/razvilka/run /opt/razvilka/log /opt/razvilka/cache /opt/root
chmod 755 /opt/bin /opt/sbin /opt/etc /opt/etc/init.d /opt/razvilka
chmod 700 /opt/etc/razvilka /opt/razvilka/state /opt/razvilka/run /opt/razvilka/log /opt/razvilka/cache /opt/root
cp "$(command -v busybox)" /opt/bin/busybox
chmod 755 /opt/bin/busybox
ln -s /opt/bin/busybox /opt/bin/sh
ln -s /opt/bin/busybox /opt/sbin/start-stop-daemon
cp "$work/old-controller" /opt/bin/razvilka
chmod 755 /opt/bin/razvilka
cp "$work/old-source/scripts/S99razvilka" /opt/etc/razvilka/source-init-0193
chmod 600 /opt/etc/razvilka/source-init-0193
cp "$work/old-source/configs/"*.json /opt/etc/razvilka/
cp /opt/etc/razvilka/config.example.json /opt/etc/razvilka/config.json
python3 - <<'PY'
import json,pathlib
p=pathlib.Path('/opt/etc/razvilka/config.json');cfg=json.loads(p.read_text())
cfg['safe_mode']=True;cfg['revision']=1;cfg['service_control']={'stopped':True}
p.write_text(json.dumps(cfg));p.chmod(0o600)
PY
# The actual old source and old script are unmodified. Its existing supported
# layout variables configure this explicit source scenario; no old-reader ABI
# or default legacy-layout migration is inferred from that configuration.
cat >/opt/etc/init.d/S99razvilka <<'SOURCE_INIT'
#!/opt/bin/sh
set -eu
export RAZVILKA_STATE_DIR=/opt/razvilka/state
export RAZVILKA_RUN_DIR=/opt/razvilka/run
export RAZVILKA_CACHE=/opt/razvilka/cache
export RAZVILKA_LOG_DIR=/opt/razvilka/log
exec /opt/bin/sh /opt/etc/razvilka/source-init-0193 "$@"
SOURCE_INIT
chmod 755 /opt/etc/init.d/S99razvilka
ip link set lo up
/opt/bin/sh /opt/etc/init.d/S99razvilka start
# tini is PID1 and joins the actual daemon after the public old-panel Stop.
# Namespace teardown kills any remaining child on fixture failure.
"$work/cmd.test" -test.run '^TestNativeConfiguredOld193PairLifecycle$' -test.v -test.count=1 -test.timeout=30m
