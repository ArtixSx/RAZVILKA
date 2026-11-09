#!/bin/sh
set -eu
umask 077
work=$1
repo=$2
stage=$3
case "$stage" in outer|inner) ;; *) exit 2 ;; esac
verify_scope() {
python3 - "$stage" "$1" <<'PY'
import fcntl,json,os,sys
result=[]
scopes=[(3,'net',0x40000000),(4,'mnt',0x20000)]
if sys.argv[1]=='inner': scopes.append((5,'pid',0x20000000))
for fd,name,kind in scopes:
 if fcntl.ioctl(fd,0xb703)!=kind: raise SystemExit('invalid original namespace type')
 a=os.fstat(fd);b=os.stat('/proc/self/ns/'+name)
 if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino): raise SystemExit('namespace is not isolated')
 result.append([name,a.st_dev,a.st_ino,b.st_dev,b.st_ino])
if sys.argv[2]=='fresh-proc':
 roots=[]
 for line in open('/proc/self/mountinfo'):
  fields=line.split();sep=fields.index('-')
  if fields[4]=='/proc': roots.append((fields[3],fields[sep+1]))
 if roots!=[('/','proc')]: raise SystemExit('one private proc root required')
print(json.dumps(result,separators=(',',':')))
PY
}
original_scope=$(verify_scope inherited)
test -n "$original_scope"
mount --make-rprivate /
if grep -E ' (shared|master|propagate_from):[0-9]+' /proc/self/mountinfo; then exit 2; fi
ip -j link show | python3 -c 'import json,sys; assert [x["ifname"] for x in json.load(sys.stdin)]==["lo"]'
test -z "$(ip -4 route show default)" && test -z "$(ip -6 route show default)"
if test "$stage" = outer; then
 /usr/sbin/iptables-legacy -t mangle -N RZV_CI_NFQ_BOOTSTRAP
 /usr/sbin/iptables-legacy -t mangle -A RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
 /usr/sbin/iptables-legacy -t mangle -D RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
 /usr/sbin/iptables-legacy -t mangle -X RZV_CI_NFQ_BOOTSTRAP
 /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
 RAZVILKA_MANAGED_PROBE_FIXTURE_WORK="$work" python3 "$repo/scripts/native-managed-probe-queue-init.py"
 exec unshare --mount --pid --fork /usr/bin/tini -g -- /bin/sh "$repo/scripts/fixtures/modern-pair-session.sh" "$work" "$repo" inner
fi
umount -l /proc
mount -t proc proc /proc
test "$(verify_scope fresh-proc)" = "$original_scope"
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
mkdir -p /opt/bin /opt/sbin /opt/etc/init.d /opt/etc/razvilka /opt/root /opt/razvilka/state /opt/razvilka/run /opt/razvilka/log /opt/razvilka/cache
chmod 755 /opt/bin /opt/sbin /opt/etc /opt/etc/init.d /opt/razvilka
chmod 700 /opt/root /opt/etc/razvilka /opt/razvilka/state /opt/razvilka/run /opt/razvilka/log /opt/razvilka/cache
cp "$(command -v busybox)" /opt/bin/busybox
chmod 755 /opt/bin/busybox
ln -s /opt/bin/busybox /opt/bin/sh
dpkg --compare-versions "$(dpkg-query -W -f='${Version}' dpkg)" ge 1.20.6
/usr/sbin/start-stop-daemon --help | grep -F -- '--no-close' >/dev/null
/usr/sbin/start-stop-daemon --help | grep -F -- '--output' >/dev/null
cp /usr/sbin/start-stop-daemon /opt/sbin/start-stop-daemon
chmod 755 /opt/sbin/start-stop-daemon
cmp /usr/sbin/start-stop-daemon /opt/sbin/start-stop-daemon
printf 'actual_configured_daemon dpkg_version=%s source_copy_sha256=%s entware_equivalence=false\n' "$(dpkg-query -W -f='${Version}' dpkg)" "$(sha256sum /usr/sbin/start-stop-daemon | cut -d ' ' -f 1)"
cp "$work/source" /opt/bin/razvilka
chmod 755 /opt/bin/razvilka
cp "$repo/scripts/S99razvilka" /opt/etc/init.d/S99razvilka
chmod 755 /opt/etc/init.d/S99razvilka
cp "$repo/configs/"*.json /opt/etc/razvilka/
cp /opt/etc/razvilka/config.example.json /opt/etc/razvilka/config.json
python3 - "$work" <<'PY'
import hashlib,json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]);cfg=pathlib.Path('/opt/etc/razvilka/config.json')
data=json.loads(cfg.read_bytes());data['safe_mode']=False;data['revision']=1;data['service_control']={'stopped':False};cfg.write_text(json.dumps(data));cfg.chmod(0o600)
digest=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
ns=os.fstat(3)
spec={'source_sha256':digest(root/'source'),'candidate_sha256':digest(root/'candidate'),'init_sha256':digest('/opt/etc/init.d/S99razvilka'),'interpreter_sha256':digest('/opt/bin/busybox'),'launcher_sha256':digest(root/'modern-daemon.py'),'daemon_sha256':digest('/usr/sbin/start-stop-daemon'),'namespace_device':ns.st_dev,'namespace_inode':ns.st_ino}
p=root/'modern-pair-native.json';p.write_text(json.dumps(spec));p.chmod(0o600)
hosts=root/'modern-hosts';hosts.write_text('127.0.0.1 localhost\n::1 localhost\n93.184.216.34 api.github.com github.com\n');hosts.chmod(0o600)
PY
# No external interface/default route exists. Both names resolve only to the
# fixture's soon-to-be-created local address; production DNS/TLS is unchanged.
mount --bind "$work/modern-hosts" /etc/hosts
ip link set lo up
"$work/cmd.test" -test.run '^TestNativeModernPublicRollback$' -test.v -test.count=1 -test.timeout=32m
