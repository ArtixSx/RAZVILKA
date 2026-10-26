//go:build linux && (amd64 || arm64)

package dataplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This opt-in harness reproduces the NDM netfilter rewrite natively. In its
// own fresh network, PID and mount namespaces it binds a private /opt and runs
// the genuine pinned nfqws2-keenetic 1.3.1 package bytes: Apply's native check
// and the guarded stock init run the package's own nfqws2 build for this CPU
// (the router runs its aarch64 sibling), which binds queue 300 and drops to
// nobody, and the init appends the closed graph with real legacy iptables;
// the genuine 100-nfqws2.sh hook then runs after a whole-table mangle
// replacement, as NDM runs it. The adapter's process, queue, kernel and
// inactivity sources are the production ones bound to a real reviewed
// collector. Modelled: the Keenetic policy/WAN facts (no ndmc), the HTTP
// health probe and the firmware itself (a sanitized NDM-shaped ruleset; the
// vendor ndmmark match is replaced by mark). Legacy iptables here is the VM's
// 1.8 build, not the router's 1.4.21. Nothing outside the namespaces is
// written except kernel modules the stock kernel_modules step or the kernel
// itself may load.
const (
	nfqws2NDMNativeOptIn  = "RAZVILKA_HOOK_NDM_NATIVE"
	nfqws2NDMNativeIPK    = "RAZVILKA_HOOK_NDM_IPK"
	nfqws2NDMNativeParent = "RAZVILKA_HOOK_NDM_PARENT"
	nfqws2NDMIPKSHA256    = "28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054"
	nfqws2NDMIPKSize      = 2382102
	nfqws2NDMHookSHA256   = "57770e0250100ca81a0af546ffee6a885b68eb5224963bca4574236b80f6b3ea"
	nfqws2NDMInert        = "NFQWS2 is managed by RAZVILKA; this entry point is inert."
)

// The sanitized NC-1812 firmware rulesets the owned graph is appended to:
// RETURN/TTL chains before PREROUTING, empty chains before POSTROUTING and the
// OUTPUT delay queue. Only fake MACs and protocol-constant addresses are used.
// The firmware's 29-character hotspot chain name loses its last letter:
// legacy iptables 1.8 refuses names longer than 28 characters.
const nfqws2NDMFirmwareV4 = `*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_DNSRT_PREROUTING_MANGLE - [0:0]
:_NDM_HOTSPOT_PREROUTING_MANG - [0:0]
:_NDM_IPSEC_POSTR_MANGLE - [0:0]
:_NDM_IPSEC_PREROUTING - [0:0]
:_NDM_OUTPUT_DELAY - [0:0]
:_NDM_POSTROUTING_TTL - [0:0]
:_NDM_PREROUTING_MC - [0:0]
:_NDM_PREROUTING_TTL - [0:0]
:_NDM_VPN_PREROUTING - [0:0]
-A PREROUTING -d 224.0.0.0/4 -j _NDM_PREROUTING_MC
-A PREROUTING -j _NDM_IPSEC_PREROUTING
-A PREROUTING -j _NDM_VPN_PREROUTING
-A PREROUTING -j _NDM_PREROUTING_TTL
-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANG
-A PREROUTING -m mark --mark 0x0 -j _NDM_DNSRT_PREROUTING_MANGLE
-A OUTPUT -j _NDM_OUTPUT_DELAY
-A POSTROUTING -j _NDM_IPSEC_POSTR_MANGLE
-A POSTROUTING -j _NDM_POSTROUTING_TTL
-A _NDM_HOTSPOT_PREROUTING_MANG -m mac --mac-source 02:00:00:00:00:01 -j RETURN
-A _NDM_HOTSPOT_PREROUTING_MANG -m mac --mac-source 02:00:00:00:00:02 -j RETURN
-A _NDM_OUTPUT_DELAY ! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m mark --mark 0x0/0x80 -j NFQUEUE --queue-num 64511
-A _NDM_PREROUTING_MC -p udp -j TTL --ttl-inc 1
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_MASQ - [0:0]
-A POSTROUTING -j _NDM_MASQ
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:_NDM_ACL - [0:0]
-A FORWARD -j _NDM_ACL
COMMIT
`

const nfqws2NDMFirmwareV6 = `*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_DNSRT_PRERT - [0:0]
:_NDM_HOTSPOT_PRERT - [0:0]
:_NDM_OUTPUT_DELAY - [0:0]
-A PREROUTING -j _NDM_HOTSPOT_PRERT
-A PREROUTING -m mark --mark 0x0 -j _NDM_DNSRT_PRERT
-A OUTPUT -j _NDM_OUTPUT_DELAY
-A _NDM_HOTSPOT_PRERT -m mac --mac-source 02:00:00:00:00:01 -j RETURN
-A _NDM_OUTPUT_DELAY ! -s ::1/128 ! -d ::1/128 -m mark --mark 0x0/0x80 -j NFQUEUE --queue-num 64512
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`

// nfqws2NDMNativeEnter re-runs the calling top-level test in fresh network,
// PID and private mount namespaces. It returns true in the parent, which
// only reports the child's result.
func nfqws2NDMNativeEnter(t *testing.T) bool {
	t.Helper()
	if os.Getenv(nfqws2NDMNativeOptIn) != "1" {
		t.Skip("explicit isolated native opt-in: " + nfqws2NDMNativeOptIn + "=1 and " + nfqws2NDMNativeIPK + "=<pinned upstream IPK>")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native NDM rewrite harness requires root")
	}
	if os.Getenv(nfqws2NDMNativeParent) == "" {
		parent, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--pid", "--fork", "--mount", "--propagation", "private", "--",
			binary, "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v", "-test.timeout=8m")
		cmd.Env = append(os.Environ(), nfqws2NDMNativeParent+"="+parent)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fresh namespace harness failed: %v\n%s", err, output)
		}
		t.Logf("fresh namespace results:\n%s", output)
		return true
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == os.Getenv(nfqws2NDMNativeParent) || os.Getpid() != 1 {
		t.Fatal("refusing mutations outside fresh unshare network/PID/mount namespaces", err)
	}
	// --mount-proc would stack a second proc over the inherited one and its
	// binfmt_misc submount; the production identity provider refuses such a
	// layout. The private mount namespace gets exactly one fresh proc instead.
	if err := syscall.Unmount("/proc", syscall.MNT_DETACH); err != nil {
		t.Fatal("detach the inherited proc tree", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		t.Fatal("mount the namespace proc", err)
	}
	if self, err := os.Readlink("/proc/self"); err != nil || self != "1" {
		t.Fatal("namespace proc does not show this PID namespace", self, err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh namespace must contain loopback only", interfaces, err)
	}
	return false
}

// nfqws2NDMRunner is the production exec runner with a log of every
// invocation and optional fault hooks around iptables/ip6tables writes.
type nfqws2NDMRunner struct {
	mu            sync.Mutex
	calls         []string
	firewall      [][]string
	before, after func(args []string)
}

func (r *nfqws2NDMRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	firewall := isIPTablesCommand(name)
	var before, after func([]string)
	r.mu.Lock()
	call := filepath.Base(name)
	if len(args) != 0 {
		call += " " + args[0]
	}
	r.calls = append(r.calls, call)
	if firewall {
		r.firewall = append(r.firewall, append([]string{filepath.Base(name)}, args...))
		before, after = r.before, r.after
	}
	r.mu.Unlock()
	if before != nil {
		before(args)
	}
	output, err := nfqws2ExecRunner{}.Run(ctx, name, args...)
	if after != nil && err == nil {
		after(args)
	}
	return output, err
}

func (r *nfqws2NDMRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.firewall)
}

func (r *nfqws2NDMRunner) arm(before, after func(args []string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.before, r.after = before, after
}

type nfqws2NDMNative struct {
	f        *firstStartFixture
	runner   *nfqws2NDMRunner
	hookPath string
	tools    map[int]string // legacy iptables per family
	restores map[int]string
	saves    map[int]string
}

// nfqws2NDMDaemon is an independent /proc reading of the stock daemon and
// its queue socket; it shares no parser with the adapter.
type nfqws2NDMDaemon struct {
	PID                 int
	Start, Exe, UID     string
	Port                string
	CopyMode, CopyRange string
	Inode               string
}

// nfqws2NDMState is every table the restoration may read or must not touch,
// normalized to zero counters and without save comments.
type nfqws2NDMState struct {
	Mangle4, NAT4, Filter4, Mangle6, Filter6 string
}

func nfqws2NDMPackage(t *testing.T) map[string][]byte {
	t.Helper()
	path := os.Getenv(nfqws2NDMNativeIPK)
	raw, err := os.ReadFile(path)
	digest := sha256.Sum256(raw)
	if !filepath.IsAbs(path) || err != nil || len(raw) != nfqws2NDMIPKSize || hex.EncodeToString(digest[:]) != nfqws2NDMIPKSHA256 {
		t.Fatal("the exact pinned upstream nfqws2-keenetic 1.3.1 IPK is required at "+nfqws2NDMNativeIPK, err)
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	want := map[string]string{
		"opt/etc/ndm/netfilter.d/100-nfqws2.sh":    "hook",
		"opt/etc/init.d/S51nfqws2":                 "init",
		"opt/tmp/nfqws2_binary/nfqws2-" + arch:     "binary",
		"opt/etc/nfqws2/lua/zapret-lib.lua.gz":     "lib",
		"opt/etc/nfqws2/lua/zapret-antidpi.lua.gz": "antidpi",
	}
	members := map[string][]byte{}
	var data []byte
	nfqws2NDMTar(t, raw, func(name string, body []byte) {
		if name == "data.tar.gz" {
			data = body
		}
	})
	nfqws2NDMTar(t, data, func(name string, body []byte) {
		if key, ok := want[name]; ok {
			members[key] = body
		}
	})
	if len(members) != len(want) {
		t.Fatal("pinned IPK lacks an expected member", len(members))
	}
	hook := sha256.Sum256(members["hook"])
	stock, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil || hex.EncodeToString(hook[:]) != nfqws2NDMHookSHA256 || !bytes.Equal(stock, members["init"]) {
		t.Fatal("pinned IPK hook or init differs from the reviewed bytes", err)
	}
	return members
}

func nfqws2NDMTar(t *testing.T, archive []byte, visit func(string, []byte)) {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || header.Size > 64<<20 {
			t.Fatal("unreadable pinned archive", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(body)) != header.Size {
			t.Fatal("short pinned archive member", err)
		}
		visit(strings.TrimPrefix(header.Name, "./"), body)
	}
}

// newNFQWS2NDMNative builds the first-start consumer over a private literal
// /opt with the genuine package files, binds the production inactivity
// source to a reviewed legacy collector and applies the first-start plan
// through the genuine guarded init.
func newNFQWS2NDMNative(t *testing.T, ipv6 bool) *nfqws2NDMNative {
	t.Helper()
	members := nfqws2NDMPackage(t)
	n := &nfqws2NDMNative{runner: &nfqws2NDMRunner{}, tools: map[int]string{}, restores: map[int]string{}, saves: map[int]string{}}
	for family, names := range map[int][3]string{4: {"iptables-legacy", "iptables-legacy-restore", "iptables-legacy-save"}, 6: {"ip6tables-legacy", "ip6tables-legacy-restore", "ip6tables-legacy-save"}} {
		for i, name := range names {
			path, err := exec.LookPath(name)
			if err != nil {
				t.Fatal("required native tool unavailable", name, err)
			}
			[]map[int]string{n.tools, n.restores, n.saves}[i][family] = path
		}
	}
	multi, err := filepath.EvalSymlinks(n.tools[4])
	if err != nil || filepath.Base(multi) != "xtables-legacy-multi" {
		t.Fatal("legacy iptables is not the multi-call binary", multi, err)
	}
	// Keenetic's /bin/sh is busybox ash; the stock init relies on it ([[ =~ ]],
	// [ == ]). Only this mount namespace sees busybox as /bin/sh.
	shell, err := filepath.EvalSymlinks("/bin/sh")
	busybox, busyErr := exec.LookPath("busybox")
	if err != nil || busyErr != nil {
		t.Fatal("busybox and /bin/sh are required", err, busyErr)
	}
	if err := syscall.Mount(busybox, shell, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("bind busybox ash as the private /bin/sh", err)
	}
	if out, err := exec.Command("/bin/sh", "-c", `[[ abc =~ b ]] && [ a == a ] && echo ash`).CombinedOutput(); err != nil || string(out) != "ash\n" {
		t.Fatal("private /bin/sh is not busybox ash", err, string(out))
	}
	backing := filepath.Join(t.TempDir(), "opt")
	if err := os.Mkdir(backing, 0755); err != nil || os.Chmod(backing, 0755) != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(backing, "/opt", "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("bind private /opt", err)
	}
	t.Setenv("RAZVILKA_FIRST_START_TEST_OPT", backing)
	n.restore(t, 4, nfqws2NDMFirmwareV4)
	n.restore(t, 6, nfqws2NDMFirmwareV6)

	f := newFirstStartFixture(t)
	n.f = f
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, mode); err != nil || os.Chmod(path, mode) != nil {
			t.Fatal(err)
		}
	}
	// The daemon drops to nobody before it reads Lua and lists: the literal
	// stock tree must be traversable, as it is on the router.
	for _, dir := range []string{"/opt", "/opt/etc", "/opt/etc/nfqws2", "/opt/etc/nfqws2/lua", "/opt/etc/nfqws2/lists", "/opt/usr", "/opt/usr/bin"} {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	program := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(f.a.InitPath))), "usr", "bin", "nfqws2")
	write(program, members["binary"], 0755)
	write(filepath.Join(filepath.Dir(f.a.ConfigPath), "lua", "zapret-lib.lua.gz"), members["lib"], 0644)
	write(filepath.Join(filepath.Dir(f.a.ConfigPath), "lua", "zapret-antidpi.lua.gz"), members["antidpi"], 0644)
	n.hookPath = filepath.Join(filepath.Dir(filepath.Dir(f.a.InitPath)), "ndm", "netfilter.d", "100-nfqws2.sh")
	write(n.hookPath, members["hook"], 0755)
	if err := os.MkdirAll("/opt/var/run", 0755); err != nil {
		t.Fatal(err)
	}
	// The init's PATH starts with /opt/sbin, as Entware's does on the router.
	for _, name := range []string{"iptables", "ip6tables", "iptables-save", "ip6tables-save"} {
		if err := os.MkdirAll("/opt/sbin", 0755); err != nil || os.Symlink(multi, filepath.Join("/opt/sbin", name)) != nil {
			t.Fatal("stock PATH tool", name, err)
		}
	}
	if ipv6 {
		writeStockText(t, f.a.ConfigPath, strings.Replace(readText(t, f.a.ConfigPath), "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1))
	}
	// Production sources only, except the Keenetic policy/WAN facts.
	f.a.Runner, f.owner.Runner = n.runner, n.runner
	f.a.IPTablesSave = "/opt/sbin/iptables-save"
	f.a.firstStartObservation, f.a.firstStartProcessRead, f.a.firstStartStopReview = nil, nil, nil
	n.bindSource(t)
	t.Cleanup(func() {
		if raw, err := os.ReadFile(f.a.firstStartPIDPath()); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 1 {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	})
	f.apply(t)
	return n
}

// bindSource authenticates the reviewed VM legacy tools and binds the
// production inactivity source, as trusted startup binds the router's.
func (n *nfqws2NDMNative) bindSource(t *testing.T) {
	t.Helper()
	profile, err := backendNativeFixtureProfile("linux70")
	if err != nil || profile.aliases[0] != n.tools[4] || profile.aliases[1] != n.tools[6] {
		t.Fatal("reviewed legacy tool profile differs from this host", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendInventoryTimeout)
	defer cancel()
	review, err := backendNativeHeldTools(ctx, profile)
	if err != nil {
		t.Fatal("reviewed legacy tools", backendNativeTrace(err))
	}
	t.Cleanup(func() { _ = review.close() })
	inventory, err := NewBackendInventory(netidentity.NewProcProvider(), BackendInventoryTools{Runner: nfqws2ExecRunner{}, IPTables: profile.aliases[0], IP6Tables: profile.aliases[1], ReviewSHA256: profile.mainSHA, Check: review.check})
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewNFQWSRuntimeInactiveSource(ctx, n.f.a, inventory)
	if err != nil {
		t.Fatal("production inactivity source", NFQWSRuntimeInactiveStage(err), err)
	}
	if err := source.Bind(n.f.a); err != nil {
		t.Fatal(err)
	}
}

func nfqws2NDMContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func (n *nfqws2NDMNative) committed(t *testing.T) Plan {
	t.Helper()
	plan, exists, err := n.f.m.Committed()
	if err != nil || !exists || plan.State != "committed" {
		t.Fatal("no committed first-start plan", err)
	}
	return plan
}

func (n *nfqws2NDMNative) command(t *testing.T, stdin string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native %s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// restore replaces every table named in image atomically, as NDM's own
// whole-table write does; tables not named are not touched.
func (n *nfqws2NDMNative) restore(t *testing.T, family int, image string) {
	t.Helper()
	n.command(t, image, n.restores[family])
}

var nfqws2NDMCounters = regexp.MustCompile(`(?m)^(:\S+ \S+) \[\d+:\d+\]$`)

func (n *nfqws2NDMNative) save(t *testing.T, family int, table string) string {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(n.command(t, "", n.saves[family], "-t", table), "\n") {
		if !strings.HasPrefix(line, "#") {
			kept = append(kept, line)
		}
	}
	return nfqws2NDMCounters.ReplaceAllString(strings.Join(kept, "\n"), "$1 [0:0]")
}

func (n *nfqws2NDMNative) state(t *testing.T) nfqws2NDMState {
	t.Helper()
	return nfqws2NDMState{Mangle4: n.save(t, 4, "mangle"), NAT4: n.save(t, 4, "nat"), Filter4: n.save(t, 4, "filter"), Mangle6: n.save(t, 6, "mangle"), Filter6: n.save(t, 6, "filter")}
}

// rewrite is the NDM signature: the whole mangle table is written again
// from the firmware's own model, which has no owned chain or jump.
func (n *nfqws2NDMNative) rewrite(t *testing.T, family int, edit func(string) string) string {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(n.save(t, family, "mangle"), "\n") {
		if !strings.Contains(line, "nfqws") {
			kept = append(kept, line)
		}
	}
	image := strings.Join(kept, "\n")
	if edit != nil {
		image = edit(image)
	}
	n.restore(t, family, image)
	return image
}

// hook runs the genuine stock NDM hook with NDM's only environment.
func (n *nfqws2NDMNative) hook(t *testing.T, table, kind string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.hookPath)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "table=" + table, "type=" + kind}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("genuine NDM hook %s/%s failed: %v\n%s", kind, table, err, out)
	}
	return string(out)
}

func (n *nfqws2NDMNative) daemon(t *testing.T) nfqws2NDMDaemon {
	t.Helper()
	raw, err := os.ReadFile(n.f.a.firstStartPIDPath())
	if err != nil {
		t.Fatal("stock PID file", err)
	}
	var d nfqws2NDMDaemon
	if d.PID, err = strconv.Atoi(strings.TrimSpace(string(raw))); err != nil || d.PID <= 1 {
		t.Fatal("stock PID file", err)
	}
	proc := filepath.Join("/proc", strconv.Itoa(d.PID))
	stat, err := os.ReadFile(filepath.Join(proc, "stat"))
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	if err != nil || len(fields) < 20 {
		t.Fatal("stock daemon stat", err)
	}
	d.Start = fields[19]
	if d.Exe, err = os.Readlink(filepath.Join(proc, "exe")); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			d.UID = strings.Fields(line)[1]
		}
	}
	queues, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		t.Fatal("queue registrations", err)
	}
	for _, line := range strings.Split(string(queues), "\n") {
		if f := strings.Fields(line); len(f) >= 5 && f[0] == "300" {
			d.Port, d.CopyMode, d.CopyRange = f[1], f[3], f[4]
		}
	}
	sockets, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(sockets), "\n") {
		if f := strings.Fields(line); len(f) == 10 && f[1] == "12" && f[2] == d.Port {
			d.Inode = f[9]
		}
	}
	entries, err := os.ReadDir(filepath.Join(proc, "fd"))
	if err != nil {
		t.Fatal(err)
	}
	held := false
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(proc, "fd", entry.Name()))
		held = held || err == nil && d.Inode != "" && link == "socket:["+d.Inode+"]"
	}
	if d.Port == "" || d.Inode == "" || !held {
		t.Fatalf("queue 300 is not bound to the stock daemon's socket: %+v", d)
	}
	return d
}

func nfqws2NDMOwned(image string) bool {
	return strings.Contains(image, "nfqws")
}

// TestNFQWS2HookNDMRewriteDefectNative reproduces the defect: after NDM writes
// mangle again, the genuine stock hook reaches only the guarded init's inert
// dispatch, the owned graph stays lost under the same live daemon and the
// Health rule verifier fails. It uses no restoration code.
func TestNFQWS2HookNDMRewriteDefectNative(t *testing.T) {
	if nfqws2NDMNativeEnter(t) {
		return
	}
	n := newNFQWS2NDMNative(t, false)
	plan := n.committed(t)
	if err := n.f.a.Health(nfqws2NDMContext(t), plan, ""); err != nil {
		t.Fatal("genuine stock start does not pass Health", err)
	}
	n.runner.mu.Lock()
	applied := slices.Compact(slices.Clone(n.runner.calls))
	n.runner.mu.Unlock()
	if !slices.Contains(applied, "nfqws2 --dry-run") || !slices.Contains(applied, "S51nfqws2 owned_start") {
		t.Fatal("Apply did not run the genuine binary check and guarded init", applied)
	}
	t.Logf("genuine Apply and Health commands: %q", applied)
	before, daemon := n.state(t), n.daemon(t)
	for _, chain := range []string{":nfqws_post -", ":nfqws_pre -", "-A POSTROUTING -j nfqws_post", "-A PREROUTING -j nfqws_pre"} {
		if !strings.Contains(before.Mangle4, chain) {
			t.Fatalf("genuine stock start left no %q:\n%s", chain, before.Mangle4)
		}
	}
	if !strings.Contains(before.NAT4, ":nfqws_nat -") || nfqws2NDMOwned(before.Mangle6) {
		t.Fatalf("unexpected stock nat or IPv6 state:\n%s\n%s", before.NAT4, before.Mangle6)
	}
	rewritten := n.rewrite(t, 4, nil)
	// NDM runs every netfilter.d hook after its write, per table and family.
	for _, call := range [][2]string{{"mangle", "iptables"}, {"nat", "iptables"}, {"mangle", "ip6tables"}, {"filter", "iptables"}} {
		out := n.hook(t, call[0], call[1])
		if inert := strings.Contains(out, nfqws2NDMInert); inert != (call[0] != "filter") {
			t.Fatalf("genuine hook %s/%s: %q", call[1], call[0], out)
		}
	}
	after := n.state(t)
	if after.Mangle4 != rewritten || nfqws2NDMOwned(after.Mangle4) || after.NAT4 != before.NAT4 || after.Mangle6 != before.Mangle6 || after.Filter4 != before.Filter4 {
		t.Fatalf("the hook changed the rewritten tables:\n%s", after.Mangle4)
	}
	if n.daemon(t) != daemon {
		t.Fatal("the stock daemon changed")
	}
	err := n.f.a.Health(nfqws2NDMContext(t), plan, "")
	if err == nil {
		t.Fatal("Health accepted the lost owned graph")
	}
	t.Logf("defect reproduced: daemon pid=%d start=%s uid=%s queue=300 port=%s inode=%s copy_mode=%s copy_range=%s; mangle after the genuine hook has no owned token; Health: %s",
		daemon.PID, daemon.Start, daemon.UID, daemon.Port, daemon.Inode, daemon.CopyMode, daemon.CopyRange, strings.SplitN(err.Error(), ":", 2)[0])
}
