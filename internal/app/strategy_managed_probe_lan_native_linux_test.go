//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"golang.org/x/sys/unix"
)

func TestManagedStrategyProbeNativeLANAppHTTP(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, true, "lan")
}

func managedProbeNativeWANListener() (listener net.Listener, result error) {
	runtime.LockOSThread()
	unlock := true
	defer func() {
		if unlock {
			runtime.UnlockOSThread()
		}
	}()
	original, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer original.Close()
	peer, err := os.Open("/run/netns/rzwanpeer")
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	if err := unix.Setns(int(peer.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, err
	}
	defer func() {
		if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
			if listener != nil {
				_ = listener.Close()
				listener = nil
			}
			result = errors.Join(result, err)
			// The sole caller immediately Fatal's this error. Leave the
			// thread locked so Go destroys it instead of reusing a WAN thread.
			unlock = false
			return
		}
	}()
	return net.Listen("tcp4", "8.8.8.8:443")
}

func approveManagedProbeNativeLAN(t *testing.T, c context.Context, a *App, control *operationgate.ControlEpochReview) {
	t.Helper()
	if err := a.ConfigureDefaultConsent(filepath.Join(filepath.Dir(a.SelfUpdateFiles.ControlRoot), "config.json"), ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{physicalscope.NativeFixtureHomeInterface}, ExcludedDeviceIDs: []string{"mac-02-00-00-77-00-20"}}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	ref := control.Reference()
	if _, err := a.Store.ApproveDefaultRouteConsent(c, a.Store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
		t.Fatal(err)
	}
}

// Exactly the production original-policy dispatch; none of these callbacks
// accepts a DTO as permission, and no fabricated success skips its checks.
func configureManagedProbeNativeLANBinding(lan *dataplane.LANPolicyRuntime, binding *dataplane.LANPolicyReceiptBinding, owner func() *managedListPolicyOwner) {
	lan.TransportCheck = func(c context.Context, p *dataplane.LANPolicyRuntimePlan, family int, line string) error {
		o := owner()
		if o == nil || o.checks == nil {
			return dataplane.ErrNetworkPolicyConsumers
		}
		return o.checks.WGTransportCheck(c, p, family, line)
	}
	lan.ConsumerCheck = func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		o := owner()
		if o == nil || o.checks == nil {
			return dataplane.ErrNetworkPolicyConsumers
		}
		return o.checks.ConsumerCheck(c, p)
	}
	binding.ApplyGuard = func(c context.Context, p *dataplane.LANPolicyRuntimePlan, e dataplane.LANPolicyEffect) error {
		o := owner()
		if o == nil {
			return dataplane.ErrNetworkPolicyConsumers
		}
		return o.lanApplyGuard(c, p, e)
	}
	binding.CleanupGuard = func(c context.Context, p *dataplane.LANPolicyRuntimePlan, e dataplane.LANPolicyEffect) error {
		o := owner()
		if o == nil {
			return dataplane.ErrNetworkPolicyConsumers
		}
		return o.lanCleanupGuard(c, p, e)
	}
	binding.RetireCheck = func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		o := owner()
		if o == nil || o.checks == nil {
			return dataplane.ErrNetworkPolicyConsumers
		}
		return o.checks.RetireCheck(c, p)
	}
}

func runManagedProbeNativeLANApply(t *testing.T, a *App, request func(string, string, string) (int, []byte), readEmpty func(context.Context) error) {
	t.Helper()
	r := a.managedNFQList
	if r == nil || !r.original() {
		t.Fatal("original App runtime absent")
	}
	stopped := false
	defer func() {
		if !stopped {
			c, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := r.Stop(c); err != nil {
				t.Error("retained original LAN cleanup", err)
			}
		}
	}()
	// Changing the actual catalogue to domains-only must refuse with no
	// effects. Restore it before the genuine positive source review.
	beforeConfig := a.Store.Get()
	originalCatalog := a.catalogSnapshot()
	negativeCatalog := originalCatalog
	negativeCatalog.Services = append(negativeCatalog.Services[:0:0], originalCatalog.Services...)
	negativeCatalog.Services[0].CIDRs = nil
	negativeCatalog.Services[0].Domains = []string{"managed-probe.example"}
	a.Catalog = negativeCatalog
	negativeCode, negativeData := request(http.MethodGet, "/api/v1/plan?scope=all", "")
	a.Catalog = originalCatalog
	if negativeCode == http.StatusOK || !reflect.DeepEqual(beforeConfig, a.Store.Get()) || r.active != nil || r.pending != nil {
		t.Fatal("domains-only actual LAN review admitted or mutated state", negativeCode, string(negativeData))
	}
	code, data := request(http.MethodGet, "/api/v1/plan?scope=all", "")
	var plan struct {
		Review      applyReview    `json:"review"`
		Transaction dataplane.Plan `json:"transaction"`
	}
	if code != http.StatusOK || json.Unmarshal(data, &plan) != nil || plan.Review.Digest == "" || !plan.Transaction.Ready {
		t.Fatal("actual original LAN review", code, string(data))
	}
	body, err := json.Marshal(plan.Review)
	if err != nil {
		t.Fatal(err)
	}
	code, data = request(http.MethodPost, "/api/v1/apply?scope=all", string(body))
	if code != http.StatusOK {
		t.Fatal("actual original LAN Apply", code, string(data))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := r.Current(ctx); err != nil {
		t.Fatal("actual current committed LAN owner", err)
	}
	before := managedProbeNativeLANQueuePackets(t, ctx)
	managedProbeNativeLANRequest(t, ctx, "rzexcluded")
	afterExcluded := managedProbeNativeLANQueuePackets(t, ctx)
	if afterExcluded != before {
		t.Fatal("excluded actual LAN client reached owned NFQUEUE", before, afterExcluded)
	}
	if err := r.Current(ctx); err != nil {
		t.Fatal("closing excluded actual LAN owner", err)
	}
	managedProbeNativeLANRequest(t, ctx, "rzincluded")
	afterIncluded := managedProbeNativeLANQueuePackets(t, ctx)
	if afterIncluded <= afterExcluded {
		t.Fatal("included actual LAN client missed owned NFQUEUE", afterExcluded, afterIncluded)
	}
	if err := r.Current(ctx); err != nil {
		t.Fatal("closing included actual LAN owner", err)
	}
	if err := r.Stop(ctx); err != nil {
		t.Fatal("same original LAN Stop", err)
	}
	stopped = true
	if err := readEmpty(ctx); err != nil {
		t.Fatal("LAN Stop left owned queue rules", err)
	}
	// After removal both clients must still reach the distinct actual WAN.
	managedProbeNativeLANRequest(t, ctx, "rzincluded")
	managedProbeNativeLANRequest(t, ctx, "rzexcluded")
	t.Log("actual authenticated three-pass probe/manual selection → SAME Review/Apply/COMMON/native consumer → included LAN counter positive/excluded negative → original Stop/empty inventory/recovered direct TLS; Home classification only modeled")
}

func managedProbeNativeLANRequest(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	const program = `import ssl,urllib.request,sys
context=ssl.create_default_context(cafile=sys.argv[1])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
with opener.open('https://managed-probe.example/',timeout=5) as response:
 assert response.status==200 and response.read(32769)==b'owned-native-service'
`
	managedProbeNativeIP(t, ctx, "netns", "exec", name, "/usr/bin/python3", "-c", program, os.Getenv("SSL_CERT_FILE"))
}

func managedProbeNativeLANQueuePackets(t *testing.T, ctx context.Context) uint64 {
	t.Helper()
	out, err := exec.CommandContext(ctx, "/usr/sbin/iptables-legacy-save", "-c", "-t", "mangle").Output()
	if err != nil {
		t.Fatal("actual readonly LAN counters", err)
	}
	var total uint64
	rows := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "-A" || !strings.HasPrefix(fields[2], "RZQ_") || !strings.Contains(" "+line+" ", " -j NFQUEUE --queue-num 200 ") {
			continue
		}
		counters := strings.Split(strings.Trim(fields[0], "[]"), ":")
		if len(counters) != 2 {
			t.Fatal("actual owned counter shape", line)
		}
		count, err := strconv.ParseUint(counters[0], 10, 64)
		if err != nil || ^uint64(0)-total < count {
			t.Fatal("actual owned counter value", line, err)
		}
		total += count
		rows++
	}
	if rows == 0 {
		t.Fatal("actual owned NFQUEUE rows absent", string(out))
	}
	return total
}

// Modeled negative pointer checks are separate from the actual kernel case.
func TestNativeFixturePhysicalSourceCopiesRefuse(t *testing.T) {
	a := &App{}
	r := &ManagedNFQWSListRuntime{app: a, provider: netidentity.NewProcProvider()}
	r.self = r
	a.managedNFQList = r
	s := &nativeFixtureNFQListPhysicalSource{runtime: r, app: a, provider: r.provider}
	s.self = s
	r.physicalSource = s
	if !s.original(r) {
		t.Fatal("original source refused")
	}
	copy := &nativeFixtureNFQListPhysicalSource{self: s, runtime: r, app: a, provider: r.provider}
	if copy.original(r) {
		t.Fatal("copied source admitted")
	}
	r.physicalSource = nil
	if s.original(r) {
		t.Fatal("replaced source slot admitted")
	}
	r.physicalSource = s
	a.managedNFQList = &ManagedNFQWSListRuntime{}
	if s.original(r) {
		t.Fatal("replaced App runtime admitted")
	}
}

// Classification of rzhome as Home is modeled. Everything else is actual:
// separate network namespaces, WAN route, two clients, bridge FDB, ARP and the
// retained Linux Observer/Review and packet fence. This is not router proof.
func TestManagedStrategyProbeNativeLANPhysical(t *testing.T) {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("explicit private namespace fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	setupManagedProbeNativeLAN(t, ctx)
	root, err := os.MkdirTemp("/var/lib", "razvilka-lan-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: controlRoot}, FreshProfile: func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }}
	if err := a.ConfigureDefaultConsent(filepath.Join(root, "config.json"), ""); err != nil {
		t.Fatal(err)
	}
	defer a.CloseDefaultConsent()
	c, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(c, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{physicalscope.NativeFixtureHomeInterface}, ExcludedDeviceIDs: []string{"mac-02-00-00-77-00-20"}}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	ref := control.Reference()
	if _, err := store.ApproveDefaultRouteConsent(c, store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
		t.Fatal(err)
	}
	provider := netidentity.NewProcProvider()
	intent, err := nfqwsPacketIntent(store.Get())
	if err != nil {
		t.Fatal(err)
	}
	if old, err := physicalscope.NewReviewedStockNC1812IPv4LANPacketScope(c, provider, control, controlRoot, func(context.Context) (physicalscope.IPv4LANPacketIntent, error) { return intent, nil }); err == nil {
		_ = old.Close()
		t.Fatal("production stock packet factory accepted Proc identity")
	} else if !strings.Contains(err.Error(), "packet.identity.kind") {
		t.Fatal("stock Proc refusal did not reach identity boundary", err)
	}
	if old, err := NewReviewedStockNC1812ListScopeBinding(c, a, provider); err == nil {
		_ = old.Close()
		t.Fatal("production stock list factory accepted Proc identity")
	}
	b, err := NewNativeFixtureListScopeBinding(c, a, provider)
	if err != nil {
		t.Fatal("actual Linux source", err)
	}
	defer b.Close()
	if b.originalPhysicalObserver == nil || b.originalPhysicalReview == nil || b.facts.Identity.Kind != netidentity.ProcNetInode || len(b.facts.Segments) != 1 || !b.facts.Segments[0].Home || b.facts.Segments[0].Interface != "rzhome" {
		t.Fatal("original Linux source lost", b.facts)
	}
	seen := map[string]bool{}
	for _, d := range b.facts.Devices {
		seen[d.MAC] = true
	}
	if !seen["02:00:00:77:00:10"] || !seen["02:00:00:77:00:20"] {
		t.Fatal("real client neighbors/FDB absent", b.facts.Devices)
	}
	p, err := NewNativeFixtureNFQWSPacketScopeBinding(c, a, provider)
	if err != nil {
		t.Fatal("actual packet scope", err)
	}
	defer p.Close()
	view, err := p.Observe(c)
	if err != nil || p.original == nil || view.Facts.Identity.Kind != netidentity.ProcNetInode || view.Facts.Home.Interface != "rzhome" || len(view.Facts.ExcludedMACs) != 1 || view.Facts.ExcludedMACs[0] != "02:00:00:77:00:20" {
		t.Fatal("actual packet selectors", view, err)
	}
	if out, err := CompileNFQWSIPv4LANPacketPolicy(store.Get(), view, nil, nil, time.Now()); out != nil || !errors.Is(err, dataplane.ErrReviewChanged) {
		t.Fatal("public stock compiler accepted genuine Proc comparison", out, err)
	}
	// A real structural event must invalidate these SAME retained sources.
	managedProbeNativeIP(t, ctx, "link", "set", "rzhome", "down")
	if _, err := p.Observe(c); err == nil {
		t.Fatal("real bridge-down drift accepted by packet source")
	}
	if _, err := b.Observe(c); err == nil {
		t.Fatal("real bridge-down drift accepted by list source")
	}
	t.Log("actual WAN peer + bridge + included/excluded clients + route/FDB/ARP + original Linux owners + real drift refusal; only Home classification modeled; no NFQ Apply/router acceptance")
}

func managedProbeNativeIP(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput()
	if err != nil {
		t.Fatal("actual isolated topology", args, string(out), err)
	}
}

func setupManagedProbeNativeLAN(t *testing.T, ctx context.Context) {
	t.Helper()
	net, err := os.Stat("/proc/self/ns/net")
	initial, e := os.Stat("/proc/1/ns/net")
	mount, me := os.Stat("/proc/self/ns/mnt")
	initialMount, ime := os.Stat("/proc/1/ns/mnt")
	if os.Geteuid() != 0 || err != nil || e != nil || me != nil || ime != nil || os.SameFile(net, initial) || os.SameFile(mount, initialMount) {
		t.Fatal("actual private mount and network namespaces required")
	}
	links, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-o", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(links)), "\n") {
		if !strings.Contains(line, ": lo:") {
			t.Fatal("fresh empty network namespace required", line)
		}
	}
	// /run/netns entries and namespace mounts stay entirely in this private
	// tmpfs. Never create named namespaces in the host's shared /run tree.
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rzwanpeer", "rzincluded", "rzexcluded"} {
		managedProbeNativeIP(t, ctx, "netns", "add", name)
	}
	t.Cleanup(func() {
		for _, name := range []string{"rzwanpeer", "rzincluded", "rzexcluded"} {
			_ = exec.Command("/usr/sbin/ip", "netns", "del", name).Run()
		}
	})
	ip := func(args ...string) { managedProbeNativeIP(t, ctx, args...) }
	ip("link", "set", "lo", "up")
	ip("link", "add", "rzwan", "type", "veth", "peer", "name", "rzserver")
	ip("link", "set", "rzserver", "netns", "rzwanpeer")
	ip("addr", "add", "8.8.8.1/24", "dev", "rzwan")
	ip("link", "set", "rzwan", "up")
	ip("route", "add", "default", "via", "8.8.8.8", "dev", "rzwan")
	ip("-n", "rzwanpeer", "link", "set", "lo", "up")
	ip("-n", "rzwanpeer", "addr", "add", "8.8.8.8/24", "dev", "rzserver")
	ip("-n", "rzwanpeer", "link", "set", "rzserver", "up")
	ip("-n", "rzwanpeer", "route", "add", "192.168.77.0/24", "via", "8.8.8.1")
	ip("link", "add", "rzhome", "type", "bridge")
	ip("addr", "add", "192.168.77.1/24", "dev", "rzhome")
	ip("link", "set", "rzhome", "up")
	for i, name := range []string{"rzincluded", "rzexcluded"} {
		port := []string{"rzport10", "rzport20"}[i]
		address := []string{"192.168.77.10/24", "192.168.77.20/24"}[i]
		mac := []string{"02:00:00:77:00:10", "02:00:00:77:00:20"}[i]
		ip("link", "add", port, "type", "veth", "peer", "name", "rzclient")
		ip("link", "set", "rzclient", "netns", name)
		ip("link", "set", port, "master", "rzhome")
		ip("link", "set", port, "up")
		ip("-n", name, "link", "set", "lo", "up")
		ip("-n", name, "link", "set", "rzclient", "address", mac)
		ip("-n", name, "addr", "add", address, "dev", "rzclient")
		ip("-n", name, "link", "set", "rzclient", "up")
		ip("-n", name, "route", "add", "default", "via", "192.168.77.1")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rzincluded", "rzexcluded"} {
		ip("netns", "exec", name, "/usr/bin/ping", "-c", "1", "-W", "2", "8.8.8.8")
	}
	awaitManagedProbeNativeLANAddresses(t, ctx)
}

// Let the actual IPv6 DAD protocol settle before acquiring the immutable
// original topology. Production readers still reject tentative/failed rows;
// this test preflight never filters, edits or fabricates their capture.
func awaitManagedProbeNativeLANAddresses(t *testing.T, ctx context.Context) {
	t.Helper()
	settle, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		data, err := exec.CommandContext(settle, "/usr/sbin/ip", "-j", "address", "show").Output()
		if err != nil || len(data) > 64<<10 {
			t.Fatal("actual address settlement read", err)
		}
		var links []struct {
			IfName    string `json:"ifname"`
			Addresses []struct {
				Tentative bool     `json:"tentative"`
				DADFailed bool     `json:"dadfailed"`
				Flags     []string `json:"flags"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(data, &links); err != nil {
			t.Fatal(err)
		}
		pending := false
		for _, link := range links {
			for _, a := range link.Addresses {
				if a.DADFailed {
					t.Fatal("actual fixture DAD failed", link.IfName)
				}
				pending = pending || a.Tentative
				for _, flag := range a.Flags {
					if flag == "dadfailed" {
						t.Fatal("actual fixture DAD failed", link.IfName)
					}
					pending = pending || flag == "tentative"
				}
			}
		}
		if !pending {
			return
		}
		select {
		case <-settle.Done():
			t.Fatal("actual fixture addresses remained tentative", settle.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
