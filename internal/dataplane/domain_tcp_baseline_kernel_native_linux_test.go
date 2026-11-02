//go:build linux

package dataplane

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Native routing/readback comparison, not an accepted-FD issuer or DNS grant.
// Every mutation is inside a fresh disposable child network namespace.
func TestDomainTCPBaselineNativeKernelComparison(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_NATIVE") != "1" {
		t.Skip("opt-in disposable Linux namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Getenv("RAZVILKA_DOMAIN_BASELINE_CHILD") != "1" {
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--fork", os.Args[0], "-test.run=^TestDomainTCPBaselineNativeKernelComparison$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_DOMAIN_BASELINE_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated native baseline: %v %s", err, out)
		}
		t.Log(string(out))
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace fixture requires root")
	}
	initial, _ := os.Readlink("/proc/1/ns/net")
	current, _ := os.Readlink("/proc/self/ns/net")
	if current == "" || current == initial {
		t.Fatal("refuse initial network namespace")
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture %s %v: %v %s", name, args, err, out)
		}
		return out
	}
	run("ip", "link", "set", "lo", "up")
	for _, pair := range [][2]string{{"lan0", "lanpeer"}, {"wan0", "wanpeer"}} {
		run("ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		for _, name := range pair {
			run("ip", "link", "set", name, "up")
		}
	}
	run("ip", "addr", "add", "192.168.1.1/24", "dev", "lan0")
	run("ip", "addr", "add", "1.1.1.254/24", "dev", "wan0")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, spec := domainTCPBaselineKernelModel(t)
	spec.Client.Interface = "lan0"
	spec.Client.Address = netip.MustParseAddr("192.168.1.10")
	spec.Listen = netip.MustParseAddrPort("192.168.1.1:18091")
	spec.Xray.RealIP = netip.MustParseAddr("1.1.1.2")
	read := func() DomainTCPBaselineReadImage {
		return DomainTCPBaselineReadImage{
			Rules: run("ip", "-4", "-j", "rule", "show"), Routes: run("ip", "-4", "-j", "route", "show", "table", "all"), Links: run("ip", "-j", "-details", "link", "show"), Lookup: run("ip", "-4", "-j", "route", "get", spec.Xray.RealIP.String(), "from", spec.Client.Address.String(), "iif", spec.Client.Interface),
		}
	}
	image := read()
	if path, err := domainTCPBaselineKernelContract(image, spec); err != nil || path.Egress != "wan0" {
		t.Fatalf("actual kernel comparison: %v %v rules=%s routes=%s links=%s lookup=%s", path, err, image.Rules, image.Routes, image.Links, image.Lookup)
	}
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bounded, done := context.WithTimeout(ctx, 2*time.Second)
	if err := domainTCPBaselineForwarding(bounded, &networkPolicyIdentity{provider: provider, value: identity}); err != nil {
		done()
		t.Fatal("actual forwarding/qdisc observer", err)
	}
	done()
	// A hidden ingress/clsact hook is absent from ip-link's root qdisc name.
	run("tc", "qdisc", "add", "dev", "lan0", "clsact")
	bounded, done = context.WithTimeout(ctx, 2*time.Second)
	err = domainTCPBaselineForwarding(bounded, &networkPolicyIdentity{provider: provider, value: identity})
	done()
	if err == nil {
		t.Fatal("independent clsact attachment granted baseline")
	}
	run("tc", "qdisc", "del", "dev", "lan0", "clsact")
	run("ip", "-4", "rule", "add", "priority", "100", "fwmark", "0x1", "lookup", "main")
	if _, err := domainTCPBaselineKernelContract(read(), spec); err == nil {
		t.Fatal("foreign RPDB policy granted baseline")
	}
	t.Log("actual forwarded route/default RPDB/whole-link comparison and original procfs+netlink readback; foreign RPDB and hidden clsact refused; no accepted flow/publication grant")
}
