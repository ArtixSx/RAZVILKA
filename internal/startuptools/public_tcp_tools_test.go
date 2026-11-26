package startuptools

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

func publicTCPLeaseModel(t *testing.T) *Lease {
	t.Helper()
	l := syntheticDNSLeaseModel(t)
	f, err := os.CreateTemp(t.TempDir(), "public-source-model")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	l.review.entry[1] = &heldImage{file: f}
	return l
}
func TestPublicTCPProtectedSourceDescriptorNeverIssuesAdmission(t *testing.T) {
	for _, l := range []*Lease{nil, {}, unitLease(t), syntheticDNSLeaseModel(t)} {
		if _, err := l.PublicTCPCommandTools(); !errors.Is(err, ErrUnknown) {
			t.Fatal("incomplete source accepted", err)
		}
	}
	for _, revoke := range []func(*Lease){func(l *Lease) { l.cancel() }, func(l *Lease) { _ = l.Close() }} {
		l := publicTCPLeaseModel(t)
		revoke(l)
		if _, err := l.PublicTCPCommandTools(); !errors.Is(err, ErrUnknown) {
			t.Fatal("revoked source accepted", err)
		}
	}
	l := publicTCPLeaseModel(t)
	tools, err := l.PublicTCPCommandTools()
	if err != nil {
		t.Fatal(err)
	}
	runner, ok := tools.Runner.(*publicTCPRunner)
	if !ok || runner.lease != l || tools.Provider != l.provider || tools.Identity != l.identity || tools.ReviewSHA256 != l.digest || tools.IP != l.profile.ipAlias || tools.IPTables != l.profile.aliases[0] || tools.IP6Tables != l.profile.aliases[1] {
		t.Fatal("source substituted")
	}
	if _, generic := tools.Runner.(interface {
		Run(context.Context, string, ...string) ([]byte, error)
	}); generic {
		t.Fatal("generic command authority exposed")
	}
	if _, err := tools.Runner.RunPublicTCP(context.Background(), nil, tools.IPTables, "-F"); !errors.Is(err, ErrUnknown) {
		t.Fatal("descriptor issued command without original admission")
	}
}
func TestPublicTCPCommandABIIsExactAndScoped(t *testing.T) {
	capture := []string{"-t", "nat", "-A", "PREROUTING", "-i", "br0", "-s", "192.168.1.40/32", "-d", "8.6.112.1/32", "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", "rzpc:0123456789abcdef0123", "-j", "REDIRECT", "--to-ports", "18081"}
	baseline := []string{"-t", "mangle", "-A", "PREROUTING", "-i", "wan0", "-s", "8.6.112.1/32", "-d", "192.168.1.40/32", "-p", "tcp", "--sport", "443", "--dport", "30001", "-m", "socket", "--transparent", "--nowildcard", "-m", "comment", "--comment", "rzpb:0123456789abcdef0123", "-j", "MARK", "--set-xmark", "0x52000001/0xffffffff"}
	for _, c := range []struct {
		index int
		args  []string
	}{{0, capture}, {0, baseline}, {2, []string{"-4", "rule", "add", "priority", "15000", "fwmark", "0x52000001/0xffffffff", "lookup", "16001"}}, {2, []string{"-4", "route", "add", "local", "192.168.1.40/32", "dev", "lo", "table", "16001"}}} {
		if !publicTCPArguments(c.index, c.args) {
			t.Fatalf("compiler ABI refused %v", c.args)
		}
		if publicTCPArguments(c.index, append(slices.Clone(c.args), "extra")) {
			t.Fatal("trailing operands admitted")
		}
		for i := range c.args {
			bad := slices.Clone(c.args)
			bad[i] = "unknown"
			if c.index == 0 && i == 5 {
				bad[i] = "bad interface"
			}
			if publicTCPArguments(c.index, bad) {
				t.Fatalf("unknown field %d admitted", i)
			}
		}
	}
	for _, mutate := range []func([]string){func(a []string) { a[7] = "0.0.0.0/0" }, func(a []string) { a[7] = "192.168.1.0/24" }, func(a []string) { a[9] = "8.6.112.0/24" }, func(a []string) { a[13] = "ff:ff:ff:ff:ff:ff" }, func(a []string) { a[17] = "53" }, func(a []string) { a[25] = "80" }, func(a []string) { a[5] = "lo" }} {
		bad := slices.Clone(capture)
		mutate(bad)
		if publicTCPArguments(0, bad) {
			t.Fatalf("broad capture ABI admitted %v", bad)
		}
	}
	for _, mutate := range []func([]string){func(a []string) { a[15] = "0" }, func(a []string) { a[15] = "30000:40000" }, func(a []string) { a[18] = "--wildcard" }, func(a []string) { a[27] = "0x52000001/0xff" }} {
		bad := slices.Clone(baseline)
		mutate(bad)
		if publicTCPArguments(0, bad) {
			t.Fatal("broad return diversion admitted")
		}
	}
}
