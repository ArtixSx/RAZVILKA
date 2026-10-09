package startuptools

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Comparison-only private source model. No Acquire, native command, Manager
// admission, policy lease publication or readiness is simulated by these files.
func syntheticDNSLeaseModel(t *testing.T) *Lease {
	t.Helper()
	l := unitLease(t)
	l.profile = ubuntuPolicyProfile()
	l.review.profile = l.profile
	for i := range 2 {
		file, err := os.CreateTemp(t.TempDir(), "source-model")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		image := &heldImage{file: file}
		l.review.images[file.Name()] = image
		if i == 0 {
			l.review.entry[0] = image
		} else {
			l.review.ipEntry = image
		}
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestSyntheticDNSFactoryRejectsUnissuedCancelledAndClosedSources(t *testing.T) {
	for _, l := range []*Lease{nil, {}, unitLease(t)} {
		if _, err := l.SyntheticDNSCommandTools(); !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued or inventory-only source returned descriptor", err)
		}
	}
	for _, revoke := range []func(*Lease){func(l *Lease) { l.cancel() }, func(l *Lease) { _ = l.Close() }} {
		l := syntheticDNSLeaseModel(t)
		revoke(l)
		if _, err := l.SyntheticDNSCommandTools(); !errors.Is(err, ErrUnknown) {
			t.Fatal("revoked source returned descriptor", err)
		}
	}
	for name, mutate := range map[string]func(*Lease){
		"policy-image":       func(l *Lease) { l.review.ipEntry = nil },
		"held-policy-file":   func(l *Lease) { l.review.ipEntry.file = nil },
		"iptables-image":     func(l *Lease) { l.review.entry[0] = nil },
		"held-iptables-file": func(l *Lease) { l.review.entry[0].file = nil },
		"policy-alias":       func(l *Lease) { l.profile.ipAlias = "" },
		"iptables-alias":     func(l *Lease) { l.profile.aliases[0] = "" },
		"review-digest":      func(l *Lease) { l.digest = "copied-version" },
		"provider":           func(l *Lease) { l.provider = nil },
		"identity":           func(l *Lease) { l.identity = netidentity.Identity{} },
	} {
		t.Run(name, func(t *testing.T) {
			l := syntheticDNSLeaseModel(t)
			mutate(l)
			if _, err := l.SyntheticDNSCommandTools(); !errors.Is(err, ErrUnknown) {
				t.Fatal("incomplete policy source returned descriptor", err)
			}
		})
	}
}

func TestSyntheticDNSDescriptorRetainsOriginalSourceWithoutGenericRun(t *testing.T) {
	l := syntheticDNSLeaseModel(t)
	tools, err := l.SyntheticDNSCommandTools()
	if err != nil {
		t.Fatal(err)
	}
	runner, ok := tools.Runner.(*syntheticDNSRunner)
	if !ok || runner.lease != l || tools.Provider != l.provider || tools.Identity != l.identity || tools.ReviewSHA256 != l.digest || tools.IPTables != l.profile.aliases[0] {
		t.Fatal("factory substituted original source")
	}
	if _, generic := tools.Runner.(interface {
		Run(context.Context, string, ...string) ([]byte, error)
	}); generic {
		t.Fatal("sealed command runner exposed generic execution")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tools.Runner.CheckSyntheticDNS(context.Background(), tools.Identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("copied descriptor survived original Close", err)
	}
}

func TestSyntheticDNSRunnerCannotBorrowUnsealedAdmissionFromContext(t *testing.T) {
	l := syntheticDNSLeaseModel(t)
	tools, err := l.SyntheticDNSCommandTools()
	if err != nil {
		t.Fatal(err)
	}
	starts := 0
	original, cancel := context.WithTimeout(context.WithValue(context.Background(), l, "original caller"), time.Second)
	defer cancel()
	ctx := WithCommandAdmission(original, admissionFunc(func(context.Context, string, []string, string, func() error) error { starts++; return nil }))
	for _, runner := range []*syntheticDNSRunner{nil, {}, tools.Runner.(*syntheticDNSRunner)} {
		out, err := runner.RunSyntheticDNS(ctx, nil, tools.IPTables, "-t", "nat", "-N", "RZSB_0123456789abcdef0123")
		if !errors.Is(err, ErrUnknown) || len(out) != 0 || starts != 0 {
			t.Fatal("generic context callback replaced sealed admission", err)
		}
	}
	if ctx.Value(l) != "original caller" || ctx.Err() != nil {
		t.Fatal("rejection changed original context")
	}
}

func syntheticDNSABIModel() (string, []string, []string) {
	chain := "RZSB_0123456789abcdef0123"
	body := []string{"-t", "nat", "-A", chain, "-p", "tcp", "-j", "DNAT", "--to-destination", "93.184.215.14"}
	selector := []string{"-t", "nat", "-A", "PREROUTING", "-i", "br0", "-s", "192.168.1.42/32", "-d", "198.18.0.1/32", "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-p", "tcp", "-m", "tcp", "--dport", "80", "-j", chain}
	return chain, body, selector
}

func TestSyntheticDNSABIAllowsOnlyExactStandbyAddDeleteShapes(t *testing.T) {
	chain, body, selector := syntheticDNSABIModel()
	commands := [][]string{{"-t", "nat", "-N", chain}, {"-t", "nat", "-X", chain}}
	for _, operation := range []string{"-A", "-D"} {
		b := slices.Clone(body)
		b[2] = operation
		commands = append(commands, b)
		for _, port := range []string{"80", "443"} {
			s := slices.Clone(selector)
			s[2], s[19] = operation, port
			commands = append(commands, s)
		}
	}
	for _, args := range commands {
		if !syntheticDNSArguments(args) {
			t.Fatal("current standby compiler shape refused", args)
		}
		if syntheticDNSArguments(append(slices.Clone(args), "extra")) {
			t.Fatal("extra argument widened exact standby shape")
		}
	}
}

func TestSyntheticDNSABIRejectsBroadCommandsAndOtherChains(t *testing.T) {
	chain, body, _ := syntheticDNSABIModel()
	bad := [][]string{nil, {"-t", "nat", "-S"}, {"-t", "nat", "-F", chain}, {"-t", "nat", "-Z", chain}, {"-t", "nat", "-P", "PREROUTING", "ACCEPT"}, {"--restore", "/private/rules"}}
	for _, table := range []string{"mangle", "filter", "raw", "security"} {
		args := slices.Clone(body)
		args[1] = table
		bad = append(bad, args)
	}
	for _, operation := range []string{"-I", "-R", "-C", "-S", "--append"} {
		args := slices.Clone(body)
		args[2] = operation
		bad = append(bad, args)
	}
	for _, value := range []string{"PREROUTING", "RZG_0123456789abcdef0123", "RZSB_0123456789ABCDEF0123", "RZSB_0123456789abcdef012", chain + "a", "-N", chain + "\n"} {
		bad = append(bad, []string{"-t", "nat", "-N", value})
		args := slices.Clone(body)
		args[3] = value
		bad = append(bad, args)
	}
	for _, args := range bad {
		if syntheticDNSArguments(args) {
			t.Fatal("unreviewed broad command entered standby ABI", args)
		}
	}
}

func TestSyntheticDNSABIRejectsNonPublicOrNonCanonicalDNAT(t *testing.T) {
	_, body, _ := syntheticDNSABIModel()
	for _, value := range []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "0.1.1.1", "240.1.1.1", "255.255.255.255", "224.0.0.1", "::ffff:93.184.215.14", "2001:4860::1", "93.184.215.14:80", "93.184.215.14/32", "093.184.215.14", "public.example", "93.184.215.14\n"} {
		args := slices.Clone(body)
		args[9] = value
		if syntheticDNSArguments(args) {
			t.Fatal("non-public/canonical IPv4 DNAT entered ABI", value)
		}
	}
	for index, value := range map[int]string{4: "--protocol", 5: "udp", 6: "--jump", 7: "REDIRECT", 8: "--to"} {
		args := slices.Clone(body)
		args[index] = value
		if syntheticDNSArguments(args) {
			t.Fatal("alternate DNAT shape entered ABI")
		}
	}
}

func TestSyntheticDNSABIRejectsWiderClientSyntheticMACPortAndIngress(t *testing.T) {
	_, _, selector := syntheticDNSABIModel()
	for index, values := range map[int][]string{
		3:  {"OUTPUT", "FORWARD"},
		5:  {"", "lo", "br+", "br0 ", "br/0", "br\\0", "br\t0", "br\n0", "br\x7f0", "сегмент", strings.Repeat("a", 16)},
		7:  {"192.168.1.0/24", "192.168.1.42", "93.184.215.14/32", "::ffff:192.168.1.42/128"},
		9:  {"198.18.0.0/15", "198.18.0.1", "198.20.0.1/32", "10.0.0.1/32", "2001:db8::1/128"},
		13: {"00:00:00:00:00:00", "03:00:00:00:00:02", "02:AA:00:00:00:02", "02-00-00-00-00-02", "02:00:00:00:00:00:00:02"},
		15: {"udp", "all"}, 19: {"0", "53", "8080", "80,443", "080"}, 21: {"DNAT", "RZG_foreign", "RZSB_bad"},
	} {
		for _, value := range values {
			args := slices.Clone(selector)
			args[index] = value
			if syntheticDNSArguments(args) {
				t.Fatal("restorative tuple widened", index, value)
			}
		}
	}
	for _, index := range []int{4, 6, 8, 10, 11, 12, 14, 16, 17, 18, 20} {
		args := slices.Clone(selector)
		args[index] = "extra"
		if syntheticDNSArguments(args) {
			t.Fatal("selector grammar widened", index)
		}
	}
}
