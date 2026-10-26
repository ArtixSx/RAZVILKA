package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// A sanitized reduction of the NC-1812 iptables-save shape after a live
// first-start resume: the firmware multicast TTL and hotspot MAC RETURN
// chains run before the owned PREROUTING hook, empty firmware chains precede
// the POSTROUTING hook and the firmware OUTPUT delay queue stays foreign.
// Only fake MACs, loopback and protocol-constant addresses are used.
const nfqws2RouterMangleFixture = `*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_DNSRT_PREROUTING_MANGLE - [0:0]
:_NDM_HOTSPOT_PREROUTING_MANGL - [0:0]
:_NDM_IPSEC_POSTR_MANGLE - [0:0]
:_NDM_IPSEC_PREROUTING - [0:0]
:_NDM_OUTPUT_DELAY - [0:0]
:_NDM_POSTROUTING_TTL - [0:0]
:_NDM_PREROUTING_MC - [0:0]
:_NDM_PREROUTING_TTL - [0:0]
:_NDM_VPN_PREROUTING - [0:0]
:nfqws_post - [0:0]
:nfqws_pre - [0:0]
-A PREROUTING -d 224.0.0.0/4 -j _NDM_PREROUTING_MC
-A PREROUTING -j _NDM_IPSEC_PREROUTING
-A PREROUTING -j _NDM_VPN_PREROUTING
-A PREROUTING -j _NDM_PREROUTING_TTL
-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL
-A PREROUTING -m mark --mark 0x0 -j _NDM_DNSRT_PREROUTING_MANGLE
-A PREROUTING -j nfqws_pre
-A OUTPUT -j _NDM_OUTPUT_DELAY
-A POSTROUTING -j _NDM_IPSEC_POSTR_MANGLE
-A POSTROUTING -j _NDM_POSTROUTING_TTL
-A POSTROUTING -j nfqws_post
-A _NDM_HOTSPOT_PREROUTING_MANGL -m mac --mac-source 02:00:00:00:00:01 -j RETURN
-A _NDM_HOTSPOT_PREROUTING_MANGL -m mac --mac-source 02:00:00:00:00:02 -j RETURN
-A _NDM_HOTSPOT_PREROUTING_MANGL -m mac --mac-source 02:00:00:00:00:03 -j RETURN
-A _NDM_OUTPUT_DELAY ! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64511
-A _NDM_PREROUTING_MC -p udp -j TTL --ttl-inc 1
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN
-A nfqws_pre -i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir reply -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_pre -i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_pre -i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass
-A nfqws_pre -i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 300 --queue-bypass
COMMIT
`

// The rest of the sanitized IPv4 image: the stock nat state left by the
// closed graph (UDP MASQUERADE guarded off) and an unrelated filter table.
const nfqws2RouterNATFixture = `*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_MASQ - [0:0]
:nfqws_nat - [0:0]
-A POSTROUTING -j _NDM_MASQ
-A POSTROUTING -j nfqws_nat
COMMIT
`
const nfqws2RouterFilterFixture = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:_NDM_ACL - [0:0]
-A FORWARD -j _NDM_ACL
COMMIT
`

// The sanitized IPv6 firmware shape with IPv6 NFQWS2 disabled.
const nfqws2RouterIPv6Fixture = `*mangle
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
-A _NDM_OUTPUT_DELAY ! -s ::1/128 ! -d ::1/128 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64512
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`

const nfqws2RouterRunFixture = "ISP_INTERFACE=\"eth3\"\nIPV6_ENABLED=0\nTCP_PORTS=443\nUDP_PORTS=\nPOLICY_NAME=\"nfqws\"\nPOLICY_EXCLUDE=0\nPOLICY_MARK=\"\"\nNFQUEUE_NUM=300\n"

const nfqws2HookTestOwner = "111111111111111111111111"

func nfqws2HookTestConfig(t *testing.T, edit func(string) string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		raw = []byte(edit(string(raw)))
	}
	config, err := engineconfig.NFQWSFirstStartConfig(raw, nfqws2HookTestOwner, []string{"service.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func nfqws2HookTestGraph(t *testing.T, ipv6 bool) nfqws2HookGraph {
	t.Helper()
	config, run := nfqws2HookTestConfig(t, nil), nfqws2RouterRunFixture
	if ipv6 {
		config = nfqws2HookTestConfig(t, func(raw string) string { return strings.Replace(raw, "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1) })
		run = strings.Replace(run, "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1)
	}
	graph, err := nfqws2FirstStartHookGraph(config, []byte(run), nfqws2HookTestOwner)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// The literal "-A <owned chain>" lines of a save fixture, in order.
func nfqws2HookTestOwnedLines(save string) []string {
	var lines []string
	for _, line := range strings.Split(save, "\n") {
		if strings.HasPrefix(line, "-A nfqws_post ") || strings.HasPrefix(line, "-A nfqws_pre ") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestNFQWS2FirstStartHookGraphMatchesRouterShape(t *testing.T) {
	graph := nfqws2HookTestGraph(t, false)
	if graph.Interface != "eth3" || graph.Queue != 300 || graph.IPv6 || len(graph.Families) != 1 {
		t.Fatalf("closed scope rendered wrongly: %+v", graph)
	}
	family := graph.Families[0]
	if family.Family != 4 || !slices.Equal(family.Chains, []string{"nfqws_post", "nfqws_pre"}) || len(family.Bodies) != 8 {
		t.Fatalf("family shape: %+v", family)
	}
	var bodies []string
	for _, rule := range family.Bodies {
		bodies = append(bodies, strings.Join(rule.tokens(), " "))
	}
	// Golden against the sanitized router -S/save form: exact tokens, order.
	if want := nfqws2HookTestOwnedLines(nfqws2RouterMangleFixture); !slices.Equal(bodies, want) {
		t.Fatalf("bodies differ from the router shape:\n%s\nwant\n%s", strings.Join(bodies, "\n"), strings.Join(want, "\n"))
	}
	var jumps []string
	for _, rule := range family.Jumps {
		jumps = append(jumps, strings.Join(rule.tokens(), " "))
	}
	if !slices.Equal(jumps, []string{"-A POSTROUTING -j nfqws_post", "-A PREROUTING -j nfqws_pre"}) {
		t.Fatal("jumps", jumps)
	}
	if len(graph.NAT) != 2 || strings.Join(graph.NAT[0].Tokens, " ") != "-N nfqws_nat" || strings.Join(graph.NAT[1].Tokens, " ") != "-A POSTROUTING -j nfqws_nat" || graph.NAT[1].Table != "nat" || graph.NAT[1].Family != 4 {
		t.Fatal("nat expectation", graph.NAT)
	}
	rows := family.rows()
	if len(rows) != 12 || strings.Join(rows[0].Tokens, " ") != "-N nfqws_post" || strings.Join(rows[11].Tokens, " ") != "-A PREROUTING -j nfqws_pre" {
		t.Fatal("rows", rows)
	}
	// Health and the builder share one source: the closed post proof and the
	// new pre proof both accept the router image the builder renders.
	config := nfqws2HookTestConfig(t, nil)
	image := nfqws2RouterNATFixture + nfqws2RouterMangleFixture + nfqws2RouterFilterFixture
	if !nfqws2ClosedReachableQueueRule([]byte(image), config, []byte(nfqws2RouterRunFixture), nfqws2HookTestOwner) ||
		!nfqws2ClosedReachablePreRule([]byte(image), config, []byte(nfqws2RouterRunFixture), nfqws2HookTestOwner) {
		t.Fatal("router shape refused by the closed hook proof")
	}
	v6 := nfqws2HookTestGraph(t, true)
	if !v6.IPv6 || len(v6.Families) != 2 || v6.Families[1].Family != 6 || !slices.EqualFunc(v6.Families[0].Bodies, v6.Families[1].Bodies, func(a, b nfqws2HookRule) bool { return a.Chain == b.Chain && slices.Equal(a.Args, b.Args) }) {
		t.Fatalf("IPv6 graph: %+v", v6)
	}
}

func TestNFQWS2FirstStartHookGraphAdmitsOnlyClosedScope(t *testing.T) {
	config := nfqws2HookTestConfig(t, nil)
	for name, tc := range map[string]struct {
		config []byte
		run    string
	}{
		"policy-mark":       {config, strings.Replace(nfqws2RouterRunFixture, `POLICY_MARK=""`, `POLICY_MARK="0x10/0x0fffffff"`, 1)},
		"udp-ports":         {config, strings.Replace(nfqws2RouterRunFixture, "UDP_PORTS=", "UDP_PORTS=443", 1)},
		"tcp-ports":         {config, strings.Replace(nfqws2RouterRunFixture, "TCP_PORTS=443", "TCP_PORTS=80", 1)},
		"queue-drift":       {config, strings.Replace(nfqws2RouterRunFixture, "NFQUEUE_NUM=300", "NFQUEUE_NUM=301", 1)},
		"interface-drift":   {config, strings.Replace(nfqws2RouterRunFixture, `"eth3"`, `"eth4"`, 1)},
		"ipv6-drift":        {config, strings.Replace(nfqws2RouterRunFixture, "IPV6_ENABLED=0", "IPV6_ENABLED=1", 1)},
		"missing-overlay":   {config, ""},
		"extra-overlay-key": {config, nfqws2RouterRunFixture + "NFQWS_ARGS=x\n"},
		"two-interfaces": {nfqws2HookTestConfig(t, func(raw string) string {
			return strings.Replace(raw, `ISP_INTERFACE="eth3"`, `ISP_INTERFACE="eth3 nwg1"`, 1)
		}),
			strings.Replace(nfqws2RouterRunFixture, `"eth3"`, `"eth3 nwg1"`, 1)},
		"stock-unmanaged": {[]byte(strings.SplitN(string(config), engineconfig.ManagedListBegin, 2)[0]), nfqws2RouterRunFixture},
	} {
		t.Run(name, func(t *testing.T) {
			if graph, err := nfqws2FirstStartHookGraph(tc.config, []byte(tc.run), nfqws2HookTestOwner); !errors.Is(err, errNFQWS2HookGraph) || len(graph.Families) != 0 {
				t.Fatalf("outside the closed scope rendered: %+v %v", graph, err)
			}
		})
	}
	if _, err := nfqws2FirstStartHookGraph(config, []byte(nfqws2RouterRunFixture), "222222222222222222222222"); err == nil {
		t.Fatal("foreign owner rendered")
	}
}

func TestNFQWS2StockScopeRendersStockPreroutingPolicyRules(t *testing.T) {
	const main = "ISP_INTERFACE=eth3\nNFQUEUE_NUM=301\nTCP_PORTS=80\nUDP_PORTS=443\nPOLICY_NAME=nfqws\nPOLICY_EXCLUDE=0\n"
	for _, tc := range []struct {
		exclude string
		want    []string
	}{
		{"0", []string{"-i eth3 -m connmark --mark 0x20000000/0x20000000 -j RETURN"}},
		{"1", []string{"-i eth3 -m mark --mark 0x123/0xfffffff -j RETURN"}},
	} {
		config := strings.Replace(main, "POLICY_EXCLUDE=0", "POLICY_EXCLUDE="+tc.exclude, 1)
		scope, ok := nfqws2StockHookScopeOf([]byte(config), []byte(config+"POLICY_MARK=0x123/0x0fffffff\n"))
		if !ok {
			t.Fatal("stock policy scope refused")
		}
		target := " -j NFQUEUE --queue-num 301 --queue-bypass"
		unprocessed := " -m mark ! --mark 0x40000000/0x40000000"
		want := append(tc.want, "-i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN",
			"-i eth3 -p udp"+unprocessed+" -m multiport --sports 443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir reply"+target,
			"-i eth3 -p tcp"+unprocessed+" -m multiport --sports 80 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir reply"+target,
			"-i eth3 -p tcp"+unprocessed+" -m multiport --sports 80 -m tcp --tcp-flags SYN,ACK SYN,ACK"+target,
			"-i eth3 -p tcp"+unprocessed+" -m multiport --sports 80 -m tcp --tcp-flags FIN FIN"+target,
			"-i eth3 -p tcp"+unprocessed+" -m multiport --sports 80 -m tcp --tcp-flags RST RST"+target)
		if got := scope.preRules(); !slices.Equal(got, want) {
			t.Fatalf("exclude=%s:\n%s", tc.exclude, strings.Join(got, "\n"))
		}
	}
}

func TestNFQWS2HealthRuleCanonicalizesPreroutingOptions(t *testing.T) {
	canonical := func(rule string) string {
		t.Helper()
		got, ok := nfqws2HealthRule(rule)
		if !ok {
			t.Fatalf("refused %q", rule)
		}
		return got
	}
	// The extracted -S post rendering keeps the previous expert canonical form.
	if canonical("-o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass") !=
		canonical("-o eth3 -m mark ! --mark 0x40000000/0x40000000 -p tcp -m multiport --dports 443 --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass") {
		t.Fatal("post rendering changed its canonical form")
	}
	pre := "-i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 300 --queue-bypass"
	if canonical(pre) != canonical(strings.ReplaceAll(pre, "SYN,ACK SYN,ACK", "ack,syn ACK,SYN")) {
		t.Fatal("flag set order or case changed the canonical rule")
	}
	for name, other := range map[string]string{
		"sports-vs-dports": strings.Replace(pre, "--sports", "--dports", 1),
		"in-vs-out":        strings.Replace(pre, "-i eth3", "-o eth3", 1),
		"syn-only":         strings.Replace(pre, "SYN,ACK SYN,ACK", "SYN SYN", 1),
		"mask-vs-compare":  strings.Replace(pre, "SYN,ACK SYN,ACK", "SYN,ACK SYN", 1),
		"other-interface":  strings.Replace(pre, "-i eth3", "-i eth4", 1),
		"other-sport":      strings.Replace(pre, "--sports 443", "--sports 80", 1),
	} {
		if got, ok := nfqws2HealthRule(other); ok && got == canonical(pre) {
			t.Fatal("distinct rule shared the canonical form:", name)
		}
	}
	if canonical("-i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN") == canonical("-i eth3 -m mark ! --mark 0x40000000/0x40000000 -j RETURN") {
		t.Fatal("mark polarity lost")
	}
	// Every earlier refusal holds; new options add no unknown predicate.
	for name, rule := range map[string]string{
		"source-address":     "-s 192.0.2.1 " + pre,
		"duplicate-in":       "-i eth3 " + pre,
		"negated-in":         "! -i eth3 -p tcp -j RETURN",
		"mac-module":         "-i eth3 -m mac --mac-source 02:00:00:00:00:01 -j RETURN",
		"unknown-flag":       strings.Replace(pre, "SYN,ACK SYN,ACK", "SYN,BOGUS SYN", 1),
		"duplicate-flag":     strings.Replace(pre, "SYN,ACK SYN,ACK", "SYN,SYN SYN", 1),
		"empty-flag":         strings.Replace(pre, "SYN,ACK SYN,ACK", "SYN, SYN", 1),
		"missing-flag-set":   "-i eth3 -p tcp -m tcp --tcp-flags SYN",
		"empty-sports":       "-i eth3 -p tcp -m multiport --sports -j RETURN",
		"zero-sport":         strings.Replace(pre, "--sports 443", "--sports 0", 1),
		"duplicate-sports":   strings.Replace(pre, "--sports 443", "--sports 443 --sport 443", 1),
		"duplicate-module":   strings.Replace(pre, "-m tcp", "-m tcp -m tcp", 1),
		"queue-zero":         strings.Replace(pre, "--queue-num 300", "--queue-num 0", 1),
		"trailing-option":    pre + " -i",
		"unknown-option":     pre + " --queue-balance 1:2",
		"negated-sports":     strings.Replace(pre, "--sports", "! --sports", 1),
		"interface-no-value": "-i",
	} {
		if _, ok := nfqws2HealthRule(rule); ok {
			t.Fatal("canonicalizer admitted", name)
		}
	}
}

func nfqws2HookTestImage(t *testing.T, save string) nfqws2MangleImage {
	t.Helper()
	image, ok := nfqws2SaveMangleImage([]byte(save))
	if !ok {
		t.Fatal("fixture image refused")
	}
	return image
}

func TestNFQWS2PreroutingVerifierAcceptsRouterShapeAndRefusesBypass(t *testing.T) {
	router := nfqws2RouterMangleFixture
	before := func(rule string) string {
		return strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", rule+"\n-A PREROUTING -j nfqws_pre\n", 1)
	}
	declare := func(save, chain string, rules ...string) string {
		save = strings.Replace(save, ":nfqws_post - [0:0]\n", ":"+chain+" - [0:0]\n:nfqws_post - [0:0]\n", 1)
		for _, rule := range rules {
			save = strings.Replace(save, "COMMIT\n", "-A "+chain+" "+rule+"\nCOMMIT\n", 1)
		}
		return save
	}
	for _, tc := range []struct {
		name, save string
		want       error
	}{
		{"router-shape", router, nil},
		{"terminal-after-hook", strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j nfqws_pre\n-A PREROUTING -j DROP\n", 1), nil},
		{"mark-and-connmark", before("-A PREROUTING -j MARK --set-xmark 0x4/0xff\n-A PREROUTING -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff"), nil},
		{"counter-only", before("-A PREROUTING -p tcp"), nil},
		{"nested-nonterminal", declare(before("-A PREROUTING -i eth3 -j vendor_a"), "vendor_a", "-j _NDM_HOTSPOT_PREROUTING_MANGL", "-p udp -j _NDM_PREROUTING_MC", "-j RETURN"), nil},
		// The firmware DNS-route chain shape: set matches with MARK, CONNMARK
		// and RETURN only (sanitized set name and mark).
		{"dns-route-marks", strings.Replace(router, "COMMIT\n", "-A _NDM_DNSRT_PREROUTING_MANGLE -m set --match-set _NDM_DNSRT_TEST dst --return-nomatch ! --update-counters -j MARK --set-xmark 0xffffd00/0xffffffff\n"+
			"-A _NDM_DNSRT_PREROUTING_MANGLE -m set --match-set _NDM_DNSRT_TEST dst -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff\n"+
			"-A _NDM_DNSRT_PREROUTING_MANGLE -m set --match-set _NDM_DNSRT_TEST dst --return-nomatch ! --update-counters ! --update-subcounters -j RETURN\nCOMMIT\n", 1), nil},
		{"target-options-on-chain-jump", declare(before("-A PREROUTING -j vendor_a --set-mark 0x1"), "vendor_a"), nfqws2HookPreUnknown},
		{"target-shaped-chain", declare(before("-A PREROUTING -j TPROXY"), "TPROXY"), nfqws2HookPreUnknown},
		{"accept-before", before("-A PREROUTING -j ACCEPT"), nfqws2HookPreTerminal},
		{"drop-before", before("-A PREROUTING -p udp -j DROP"), nfqws2HookPreTerminal},
		{"nfqueue-before", before("-A PREROUTING -j NFQUEUE --queue-num 301"), nfqws2HookPreTerminal},
		{"conditional-terminal-in-chain", strings.Replace(router, "-A _NDM_PREROUTING_MC -p udp -j TTL --ttl-inc 1\n", "-A _NDM_PREROUTING_MC -p udp -j TTL --ttl-inc 1\n-A _NDM_PREROUTING_MC -p igmp -j ACCEPT\n", 1), nfqws2HookPreTerminal},
		{"nested-undeclared-chain", declare(before("-A PREROUTING -j vendor_a"), "vendor_a", "-j vendor_b"), nfqws2HookPreUnknown},
		{"terminal-in-nested-chain", declare(declare(before("-A PREROUTING -j vendor_a"), "vendor_a", "-m mark --mark 0x1 -j vendor_b"), "vendor_b", "-j RETURN", "-p tcp -j DROP"), nfqws2HookPreTerminal},
		{"builtin-jump", before("-A PREROUTING -j INPUT"), nfqws2HookPreUnknown},
		{"unknown-target", before("-A PREROUTING -j NDMMARK --set-xndmmark 0x1/0x0"), nfqws2HookPreUnknown},
		{"undeclared-chain", before("-A PREROUTING -j vendor_missing"), nfqws2HookPreUnknown},
		{"return-in-prerouting", before("-A PREROUTING -m mark --mark 0x1 -j RETURN"), nfqws2HookPreReturn},
		{"goto-before", before("-A PREROUTING -g _NDM_IPSEC_PREROUTING"), nfqws2HookPreGoto},
		{"comment-spells-jump", before(`-A PREROUTING -m comment --comment "-j" -j _NDM_IPSEC_PREROUTING`), nfqws2HookPreUnknown},
		{"duplicate-jump", strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j nfqws_pre\n-A PREROUTING -j nfqws_pre\n", 1), nfqws2HookPreJumpDuplicate},
		{"conditional-owned-jump", strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -i eth3 -j nfqws_pre\n", 1), nfqws2HookPreForeign},
		{"owned-jump-elsewhere", strings.Replace(router, "-A OUTPUT -j _NDM_OUTPUT_DELAY\n", "-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A OUTPUT -j nfqws_pre\n", 1), nfqws2HookPreForeign},
		{"owned-post-before", before("-A PREROUTING -j nfqws_post"), nfqws2HookPreForeign},
		{"missing-jump", strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", "", 1), nfqws2HookPreJumpMissing},
		{"missing-chain", strings.Replace(router, ":nfqws_pre - [0:0]\n", "", 1), nil}, // Refused by the image parser below.
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, ok := nfqws2SaveMangleImage([]byte(tc.save))
			if tc.name == "missing-chain" {
				if ok {
					t.Fatal("undeclared owned chain body parsed")
				}
				return
			}
			if !ok {
				t.Fatal("fixture refused by the parser")
			}
			if err := nfqws2PreroutingReaches(image, false); !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	// A declaration without rules and without its jump is still not the hook.
	jumpOnly := strings.Replace(strings.Replace(router, ":nfqws_pre - [0:0]\n", "", 1), "-A nfqws_pre ", "-A nfqws_post ", -1)
	if err := nfqws2PreroutingReaches(nfqws2HookTestImage(t, jumpOnly), false); !errors.Is(err, nfqws2HookPreChainInvalid) {
		t.Fatal("jump into an undeclared owned chain accepted", err)
	}
	cycle := declare(declare(before("-A PREROUTING -j vendor_a"), "vendor_a", "-j vendor_b"), "vendor_b", "-j vendor_a")
	if err := nfqws2PreroutingReaches(nfqws2HookTestImage(t, cycle), false); !errors.Is(err, nfqws2HookPreCycle) {
		t.Fatal("cycle accepted", err)
	}
	// The LOSS form: no owned object yet, and the appended hook is reachable.
	loss := strings.Replace(router, "-A PREROUTING -j nfqws_pre\n", "", 1)
	loss = strings.Replace(loss, ":nfqws_pre - [0:0]\n", "", 1)
	var kept []string
	for _, line := range strings.Split(loss, "\n") {
		if !strings.HasPrefix(line, "-A nfqws_pre ") {
			kept = append(kept, line)
		}
	}
	if err := nfqws2PreroutingReaches(nfqws2HookTestImage(t, strings.Join(kept, "\n")), true); err != nil {
		t.Fatal("restorable PREROUTING refused", err)
	}
	if err := nfqws2PreroutingReaches(nfqws2HookTestImage(t, router), true); !errors.Is(err, nfqws2HookPreForeign) {
		t.Fatal("appended verification accepted an existing owned hook", err)
	}
	for _, chain := range []string{"MARK", "RETURN", "PREROUTING_X"} {
		save := declare(router, chain)
		if _, ok := nfqws2SaveMangleImage([]byte(save)); ok != (chain == "PREROUTING_X") {
			t.Fatal("target-named user chain resolved", chain)
		}
	}
}

func TestNFQWS2ClosedPreRuleBindsExactOwnedBody(t *testing.T) {
	config := nfqws2HookTestConfig(t, nil)
	run := []byte(nfqws2RouterRunFixture)
	image := nfqws2RouterNATFixture + nfqws2RouterMangleFixture
	if !nfqws2ClosedReachablePreRule([]byte(image), config, run, nfqws2HookTestOwner) {
		t.Fatal("router shape refused")
	}
	for name, save := range map[string]string{
		"missing-syn-ack":    strings.Replace(image, "-A nfqws_pre -i eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --sports 443 -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 300 --queue-bypass\n", "", 1),
		"wrong-interface":    strings.ReplaceAll(image, "-i eth3", "-i eth4"),
		"wrong-direction":    strings.ReplaceAll(image, "--connbytes-dir reply", "--connbytes-dir original"),
		"wrong-queue":        strings.ReplaceAll(image, "--sports 443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 300", "--sports 443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 301"),
		"dports-not-sports":  strings.ReplaceAll(image, "--sports", "--dports"),
		"missing-processed":  strings.Replace(image, "-A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN\n", "", 1),
		"extra-return-first": strings.Replace(image, "-A nfqws_pre -i eth3 -m mark", "-A nfqws_pre -j RETURN\n-A nfqws_pre -i eth3 -m mark", 1),
		"missing-jump":       strings.Replace(image, "-A PREROUTING -j nfqws_pre\n", "", 1),
		"terminal-before":    strings.Replace(image, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j ACCEPT\n-A PREROUTING -j nfqws_pre\n", 1),
		"other-table":        strings.Replace(image, "*mangle", "*raw", 1),
	} {
		if nfqws2ClosedReachablePreRule([]byte(save), config, run, nfqws2HookTestOwner) {
			t.Fatal("pre proof accepted", name)
		}
	}
	if nfqws2ClosedReachablePreRule([]byte(image), config, []byte(strings.Replace(nfqws2RouterRunFixture, `POLICY_MARK=""`, `POLICY_MARK="0x10/0x0fffffff"`, 1)), nfqws2HookTestOwner) {
		t.Fatal("pre proof expanded beyond the closed scope")
	}
}

// Converts iptables-save text into the -S inventory rows of one family: a
// built-in policy becomes -P, a user chain -N, and each rule keeps tokens.
func nfqws2HookTestRows(t *testing.T, family int, save string) []BackendInventoryRow {
	t.Helper()
	var rows []BackendInventoryRow
	table := ""
	for _, line := range strings.Split(save, "\n") {
		switch {
		case line == "" || line == "COMMIT" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "*"):
			table = line[1:]
		case strings.HasPrefix(line, ":"):
			f := strings.Fields(line[1:])
			if f[1] == "-" {
				rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: []string{"-N", f[0]}})
			} else {
				rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: []string{"-P", f[0], f[1]}})
			}
		default:
			tokens, err := backendXTablesTokens(line)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, BackendInventoryRow{Family: family, Table: table, Tokens: tokens})
		}
	}
	return rows
}

// Removes every owned mangle line: the NDM table rewrite signature.
func nfqws2HookTestLoss(save string) string {
	var kept []string
	for _, line := range strings.Split(save, "\n") {
		if !strings.Contains(line, "nfqws_post") && !strings.Contains(line, "nfqws_pre") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// The IPv6 firmware shape with the owned graph rendered into it.
func nfqws2HookTestIPv6Full() string {
	save := strings.Replace(nfqws2RouterIPv6Fixture, ":_NDM_OUTPUT_DELAY - [0:0]\n", ":_NDM_OUTPUT_DELAY - [0:0]\n:nfqws_post - [0:0]\n:nfqws_pre - [0:0]\n", 1)
	save = strings.Replace(save, "-A OUTPUT -j _NDM_OUTPUT_DELAY\n", "-A PREROUTING -j nfqws_pre\n-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A POSTROUTING -j nfqws_post\n", 1)
	return strings.Replace(save, "COMMIT\n", strings.Join(nfqws2HookTestOwnedLines(nfqws2RouterMangleFixture), "\n")+"\nCOMMIT\n", 1)
}

func TestNFQWS2HookClassifierMatrix(t *testing.T) {
	identity, _ := networkPolicyIdentityFixture()
	v4 := nfqws2RouterNATFixture + nfqws2RouterMangleFixture + nfqws2RouterFilterFixture
	image := func(ipv4, ipv6 string) BackendInventorySnapshot {
		rows := append(nfqws2HookTestRows(t, 4, ipv4), nfqws2HookTestRows(t, 6, ipv6)...)
		return networkPolicyInventoryTestImage(identity.value, rows)
	}
	mangle := func(edit func(string) string) string {
		return nfqws2RouterNATFixture + edit(nfqws2RouterMangleFixture) + nfqws2RouterFilterFixture
	}
	reorder := strings.Replace(nfqws2RouterMangleFixture, "-A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN\n", "", 1)
	reorder = strings.Replace(reorder, "COMMIT\n", "-A nfqws_pre -i eth3 -m mark --mark 0x40000000/0x40000000 -j RETURN\nCOMMIT\n", 1)
	type matrixCase struct {
		name     string
		enabled  bool
		ipv4     string
		ipv6     string
		class    nfqws2HookClass
		reason   error
		restore  []int
		mutation func(*BackendInventorySnapshot)
	}
	cases := []matrixCase{
		{name: "full", ipv4: v4, ipv6: nfqws2RouterIPv6Fixture, class: nfqws2HookFull},
		{name: "loss-with-nat-intact", ipv4: nfqws2HookTestLoss(v4), ipv6: nfqws2RouterIPv6Fixture, class: nfqws2HookLoss, restore: []int{4}},
		{name: "partial-jumps-missing", ipv4: mangle(func(s string) string {
			return strings.Replace(strings.Replace(s, "-A PREROUTING -j nfqws_pre\n", "", 1), "-A POSTROUTING -j nfqws_post\n", "", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookPartial},
		{name: "partial-pre-only-lost", ipv4: mangle(func(s string) string {
			var kept []string
			for _, line := range strings.Split(s, "\n") {
				if !strings.Contains(line, "nfqws_pre") {
					kept = append(kept, line)
				}
			}
			return strings.Join(kept, "\n")
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookPartial},
		{name: "duplicate-post-jump", ipv4: mangle(func(s string) string {
			return strings.Replace(s, "-A POSTROUTING -j nfqws_post\n", "-A POSTROUTING -j nfqws_post\n-A POSTROUTING -j nfqws_post\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookJumpDuplicate},
		{name: "duplicate-pre-jump", ipv4: mangle(func(s string) string {
			return strings.Replace(s, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j nfqws_pre\n-A PREROUTING -j nfqws_pre\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookJumpDuplicate},
		{name: "foreign-same-named-chain", ipv4: mangle(func(s string) string {
			var kept []string
			for _, line := range strings.Split(s, "\n") {
				if !strings.HasPrefix(line, "-A nfqws_post ") {
					kept = append(kept, line)
				}
			}
			return strings.Replace(strings.Join(kept, "\n"), "COMMIT\n", "-A nfqws_post -o eth3 -j ACCEPT\nCOMMIT\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookBodyDiffers},
		{name: "other-queue-number", ipv4: mangle(func(s string) string { return strings.ReplaceAll(s, "--queue-num 300", "--queue-num 301") }), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookBodyDiffers},
		{name: "token-order-differs", ipv4: mangle(func(s string) string {
			return strings.Replace(s, "-A nfqws_post -o eth3 -p tcp -m mark", "-A nfqws_post -p tcp -o eth3 -m mark", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookBodyDiffers},
		{name: "body-order-differs", ipv4: nfqws2RouterNATFixture + reorder + nfqws2RouterFilterFixture, ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookBodyDiffers},
		{name: "foreign-owned-reference", ipv4: mangle(func(s string) string {
			return strings.Replace(s, "-A OUTPUT -j _NDM_OUTPUT_DELAY\n", "-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A OUTPUT -j nfqws_post\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookForeignReference},
		{name: "managed-chain-present", ipv4: mangle(func(s string) string {
			return strings.Replace(s, ":nfqws_post - [0:0]\n", ":RZQ_0123456789 - [0:0]\n:nfqws_post - [0:0]\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookForeignReference},
		{name: "managed-chain-with-loss", ipv4: nfqws2HookTestLoss(mangle(func(s string) string {
			return strings.Replace(s, ":nfqws_post - [0:0]\n", ":RZQ_0123456789 - [0:0]\n:nfqws_post - [0:0]\n", 1)
		})), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookForeignReference},
		{name: "nat-missing", ipv4: strings.Replace(strings.Replace(v4, ":nfqws_nat - [0:0]\n", "", 1), "-A POSTROUTING -j nfqws_nat\n", "", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookNATMissing},
		{name: "nat-jump-missing-with-loss", ipv4: nfqws2HookTestLoss(strings.Replace(v4, "-A POSTROUTING -j nfqws_nat\n", "", 1)), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookNATMissing},
		{name: "nat-not-empty", ipv4: strings.Replace(v4, "-A POSTROUTING -j nfqws_nat\n", "-A POSTROUTING -j nfqws_nat\n-A nfqws_nat -o eth3 -p udp -m mark --mark 0x40000000/0x40000000 -j MASQUERADE\n", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookNATNonEmpty},
		{name: "nat-duplicate-jump", ipv4: strings.Replace(v4, "-A POSTROUTING -j nfqws_nat\n", "-A POSTROUTING -j nfqws_nat\n-A POSTROUTING -j nfqws_nat\n", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookNATForeign},
		{name: "nat-conditional-jump", ipv4: strings.Replace(v4, "-A POSTROUTING -j nfqws_nat\n", "-A POSTROUTING -o eth3 -j nfqws_nat\n", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookNATForeign},
		{name: "owned-in-filter", ipv4: strings.Replace(v4, "-A FORWARD -j _NDM_ACL\n", "-A FORWARD -j _NDM_ACL\n-A FORWARD -m comment --comment nfqws2 -j ACCEPT\n", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookOutsideMangle},
		{name: "owned-in-raw", ipv4: v4 + "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:nfqws_raw - [0:0]\nCOMMIT\n", ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookOutsideMangle},
		{name: "loss-with-owned-in-raw", ipv4: nfqws2HookTestLoss(v4) + "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:nfqws_raw - [0:0]\nCOMMIT\n", ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookOutsideMangle},
		{name: "ipv6-tokens-while-disabled", ipv4: v4, ipv6: nfqws2HookTestIPv6Full(), reason: nfqws2HookIPv6Disabled},
		{name: "ipv6-nat-token-while-disabled", ipv4: nfqws2HookTestLoss(v4), ipv6: nfqws2RouterIPv6Fixture + "*nat\n:POSTROUTING ACCEPT [0:0]\n:nfqws_nat - [0:0]\nCOMMIT\n", reason: nfqws2HookIPv6Disabled},
		{name: "ipv6-full-enabled", enabled: true, ipv4: v4, ipv6: nfqws2HookTestIPv6Full(), class: nfqws2HookFull},
		{name: "ipv6-loss-enabled", enabled: true, ipv4: v4, ipv6: nfqws2RouterIPv6Fixture, class: nfqws2HookLoss, restore: []int{6}},
		{name: "both-loss-enabled", enabled: true, ipv4: nfqws2HookTestLoss(v4), ipv6: nfqws2RouterIPv6Fixture, class: nfqws2HookLoss, restore: []int{4, 6}},
		{name: "ipv6-partial-blocks-ipv4-loss", enabled: true, ipv4: nfqws2HookTestLoss(v4), ipv6: strings.Replace(nfqws2HookTestIPv6Full(), "-A PREROUTING -j nfqws_pre\n", "", 1), reason: nfqws2HookPartial},
		{name: "ipv6-nat-owned-enabled", enabled: true, ipv4: v4, ipv6: nfqws2HookTestIPv6Full() + "*nat\n:POSTROUTING ACCEPT [0:0]\n:nfqws_nat - [0:0]\nCOMMIT\n", reason: nfqws2HookOutsideMangle},
		{name: "foreign-queue-reference", ipv4: strings.Replace(v4, "-A FORWARD -j _NDM_ACL\n", "-A FORWARD -j _NDM_ACL\n-A FORWARD -p tcp -j NFQUEUE --queue-num 300\n", 1), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookForeignQueue},
		{name: "foreign-queue-balance", ipv4: nfqws2HookTestLoss(strings.Replace(v4, "-A OUTPUT -j _NDM_OUTPUT_DELAY\n", "-A OUTPUT -j _NDM_OUTPUT_DELAY\n-A OUTPUT -j NFQUEUE --queue-balance 299:301\n", 1)), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookForeignQueue},
		{name: "ipv6-foreign-queue", ipv4: v4, ipv6: strings.Replace(nfqws2RouterIPv6Fixture, "--queue-num 64512", "--queue-num 300", 1), reason: nfqws2HookForeignQueue},
		{name: "loss-terminal-before-prerouting-hook", ipv4: nfqws2HookTestLoss(mangle(func(s string) string {
			return strings.Replace(s, "-A PREROUTING -j _NDM_IPSEC_PREROUTING\n", "-A PREROUTING -j _NDM_IPSEC_PREROUTING\n-A PREROUTING -p tcp -j ACCEPT\n", 1)
		})), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookPreTerminal},
		{name: "loss-unreachable-postrouting", ipv4: nfqws2HookTestLoss(mangle(func(s string) string {
			return strings.Replace(s, "-A POSTROUTING -j _NDM_POSTROUTING_TTL\n", "-A POSTROUTING -j _NDM_POSTROUTING_TTL\n-A POSTROUTING -o eth3 -j ACCEPT\n", 1)
		})), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookPostUnreachable},
		{name: "full-shadowed-prerouting", ipv4: mangle(func(s string) string {
			return strings.Replace(s, "-A PREROUTING -j nfqws_pre\n", "-A PREROUTING -j DROP\n-A PREROUTING -j nfqws_pre\n", 1)
		}), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookPreTerminal},
		{name: "incomplete-inventory", ipv4: v4, ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookInventoryIncomplete, mutation: func(s *BackendInventorySnapshot) {
			s.Coverage.RegisteredTablesComplete = false
		}},
		{name: "nft-tables-present", ipv4: nfqws2HookTestLoss(v4), ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookInventoryIncomplete, mutation: func(s *BackendInventorySnapshot) {
			s.NFTState, s.NFTTables = BackendNFTPresent, []BackendNFTTable{{Family: 2, Name: "foreign"}}
		}},
		{name: "malformed-row", ipv4: v4, ipv6: nfqws2RouterIPv6Fixture, reason: nfqws2HookInventoryShape, mutation: func(s *BackendInventorySnapshot) {
			s.Rows = append(s.Rows, BackendInventoryRow{Family: 4, Table: "mangle", Tokens: []string{"-X", "nfqws_post"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := nfqws2HookTestGraph(t, tc.enabled)
			snapshot := image(tc.ipv4, tc.ipv6)
			if tc.mutation != nil {
				tc.mutation(&snapshot)
			}
			got := nfqws2ClassifyHookGraph(graph, snapshot)
			want := tc.class
			if tc.reason != nil {
				want = nfqws2HookOther
			}
			if got.Class != want || !errors.Is(got.Reason, tc.reason) || (got.Reason == nil) != (tc.reason == nil) || !slices.Equal(got.restore(), tc.restore) {
				t.Fatalf("class=%d reason=%v restore=%v families=%+v", got.Class, got.Reason, got.restore(), got.Families)
			}
		})
	}
	// The detached result names its family/table and keeps no row content.
	got := nfqws2ClassifyHookGraph(nfqws2HookTestGraph(t, false), image(strings.Replace(v4, "-A POSTROUTING -j nfqws_nat\n", "", 1), nfqws2RouterIPv6Fixture))
	if got.Reason == nil || got.Reason.Error() != "ipv4 nat: NFQWS2 owned hook graph refused: nat-hook-missing" {
		t.Fatal("reason", got.Reason)
	}
	if got := nfqws2ClassifyHookGraph(nfqws2HookGraph{}, image(v4, nfqws2RouterIPv6Fixture)); got.Class != nfqws2HookOther || !errors.Is(got.Reason, errNFQWS2HookGraph) {
		t.Fatal("empty graph classified", got)
	}
}
