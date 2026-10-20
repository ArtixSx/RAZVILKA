package routeprobe

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const stockProbeFixture = `*mangle
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:_NDM_OUTPUT_DELAY - [0:0]
:_NDM_IPSEC_OUTPUT_MANGLE - [0:0]
:_NDM_IPSEC_POSTR_MANGLE - [0:0]
:_NDM_POSTROUTING_TTL - [0:0]
:nfqws_post - [0:0]
[0:0] -A OUTPUT -j _NDM_OUTPUT_DELAY
[0:0] -A OUTPUT -j _NDM_IPSEC_OUTPUT_MANGLE
[0:0] -A _NDM_OUTPUT_DELAY ! -s 127.0.0.1/32 ! -d 127.0.0.1/32 -m ndmmark --ndmmark 0x0/0x80 -j NFQUEUE --queue-num 64511
[0:0] -A POSTROUTING -j _NDM_IPSEC_POSTR_MANGLE
[0:0] -A POSTROUTING -j _NDM_POSTROUTING_TTL
[0:0] -A POSTROUTING -j nfqws_post
[0:0] -A nfqws_post -o eth3 -p udp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300 --queue-bypass
[7:420] -A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443,8443 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 300 --queue-bypass
[0:0] -A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443,8443 -m tcp --tcp-flags FIN FIN -j NFQUEUE --queue-num 300 --queue-bypass
[0:0] -A nfqws_post -o eth3 -p tcp -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 80,443,8443 -m tcp --tcp-flags RST RST -j NFQUEUE --queue-num 300 --queue-bypass
COMMIT
`

var stockProbeAddress = netip.MustParseAddr("162.159.136.232")

func stockProbeRead(raw, iface string) (stockProbePath, error) {
	return inspectStockProbePath(raw, "162.159.136.232 dev "+iface+" src 100.64.181.129\n cache", stockProbeAddress, 300, "RZRP12345678", 41234)
}

func TestStockNFQProbeUsesOnlyPassiveEligibleSocketOnStockInterface(t *testing.T) {
	before, err := stockProbeRead(stockProbeFixture, "eth3")
	if err != nil || !before.passive || before.packets != 7 {
		t.Fatalf("official stock path not recognized: %+v %v", before, err)
	}
	hook, args := scopedNFQProbeJump(stockProbeAddress, 41234, "RZRP12345678", before)
	joined := strings.Join(args, " ")
	if hook != "POSTROUTING" || !strings.Contains(joined, "--sport 41234") || !strings.Contains(joined, "! --mark 0x40000000/0x40000000") || !strings.Contains(joined, "--connbytes-dir original") || strings.Contains(joined, "NFQUEUE") || strings.Contains(joined, "MARK") || strings.Contains(joined, "ACCEPT") {
		t.Fatalf("passive observation changed the stock path: %s %s", hook, joined)
	}
	after := strings.Replace(stockProbeFixture, ":POSTROUTING ACCEPT [0:0]", ":POSTROUTING ACCEPT [800:48000]\n:RZRP12345678 - [0:0]", 1)
	after = strings.Replace(after, "[7:420]", "[9:600]", 1)
	after = strings.Replace(after, "COMMIT", "[2:120] -A RZRP12345678 -j RETURN\n[2:120] -A POSTROUTING -d 162.159.136.232/32 -o eth3 -p tcp -m tcp --sport 41234 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -m connbytes --connbytes 1:15 --connbytes-mode packets --connbytes-dir original -j RZRP12345678\nCOMMIT", 1)
	observed, err := stockProbeRead(after, "eth3")
	if err != nil || !stockProbeSamePath(before, observed) || observed.packets != 9 {
		t.Fatalf("counter-only owned readback invalidated an unchanged graph: %+v %v", observed, err)
	}
	if !stockProbeSocketConfirmed(before, observed, 2) || stockProbeSocketConfirmed(before, observed, 0) || stockProbeSocketConfirmed(before, before, 2) {
		t.Fatal("aggregate stock counters or socket counters alone granted route evidence")
	}
	if got := parseScopedReturnPackets(" pkts bytes target prot opt in out source destination\n 2 120 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0"); got != 2 {
		t.Fatalf("eligible socket packet count = %d", got)
	}
	// The original stock interface stays foreign. A different proven interface
	// needs the isolated queue, because stock POSTROUTING cannot select it.
	other, err := stockProbeRead(stockProbeFixture, "nwg0")
	if err != nil || other.passive || stockProbeSamePath(before, other) {
		t.Fatalf("foreign interface incorrectly attributed to stock queue: %+v %v", other, err)
	}
	hook, args = scopedNFQProbeJump(stockProbeAddress, 41234, "RZRP12345678", other)
	if hook != "OUTPUT" || strings.Contains(strings.Join(args, " "), "--mark") {
		t.Fatal("different-interface isolation borrowed a foreign mark")
	}
}

func TestStockNFQProbeRefusesUnknownOrAmbiguousPacketGraphs(t *testing.T) {
	for name, raw := range map[string]string{
		"early accept":                  strings.Replace(stockProbeFixture, "[0:0] -A POSTROUTING", "[1:60] -A POSTROUTING -j ACCEPT\n[0:0] -A POSTROUTING", 1),
		"early return":                  strings.Replace(stockProbeFixture, "[0:0] -A POSTROUTING", "[1:60] -A POSTROUTING -j RETURN\n[0:0] -A POSTROUTING", 1),
		"vendor effect":                 strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A _NDM_POSTROUTING_TTL -j TTL --ttl-set 64\nCOMMIT", 1),
		"unknown stock rule":            strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A nfqws_post -p tcp -j RETURN\nCOMMIT", 1),
		"changed queue":                 strings.ReplaceAll(stockProbeFixture, "--queue-num 300", "--queue-num 301"),
		"changed mark":                  strings.ReplaceAll(stockProbeFixture, "0x40000000/0x40000000", "0x20000000/0x20000000"),
		"nonfirst connbytes":            strings.ReplaceAll(stockProbeFixture, "--connbytes 1:15", "--connbytes 2:15"),
		"duplicate hook":                strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A POSTROUTING -j nfqws_post\nCOMMIT", 1),
		"output extra queue":            strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A OUTPUT -j NFQUEUE --queue-num 300\nCOMMIT", 1),
		"output mark":                   strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A OUTPUT -j MARK --set-xmark 0x40000000/0x40000000\nCOMMIT", 1),
		"foreign change in owned chain": strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A RZRP12345678 -j NFQUEUE --queue-num 300\nCOMMIT", 1),
		"wrong owned tuple":             strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A OUTPUT -p tcp -d 162.159.136.232/32 --dport 443 --sport 41235 -j RZRP12345678\nCOMMIT", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stockProbeRead(raw, "eth3"); !errors.Is(err, errStockProbePath) {
				t.Fatalf("unsafe stock graph granted evidence: %v", err)
			}
		})
	}
}

func TestStockNFQProbeReadbackFencesChangesWithoutTreatingTrafficAsStructure(t *testing.T) {
	before, err := stockProbeRead(stockProbeFixture, "eth3")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unrelated foreign rule": strings.Replace(stockProbeFixture, "COMMIT", "[0:0] -A PREROUTING -p udp -j ACCEPT\nCOMMIT", 1),
		"foreign interface":      strings.ReplaceAll(stockProbeFixture, "-o eth3", "-o eth4"),
	} {
		t.Run(name, func(t *testing.T) {
			after, err := stockProbeRead(raw, "eth3")
			if err == nil && stockProbeSamePath(before, after) {
				t.Fatal("changed graph retained route authority")
			}
		})
	}
	after, err := stockProbeRead(strings.ReplaceAll(stockProbeFixture, "[0:0]", "[99:5900]"), "eth3")
	if err != nil || !stockProbeSamePath(before, after) {
		t.Fatal("unrelated traffic counter falsely changed the graph")
	}
}
