package routeprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestStockProbePinsSourceWithoutDiscardingRouteTable(t *testing.T) {
	address := netip.MustParseAddr("162.159.136.232")
	initial, err := parseStockProbeRoute("162.159.136.232 via 100.64.128.1 dev eth3 table 4096 src 100.64.181.129\n cache", address)
	if err != nil {
		t.Fatal(err)
	}
	boundText := "162.159.136.232 from 100.64.181.129 via 100.64.128.1 dev eth3 table 16386\n cache"
	bound, err := parseStockProbeRoute(boundText, address)
	if err != nil || !sameStockProbeForwarding(initial, bound) {
		t.Fatal("equivalent initial/source-bound forwarding refused", err)
	}
	before, err := inspectStockProbePath(stockProbeFixture, boundText, address, 300, "RZRP12345678", 41234)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"gateway", "via 100.64.128.1", "via 100.64.128.2"},
		{"device", "dev eth3", "dev eth4"},
		{"source", "from 100.64.181.129", "from 100.64.181.130"},
		{"table", "table 16386", "table 16387"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after, err := inspectStockProbePath(stockProbeFixture, strings.Replace(boundText, tc.from, tc.to, 1), address, 300, "RZRP12345678", 41234)
			if err == nil && stockProbeSamePath(before, after) {
				t.Fatal("changed bound route accepted")
			}
			changed, err := parseStockProbeRoute(strings.Replace(boundText, tc.from, tc.to, 1), address)
			if tc.name != "table" && err == nil && sameStockProbeForwarding(initial, changed) {
				t.Fatal("initial/source-bound forwarding mismatch accepted")
			}
		})
	}
	for _, raw := range []string{boundText + " expires 20sec", strings.Replace(boundText, "table 16386", "table 16386 mtu 1200", 1), strings.Replace(boundText, "from 100.64.181.129", "from 127.0.0.1", 1)} {
		if _, err := parseStockProbeRoute(raw, address); err == nil {
			t.Fatal("unknown cache annotation or unsafe source accepted")
		}
	}
	after := before
	before.policy = "reviewed-rpdb-and-fib"
	after.policy = "changed"
	if stockProbeSamePath(before, after) {
		t.Fatal("RPDB/FIB change accepted")
	}
}

func TestPinnedNFQDialerUsesActualSelectedLocalAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer := make(chan net.Addr, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			peer <- conn.RemoteAddr()
			conn.Close()
		}
	}()
	source := netip.MustParseAddr("127.0.0.2")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pinnedTCPDialer(source, 0).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); got != source.String() {
		t.Fatal("socket used another source", got)
	}
	select {
	case got := <-peer:
		if got.(*net.TCPAddr).IP.String() != source.String() {
			t.Fatal("peer saw another source", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestNFQProofDiagnosticsRetainEveryExistingProofRequirement(t *testing.T) {
	type observation struct {
		before, after                    stockProbePath
		packets                          uint64
		counterErr, stockErr, processErr error
		active                           bool
		queue, currentQueue              int
		process, currentProcess          string
	}
	for _, tc := range []struct {
		name, want string
		alter      func(*observation)
	}{
		{"confirmed", "", func(*observation) {}},
		{"counter", "nfq-socket-counter-unavailable", func(o *observation) { o.counterErr = errors.New("private command error") }},
		{"socket", "nfq-socket-unobserved", func(o *observation) { o.packets = 0 }},
		{"stock", "nfq-stock-readback-refused", func(o *observation) { o.stockErr = errors.New("private rules") }},
		{"kernel", "nfq-kernel-queue-unavailable", func(o *observation) { o.active = false }},
		{"process-read", "nfq-process-readback-refused", func(o *observation) { o.processErr = errors.New("private process") }},
		{"queue", "nfq-queue-changed", func(o *observation) { o.currentQueue = 301 }},
		{"process", "nfq-process-changed", func(o *observation) { o.currentProcess = "other" }},
		{"interface", "nfq-route-interface-changed", func(o *observation) { o.after.passive = false }},
		{"graph", "nfq-rules-changed", func(o *observation) { o.after.graph = "different" }},
		{"route", "nfq-route-changed", func(o *observation) { o.after.route = "different" }},
		{"stock-counter", "nfq-stock-counter-not-advanced", func(o *observation) { o.after.packets = o.before.packets }},
		{"source-identity", "nfq-source-changed", func(o *observation) { o.after.source = netip.MustParseAddr("100.64.181.129") }},
		{"policy", "nfq-policy-changed", func(o *observation) { o.after.policy = "different" }},
		{"active-nonstock", "", func(o *observation) {
			o.before.passive = false
			o.after.passive = false
			o.after.packets = o.before.packets
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observation{before: stockProbePath{passive: true, graph: "graph", route: "route", packets: 7}, after: stockProbePath{passive: true, graph: "graph", route: "route", packets: 8}, packets: 1, active: true, queue: 300, currentQueue: 300, process: "same", currentProcess: "same"}
			tc.alter(&o)
			code := nfqwsProofRefusal(o.before, o.after, o.packets, o.counterErr, o.stockErr, o.processErr, o.active, o.queue, o.currentQueue, o.process, o.currentProcess)
			oldProof := o.counterErr == nil && o.packets > 0 && o.active && o.stockErr == nil && stockProbeSocketConfirmed(o.before, o.after, o.packets) && o.processErr == nil && o.queue == o.currentQueue && o.process == o.currentProcess
			if code != tc.want || (code == "") != oldProof {
				t.Fatalf("diagnostic=%q want=%q old-proof=%t", code, tc.want, oldProof)
			}
		})
	}
}

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
