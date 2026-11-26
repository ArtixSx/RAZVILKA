package dataplane

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func xrayRuntimeStatFixture(pid int) []byte {
	f := make([]string, 50)
	for i := range f {
		f[i] = "0"
	}
	f[0], f[1], f[2], f[5], f[19] = "S", "123", "123", "-1", "456789"
	return []byte(strconv.Itoa(pid) + " (xray ) worker) " + strings.Join(f, " ") + "\n")
}

func TestXraySelectedTCPRuntimeStatWholeOriginalLiveProcess(t *testing.T) {
	valid := xrayRuntimeStatFixture(4321)
	start, parent, group, err := xraySelectedTCPStat(valid, 4321)
	if err != nil || start != "456789" || parent != 123 || group != 123 {
		t.Fatalf("valid stat: %q %d %d %v", start, parent, group, err)
	}
	bad := map[string][]byte{
		"truncated":              valid[:len(valid)-1],
		"foreign PID":            []byte(strings.Replace(string(valid), "4321 (", "4322 (", 1)),
		"noncanonical PID":       []byte("0" + string(valid)),
		"zombie":                 []byte(strings.Replace(string(valid), ") S ", ") Z ", 1)),
		"dead":                   []byte(strings.Replace(string(valid), ") S ", ") X ", 1)),
		"zero birth":             []byte(strings.Replace(string(valid), "456789", "0", 1)),
		"noncanonical birth":     []byte(strings.Replace(string(valid), "456789", "0456789", 1)),
		"unknown state":          []byte(strings.Replace(string(valid), ") S ", ") ? ", 1)),
		"two lines":              append(append([]byte{}, valid...), '\n'),
		"NUL":                    []byte(strings.Replace(string(valid), "worker", "work\x00er", 1)),
		"non numeric suffix":     []byte(strings.TrimSuffix(string(valid), "0\n") + "abc\n"),
		"incomplete after birth": []byte(strings.Split(string(valid), "456789")[0] + "456789\n"),
		"oversized":              []byte(strings.Repeat("1", 8193) + "\n"),
	}
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := xraySelectedTCPStat(data, 4321); err == nil {
				t.Fatal("accepted malformed/incomplete stat")
			}
		})
	}
}

func xrayRuntimeProcAddress(endpoint netip.AddrPort) string {
	ip := endpoint.Addr()
	var data []byte
	if ip.Is4() {
		a := ip.As4()
		data = a[:]
	} else {
		a := ip.As16()
		data = a[:]
	}
	var text strings.Builder
	for i := 0; i < len(data); i += 4 {
		fmt.Fprintf(&text, "%08X", binary.NativeEndian.Uint32(data[i:i+4]))
	}
	fmt.Fprintf(&text, ":%04X", endpoint.Port())
	return text.String()
}
func xrayRuntimeProcRow(local, remote netip.AddrPort, state uint8, inode uint64, short bool) string {
	row := fmt.Sprintf("0: %s %s %02X 00000000:00000000 00:00000000 00000000 0 0 %d 1 0000000000000000", xrayRuntimeProcAddress(local), xrayRuntimeProcAddress(remote), state, inode)
	if !short {
		row += " 100 0 0 10 -1"
	}
	return row + "\n"
}
func xrayRuntimeProcTable(ipv6 bool, rows ...string) []byte {
	remote := "rem_address"
	if ipv6 {
		remote = "remote_address"
	}
	return []byte("  sl  local_address " + remote + " st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + strings.Join(rows, ""))
}

func TestXraySelectedTCPRuntimeProcTCPParsesEveryNativeRow(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.1:23456")
	zero := netip.MustParseAddrPort("0.0.0.0:0")
	valid := xrayRuntimeProcTable(false, xrayRuntimeProcRow(local, zero, 10, 789, false), xrayRuntimeProcRow(netip.MustParseAddrPort("192.168.1.40:55000"), netip.MustParseAddrPort("149.154.167.51:443"), 6, 0, true))
	rows, err := xraySelectedTCPSockets(valid, false)
	if err != nil || len(rows) != 2 || rows[0].local != local || rows[0].inode != 789 || rows[1].state != 6 {
		t.Fatalf("valid IPv4 TCP rows: %v", err)
	}
	for _, text := range []string{"[2001:db8:1234:5678:abcd:ef01:2345:6789]:23456", "[::ffff:192.168.1.1]:23456"} {
		endpoint := netip.MustParseAddrPort(text)
		table := xrayRuntimeProcTable(true, xrayRuntimeProcRow(endpoint, netip.MustParseAddrPort("[::]:0"), 10, 890, false))
		rows, err := xraySelectedTCPSockets(table, true)
		if err != nil || len(rows) != 1 || rows[0].local != endpoint {
			t.Fatalf("native IPv6 words %s: %v", endpoint, err)
		}
	}
	bad := map[string][]byte{
		"truncated":                 valid[:len(valid)-1],
		"wrong header":              []byte(strings.Replace(string(valid), "rem_address", "remote_address", 1)),
		"malformed unrelated":       append(append([]byte{}, valid...), []byte("unrelated broken row\n")...),
		"blank trailing row":        append(append([]byte{}, valid...), '\n'),
		"invalid address":           []byte(strings.Replace(string(valid), xrayRuntimeProcAddress(local), "ZZZZZZZZ:5BA0", 1)),
		"short address":             []byte(strings.Replace(string(valid), xrayRuntimeProcAddress(local), "1:5BA0", 1)),
		"signed address":            []byte(strings.Replace(string(valid), xrayRuntimeProcAddress(local), "+0000001:5BA0", 1)),
		"unknown state":             []byte(strings.Replace(string(valid), " 0A ", " FF ", 1)),
		"zero listener inode":       []byte(strings.Replace(string(valid), " 789 ", " 0 ", 1)),
		"nonempty listener remote":  []byte(strings.Replace(string(valid), xrayRuntimeProcAddress(zero), xrayRuntimeProcAddress(netip.MustParseAddrPort("1.1.1.1:443")), 1)),
		"short queue":               []byte(strings.Replace(string(valid), "00000000:00000000", "0:0", 1)),
		"bad timer":                 []byte(strings.Replace(string(valid), "00:00000000", "GG:00000000", 1)),
		"signed inode":              []byte(strings.Replace(string(valid), " 789 ", " +789 ", 1)),
		"overflow inode":            []byte(strings.Replace(string(valid), " 789 ", " 18446744073709551616 ", 1)),
		"truncated listener fields": xrayRuntimeProcTable(false, xrayRuntimeProcRow(local, zero, 10, 789, true)),
		"NUL":                       []byte(strings.Replace(string(valid), "inode", "in\x00ode", 1)),
		"extra suffix":              []byte(strings.Replace(string(valid), "10 -1\n", "10 -1 extra\n", 1)),
		"oversized":                 []byte(strings.Repeat(" ", 8<<20) + "\n"),
	}
	for name, table := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := xraySelectedTCPSockets(table, false); err == nil {
				t.Fatal("accepted incomplete/malformed whole TCP inventory")
			}
		})
	}
}

func TestXraySelectedTCPRuntimeListenerRequiresSoleExactIPv4(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.168.1.1:23456")
	parse := func(ipv6 bool, rows ...string) []xraySelectedTCPSocketRow {
		t.Helper()
		result, err := xraySelectedTCPSockets(xrayRuntimeProcTable(ipv6, rows...), ipv6)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	zero := netip.MustParseAddrPort("0.0.0.0:0")
	zero6 := netip.MustParseAddrPort("[::]:0")
	one := xrayRuntimeProcRow(endpoint, zero, 10, 789, false)
	v4 := parse(false, one, xrayRuntimeProcRow(netip.MustParseAddrPort("192.168.2.1:23456"), zero, 10, 790, false))
	v6 := parse(true, xrayRuntimeProcRow(netip.MustParseAddrPort("[2001:db8::1]:23456"), zero6, 10, 791, false))
	if inode, err := xraySelectedTCPListenerInode(v4, v6, endpoint); err != nil || inode != 789 {
		t.Fatalf("disjoint listener was mistaken for overlap: %d %v", inode, err)
	}
	bad := []struct {
		name     string
		v4, v6   []xraySelectedTCPSocketRow
		endpoint netip.AddrPort
	}{
		{"absent", parse(false), v6, endpoint},
		{"duplicate exact", parse(false, one, one), v6, endpoint},
		{"wildcard IPv4", parse(false, one, xrayRuntimeProcRow(netip.MustParseAddrPort("0.0.0.0:23456"), zero, 10, 790, false)), v6, endpoint},
		{"wildcard IPv6", v4, parse(true, xrayRuntimeProcRow(netip.MustParseAddrPort("[::]:23456"), zero6, 10, 790, false)), endpoint},
		{"mapped IPv6", v4, parse(true, xrayRuntimeProcRow(netip.MustParseAddrPort("[::ffff:192.168.1.1]:23456"), zero6, 10, 790, false)), endpoint},
		{"loopback", v4, v6, netip.MustParseAddrPort("127.0.0.1:23456")},
		{"link local", v4, v6, netip.MustParseAddrPort("169.254.1.1:23456")},
		{"privileged port", v4, v6, netip.MustParseAddrPort("192.168.1.1:443")},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := xraySelectedTCPListenerInode(tt.v4, tt.v6, tt.endpoint); err == nil {
				t.Fatal("accepted ambiguous/wrong listener")
			}
		})
	}
}

// Genuine Go helper children model actual Cmd/Wait ownership only. They are
// never an Xray/native/redirect/router/LAN readiness proof.
func TestXraySelectedTCPRuntimeChild(t *testing.T) {
	if os.Getenv("RAZVILKA_XRAY_WAIT_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "ready")
	var byte [1]byte
	_, _ = os.Stdin.Read(byte[:])
	code, _ := strconv.Atoi(os.Getenv("RAZVILKA_XRAY_WAIT_EXIT"))
	os.Exit(code)
}

type xrayRuntimeChildFixture struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	owner *xraySelectedTCPProcess
}

func xrayRuntimeChild(t *testing.T, code int) *xrayRuntimeChildFixture {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Clean(binary), "-test.run=^TestXraySelectedTCPRuntimeChild$")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"RAZVILKA_XRAY_WAIT_HELPER=1", "RAZVILKA_XRAY_WAIT_EXIT=" + strconv.Itoa(code)}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := &xrayRuntimeChildFixture{cmd: cmd, input: input}
	t.Cleanup(func() {
		_ = input.Close()
		if f.owner != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			select {
			case <-f.owner.done:
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				<-f.owner.done
			}
		} else {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("actual helper ACK: %q %v", line, err)
	}
	return f
}

func xrayRuntimeFinite(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestXraySelectedTCPRuntimeWaitSingleOwnerAndOriginalCancellation(t *testing.T) {
	f := xrayRuntimeChild(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	owners := make(chan *xraySelectedTCPProcess, 8)
	for range 8 {
		wg.Go(func() {
			p, err := retainXraySelectedTCPProcessWait(ctx, f.cmd)
			if err == nil {
				owners <- p
			}
		})
	}
	wg.Wait()
	close(owners)
	for p := range owners {
		if f.owner != nil {
			t.Fatal("same actual Cmd acquired two Wait owners")
		}
		f.owner = p
	}
	if f.owner == nil {
		t.Fatal("actual child was not retained")
	}
	if _, release, err := f.owner.forwardContext(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	cancel()
	if _, _, err := f.owner.forwardContext(xrayRuntimeFinite(t)); err == nil {
		t.Fatal("fresh context revived original cancelled forward owner")
	}
	if _, err := f.owner.observe(xrayRuntimeFinite(t), netidentity.NewProcProvider(), netidentity.Identity{}); err == nil {
		t.Fatal("cancelled owner issued process observation")
	}
	_ = f.input.Close()
	if err := f.owner.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd); err == nil {
		t.Fatal("already waited actual Cmd was replayed")
	}
	if xraySelectedTCPWaitResult(f.owner.pid+1, f.owner.state, f.owner.waitErr) || xraySelectedTCPWaitResult(f.owner.pid, nil, errors.New("ECHILD")) || xraySelectedTCPWaitResult(f.owner.pid, f.owner.state, errors.New("unrelated wait error")) || xraySelectedTCPWaitResult(f.owner.pid, f.owner.state, &exec.ExitError{ProcessState: f.owner.state}) {
		t.Fatal("foreign PID/state/error adopted as actual terminal Wait")
	}
	xraySelectedTCPWaits.Lock()
	retained := xraySelectedTCPWaits.live[f.cmd]
	xraySelectedTCPWaits.Unlock()
	if retained != nil {
		t.Fatal("terminal Wait left live association")
	}
}

func TestXraySelectedTCPRuntimeWaitCanRetainCancelledStartACK(t *testing.T) {
	f := xrayRuntimeChild(t, 7)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cancel()
	p, err := retainXraySelectedTCPProcessWait(ctx, f.cmd)
	if err != nil {
		t.Fatal("actual Start ACK lost its sole reaper after cancellation", err)
	}
	f.owner = p
	if _, _, err := p.forwardContext(xrayRuntimeFinite(t)); err == nil {
		t.Fatal("cancelled original acquired forward readback")
	}
	_ = f.input.Close()
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal("actual nonzero child exit was not joined", err)
	}
	if p.state == nil || p.state.ExitCode() != 7 || p.waitErr == nil {
		t.Fatal("lost actual exit state/error")
	}
}

func TestXraySelectedTCPRuntimeCloseTimeoutDoesNotSignalChild(t *testing.T) {
	f := xrayRuntimeChild(t, 0)
	p, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = p
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Close(short); err == nil {
		t.Fatal("close timeout became terminal proof")
	}
	select {
	case <-p.done:
		t.Fatal("Close killed/signalled live child")
	default:
	}
	if _, _, err := p.forwardContext(xrayRuntimeFinite(t)); err == nil {
		t.Fatal("Close revived forward readback")
	}
	_ = f.input.Close()
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	}
}

func TestXraySelectedTCPRuntimeOriginalCmdCannotBeCopiedOrChanged(t *testing.T) {
	f := xrayRuntimeChild(t, 0)
	p, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = p
	copy := &xraySelectedTCPProcess{self: p, cmd: p.cmd, child: p.child, pid: p.pid, image: p.image, ctx: p.ctx, cancel: p.cancel, done: p.done}
	if copy.Joined(xrayRuntimeFinite(t)) == nil {
		t.Fatal("copied owner joined actual child")
	}
	_ = f.input.Close()
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	}
	old := f.cmd.Args[0]
	f.cmd.Args[0] = "changed"
	if p.Joined(xrayRuntimeFinite(t)) == nil {
		t.Fatal("changed actual Cmd adopted old terminal result")
	}
	f.cmd.Args[0] = old
	if p.Joined(context.Background()) == nil {
		t.Fatal("unbounded cleanup context joined")
	}
}

func TestXraySelectedTCPRuntimeRejectsUnstartedUnboundedAndCommandContext(t *testing.T) {
	f := xrayRuntimeChild(t, 0)
	if _, err := retainXraySelectedTCPProcessWait(context.Background(), f.cmd); err == nil {
		t.Fatal("unbounded context retained child")
	}
	originalArgs := f.cmd.Args
	f.cmd.Args = make([]string, 17)
	if _, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd); err == nil {
		t.Fatal("unbounded argv retained child")
	}
	f.cmd.Args = originalArgs
	f.cmd.Cancel = func() error { return nil }
	if _, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd); err == nil {
		t.Fatal("automatic external Cancel acquired child")
	}
	f.cmd.Cancel = nil
	if _, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), exec.Command(f.cmd.Path)); err == nil {
		t.Fatal("unstarted command retained child")
	}
	p, err := retainXraySelectedTCPProcessWait(xrayRuntimeFinite(t), f.cmd)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = p
	_ = f.input.Close()
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	}
}

func TestXraySelectedTCPRuntimeObservationDTOCannotProveIdentity(t *testing.T) {
	o := xraySelectedTCPProcessObservation{pid: 4321, parent: 123, group: 123, boot: "claimed", start: "456", exe: "/claimed", argumentsSHA256: "claimed", configSHA256: "claimed"}
	if o.same(o) {
		t.Fatal("detached comparison fields manufactured native original identity")
	}
	if text := fmt.Sprintf("%v %#v", o, o); strings.Contains(text, "claimed") {
		t.Fatal("private observation leaked its fields")
	}
}
