//go:build linux

package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

func syntheticIPSetAck(request []byte, code int32) []byte {
	b := make([]byte, 36)
	copy(b[:16], request[:16])
	binary.NativeEndian.PutUint32(b[:4], 36)
	binary.NativeEndian.PutUint16(b[4:6], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(b[6:8], 0)
	binary.NativeEndian.PutUint32(b[16:20], uint32(code))
	copy(b[20:], request[:16])
	return b
}

func TestSyntheticIPSetNetlinkClosedABIAndMalformedReplies(t *testing.T) {
	request, err := syntheticIPSetRequest(syntheticIPSetTest, 7, 9, "_NDM_OGDN_4_@domain-list4", netip.MustParseAddr("1.1.1.1"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int32{0, -4103} {
		r := syntheticIPSetReply{}
		if err := syntheticIPSetConsume(syntheticIPSetAck(request, code), request, &r); err != nil || !r.ack || r.member != (code == 0) {
			t.Fatal("exact test ACK refused", err)
		}
	}
	capped := syntheticIPSetAck(request, 0)
	binary.NativeEndian.PutUint16(capped[6:8], 0x100)
	if err := syntheticIPSetConsume(capped, request, &syntheticIPSetReply{}); err != nil {
		t.Fatal("modern header-only CAPPED ACK refused", err)
	}
	for _, command := range []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 65535} {
		if _, err := syntheticIPSetRequest(command, 1, 2, "test", netip.MustParseAddr("1.1.1.1"), false); err == nil {
			t.Fatal("unsupported/mutation command representable", command)
		}
	}
	base := syntheticIPSetAck(request, 0)
	for name, mutate := range map[string]func([]byte) []byte{
		"short": func(b []byte) []byte { return b[:15] }, "length": func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], 4096); return b },
		"sequence": func(b []byte) []byte { b[8]++; return b }, "port": func(b []byte) []byte { b[12]++; return b },
		"flags": func(b []byte) []byte { b[6] = 1; return b }, "echo": func(b []byte) []byte { b[24]++; return b },
		"duplicate": func(b []byte) []byte { return append(b, b...) }, "missing-set": func(b []byte) []byte { return syntheticIPSetAck(request, -int32(unix.ENOENT)) },
		"permission": func(b []byte) []byte { return syntheticIPSetAck(request, -int32(unix.EPERM)) },
		"unknown":    func(b []byte) []byte { return syntheticIPSetAck(request, -4097) },
	} {
		t.Run(name, func(t *testing.T) {
			r := syntheticIPSetReply{}
			if err := syntheticIPSetConsume(mutate(slices.Clone(base)), request, &r); !errors.Is(err, ErrSyntheticIPSet) {
				t.Fatal("malformed/unknown accepted", err)
			}
		})
	}
	attrs := []byte{}
	for _, a := range []struct {
		k uint16
		b []byte
	}{{1, []byte{6}}, {2, []byte("test\x00")}, {3, []byte("hash:net\x00")}, {4, []byte{2}}, {5, []byte{2}}} {
		attrs = append(attrs, syntheticIPSetAttr(a.k, a.b)...)
	}
	body := append([]byte{2, 0, 0, 0}, attrs...)
	if _, err := syntheticIPSetDecodeHeader(body); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{body[:len(body)-1], append(slices.Clone(body), syntheticIPSetAttr(1, []byte{6})...), append(slices.Clone(body), syntheticIPSetAttr(6, []byte{0})...)} {
		if _, err := syntheticIPSetDecodeHeader(bad); err == nil {
			t.Fatal("malformed header accepted")
		}
	}
}

// Root-only actual kernel fixture. The sole child gets a fresh network
// namespace before any ipset command. No host set/rule/link/sysctl is changed.
func TestSyntheticIPSetNative(t *testing.T) {
	if os.Getenv("RAZVILKA_SYNTHETIC_IPSET_NATIVE") != "1" {
		t.Skip("explicit private namespace kernel test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if os.Getenv("RAZVILKA_SYNTHETIC_IPSET_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestSyntheticIPSetNative$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "RAZVILKA_SYNTHETIC_IPSET_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private child failed: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	currentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initialNet, err := os.Readlink("/proc/1/ns/net")
	if err != nil || currentNet == initialNet {
		t.Fatal("fixture refuses the initial host namespace")
	}
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/sbin/ipset", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v", err)
		}
		return out
	}
	run("create", "rz_ipset_fixture", "hash:net", "family", "inet", "counters")
	run("add", "rz_ipset_fixture", "1.1.1.0/24", "packets", "5", "bytes", "70")
	run("add", "rz_ipset_fixture", "198.18.0.1/32", "packets", "5", "bytes", "70")
	provider := netidentity.NewProcProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	identity, err := provider.Observe(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewSyntheticBaselineIPSetReader(provider, identity, func(ctx context.Context, use func(context.Context) error) error { return use(ctx) })
	if err != nil {
		t.Fatal(err)
	}
	equal := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := reader.EquivalentDestinations(ctx, "rz_ipset_fixture", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1"))
		if (err == nil) != want {
			t.Fatalf("actual membership equal=%v: %v", want, err)
		}
	}
	before := run("save", "rz_ipset_fixture")
	equal(true)
	after := run("save", "rz_ipset_fixture")
	if string(before) != string(after) {
		t.Fatal("read-only TEST changed actual counters/set")
	}
	run("del", "rz_ipset_fixture", "198.18.0.1/32")
	equal(false)
	run("add", "rz_ipset_fixture", "198.18.0.1/32", "nomatch")
	equal(false)
	run("del", "rz_ipset_fixture", "1.1.1.0/24")
	run("add", "rz_ipset_fixture", "1.1.1.0/24", "nomatch")
	equal(true)
	run("flush", "rz_ipset_fixture")
	equal(true)
	run("destroy", "rz_ipset_fixture")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	err = reader.EquivalentDestinations(ctx, "rz_ipset_fixture", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1"))
	cancel()
	if err == nil || !strings.Contains(err.Error(), "set-absent") {
		t.Fatal("missing set misclassified as negative", err)
	}
	run("create", "rz_ipset_fixture", "hash:ip", "family", "inet")
	equal(false)
	run("destroy", "rz_ipset_fixture")
	// Even a scope callback claiming success without executing the kernel leaf
	// cannot turn a detached descriptor into comparison success.
	fake, err := NewSyntheticBaselineIPSetReader(provider, identity, func(context.Context, func(context.Context) error) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	err = fake.EquivalentDestinations(ctx, "rz_ipset_fixture", netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.1"))
	cancel()
	if err == nil {
		t.Fatal("omitted kernel callback granted success")
	}
	t.Log("NATIVE_IPSET_ONLY: actual ordinary/nomatch/CIDR/absent/type checks; counters unchanged; private namespace removed with child")
}
