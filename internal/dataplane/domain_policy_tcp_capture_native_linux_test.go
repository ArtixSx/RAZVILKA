//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const domainPolicyTCPOriginalDstNative = "RAZVILKA_TCP_ORIGINAL_DST_NATIVE"

// Root-only opt-in acceptance for the real SO_ORIGINAL_DST decoder. Every
// route/NAT/socket/conntrack lives in one fresh private network namespace;
// deleting that namespace settles those owned objects together. No router
// rules, foreign conntracks, default route or external network are touched.
// This proves socket decoding only, not LAN MAC/iif, Manager, DNS or VLESS.
func TestDomainPolicySyntheticTCPLinuxOriginalDstNative(t *testing.T) {
	if os.Getenv(domainPolicyTCPOriginalDstNative) != "1" {
		t.Skip("Root-only owned namespace socket acceptance requires explicit opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("opted-in socket acceptance requires root")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	namespace := "rztcp-" + hex.EncodeToString(nonce[:])
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, ip, args...).CombinedOutput()
	}
	if output, err := run("netns", "add", namespace); err != nil {
		t.Fatalf("create owned namespace: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := run("netns", "delete", namespace); err != nil {
			t.Errorf("owned namespace cleanup pending: %v: %s", err, output)
			return
		}
		output, err := run("netns", "list")
		if err != nil {
			t.Errorf("namespace cleanup readback unavailable: %v", err)
			return
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == namespace {
				t.Error("owned namespace still present after delete ACK")
			}
		}
	})
	if output, err := run("-n", namespace, "link", "set", "lo", "up"); err != nil {
		t.Fatalf("owned loopback: %v: %s", err, output)
	}
	if output, err := run("-n", namespace, "route", "add", "198.18.255.254/32", "dev", "lo", "src", "127.0.0.1"); err != nil {
		t.Fatalf("owned initial route: %v: %s", err, output)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, ip, "netns", "exec", namespace, binary, "-test.run=^TestDomainPolicySyntheticTCPLinuxOriginalDstNativeChild$", "-test.count=1", "-test.timeout=12s")
	child.Env = append(os.Environ(), "RAZVILKA_TCP_ORIGINAL_DST_ROLE=isolated-reader")
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("ORIGINAL_DST_SOCKET_OK")) {
		t.Fatalf("native decoder acceptance failed: %v: %s", err, output)
	}
	t.Log("NATIVE_SOCKET_ONLY: actual accepted source and synthetic original destination; owned namespace cleanup required")
}

func TestDomainPolicySyntheticTCPLinuxOriginalDstNativeChild(t *testing.T) {
	if os.Getenv(domainPolicyTCPOriginalDstNative) != "1" || os.Getenv("RAZVILKA_TCP_ORIGINAL_DST_ROLE") != "isolated-reader" {
		t.Skip("only the explicit owned namespace parent may run this slice")
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	local := listener.Addr().(*net.TCPAddr).AddrPort()
	rule := []string{"OUTPUT", "-p", "tcp", "-s", "127.0.0.1/32", "-d", "198.18.255.254/32", "--dport", "443", "-m", "comment", "--comment", "rz-original-dst-owned", "-j", "DNAT", "--to-destination", local.String()}
	runRule := func(operation string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "iptables", append([]string{"-w", "1", "-t", "nat", operation}, rule...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("owned DNAT %s: %w: %s", operation, err, output)
		}
		return nil
	}
	if err := runRule("-A"); err != nil {
		t.Fatal(err)
	}
	if err := runRule("-C"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runRule("-D"); err != nil {
			t.Error(err)
		}
	}()
	original := netip.MustParseAddrPort("198.18.255.254:443")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	base, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}).DialContext(ctx, "tcp4", original.String())
	if err != nil {
		t.Fatal(err)
	}
	client := base.(*net.TCPConn)
	defer client.Close()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	socket, err := observeDomainPolicyTCPSocket(accepted)
	if err != nil || socket.Source != client.LocalAddr().(*net.TCPAddr).AddrPort() || socket.Listener != local || socket.OriginalDestination != original {
		t.Fatalf("actual native tuple differs: %+v: %v", socket, err)
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = accepted.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("GET / HTTP/1.1\r\nHost: service.example.com\r\n\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, len(payload))
	if _, err := io.ReadFull(accepted, read); err != nil || !bytes.Equal(read, payload) {
		t.Fatal("capture changed bytes", err)
	}
	fmt.Println("ORIGINAL_DST_SOCKET_OK")
}
