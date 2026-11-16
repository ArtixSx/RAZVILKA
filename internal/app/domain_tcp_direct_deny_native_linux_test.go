//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDomainTCPOriginalNativeDirectForwardDeny(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DIRECT_DENY_NATIVE", "1")
	runDomainTCPOriginalNative(t, false)
}

type domainDirectSYNReply struct {
	Count uint64
	Error bool
}

// This observer adds no packet rules, BPF programs, listener or routing state.
// Its sole AF_PACKET FD lives in the existing disposable server namespace.
func TestDomainTCPDirectNativeSYNObserver(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_SYN_OBSERVER") != "1" {
		t.Skip("isolated passive observer role")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root observer required")
	}
	controlFile := os.NewFile(3, "original-observer-control")
	if controlFile == nil {
		t.Fatal("missing original control")
	}
	control, err := net.FileConn(controlFile)
	closeErr := controlFile.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	defer func() {
		if err := control.Close(); err != nil {
			t.Error("observer control close", err)
		}
	}()
	control.SetDeadline(time.Now().Add(30 * time.Second))
	iface, err := net.InterfaceByName("server0")
	if err != nil {
		t.Fatal(err)
	}
	// Packet SOCK_DGRAM exposes the IPv4 header, avoiding link-header guesses.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int((unix.ETH_P_IP>>8)|((unix.ETH_P_IP&255)<<8)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Error("passive socket close", err)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16((unix.ETH_P_IP >> 8) | ((unix.ETH_P_IP & 255) << 8)), Ifindex: iface.Index}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65536)
	var count uint64
	drain := func() error {
		for reads := 0; reads < 4096; reads++ {
			n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return err
			}
			if n < 20 || buffer[0]>>4 != 4 {
				continue
			}
			header := int(buffer[0]&15) * 4
			if header < 20 || n < header+20 || buffer[9] != unix.IPPROTO_TCP || binary.BigEndian.Uint16(buffer[6:8])&0x3fff != 0 {
				continue
			}
			if buffer[16] != 1 || buffer[17] != 1 || buffer[18] != 1 || buffer[19] != 2 || binary.BigEndian.Uint16(buffer[header+2:header+4]) != 443 {
				continue
			}
			if buffer[header+13]&0x12 == 0x02 {
				count++
			}
		}
		return errors.New("bounded passive queue did not drain")
	}
	encoder, decoder := json.NewEncoder(control), json.NewDecoder(control)
	if err := encoder.Encode(domainDirectSYNReply{}); err != nil {
		t.Fatal(err)
	}
	for {
		var command string
		if decoder.Decode(&command) != nil {
			t.Fatal("observer original control lost")
		}
		if err := drain(); err != nil {
			_ = encoder.Encode(domainDirectSYNReply{Error: true})
			t.Fatal(err)
		}
		if command == "arm" {
			count = 0
		} else if command != "snapshot" && command != "close" {
			t.Fatal("unknown closed observer command")
		}
		if err := encoder.Encode(domainDirectSYNReply{Count: count}); err != nil {
			t.Fatal(err)
		}
		if command == "close" {
			return
		}
	}
}

func domainOriginalDirectDeny(t *testing.T, ctx context.Context, peers *domainOriginalNativePeers, iptables, alias string) {
	t.Helper()
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile, childFile := os.NewFile(uintptr(sockets[0]), "original-observer-parent"), os.NewFile(uintptr(sockets[1]), "original-observer-child")
	control, err := net.FileConn(parentFile)
	parentErr := parentFile.Close()
	if err != nil || parentErr != nil {
		childFile.Close()
		t.Fatal(errors.Join(err, parentErr))
	}
	defer control.Close()
	command := exec.CommandContext(ctx, "ip", "netns", "exec", peers.server, os.Args[0], "-test.run=^TestDomainTCPDirectNativeSYNObserver$", "-test.v", "-test.timeout=30s")
	command.Env = append(os.Environ(), "RAZVILKA_DOMAIN_SYN_OBSERVER=1")
	command.ExtraFiles = []*os.File{childFile}
	logPath := peers.root + "/direct-syn-observer.log"
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		childFile.Close()
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		childFile.Close()
		t.Fatal(err)
	}
	if err := childFile.Close(); err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = command.Process.Kill()
			joined = true
			_ = command.Wait()
		}
	}()
	encoder, decoder := json.NewEncoder(control), json.NewDecoder(control)
	reply := func(send string) uint64 {
		t.Helper()
		control.SetDeadline(time.Now().Add(3 * time.Second))
		if send != "" {
			if err := encoder.Encode(send); err != nil {
				t.Fatal(err)
			}
		}
		var result domainDirectSYNReply
		if decoder.Decode(&result) != nil || result.Error {
			t.Fatal("original passive SYN observer failed")
		}
		return result.Count
	}
	if reply("") != 0 {
		t.Fatal("observer was not initially empty")
	}
	// Prove the SAME held observer sees a real allowed SYN to the SAME target.
	positive := peers.clientRequest(t, ctx, "selected", domainOriginalServer)
	if positive.Source != domainOriginalClient || positive.Marker != "native-domain-service" || reply("snapshot") == 0 {
		t.Fatal("passive observer positive control missing", positive)
	}
	if reply("arm") != 0 {
		t.Fatal("passive reset failed")
	}
	run := func(args ...string) (string, error) {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(c, iptables, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	for _, chain := range []string{"FORWARD", "OUTPUT"} {
		out, err := run("-S", chain)
		if err != nil || out != "-P "+chain+" ACCEPT" {
			t.Fatal("owned initial policy not exact ACCEPT", chain, err)
		}
	}
	if out, err := run("-P", "FORWARD", "DROP"); err != nil {
		t.Fatal(out, err)
	}
	restored := false
	restore := func() error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cleanup, iptables, "-S", "FORWARD").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "-P FORWARD DROP" {
			return fmt.Errorf("owned DROP policy drift: %w", err)
		}
		if err := exec.CommandContext(cleanup, iptables, "-P", "FORWARD", "ACCEPT").Run(); err != nil {
			return err
		}
		out, err = exec.CommandContext(cleanup, iptables, "-S", "FORWARD").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "-P FORWARD ACCEPT" {
			return fmt.Errorf("owned ACCEPT readback failed: %w", err)
		}
		return nil
	}
	defer func() {
		if !restored {
			if err := restore(); err != nil {
				t.Error("owned FORWARD policy restore failed", err)
			}
		}
	}()
	negative := peers.clientRequest(t, ctx, "mismatch-deny", alias)
	if negative.Marker != "explicit-accepted-connection-close" || negative.ClientPort == "" || negative.ClientPort == "0" {
		t.Fatal("no actual accepted connection refusal", negative)
	}
	if count := reply("snapshot"); count != 0 {
		t.Fatal("FORWARD deny bypassed through OUTPUT", count)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	restored = true
	if count := reply("close"); count != 0 {
		t.Fatal("late outbound SYN after refusal", count)
	}
	joined = true
	if err := command.Wait(); err != nil {
		t.Fatal("passive observer did not join", err)
	}
	t.Log(fmt.Sprintf("ACTUAL_DIRECT_FORWARD_DENY_ZERO_SYN: published alias accepted client port=%s; positive same-FD observer control; FORWARD DROP/OUTPUT ACCEPT; explicit EOF/reset, zero outbound target SYN; original policy restored; observer joined", negative.ClientPort))
}
