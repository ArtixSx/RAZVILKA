//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const mihomoOutputTestEnvelope = "[2026-11-16 12:34:56] [E] "

func TestMihomoSidecarOutputClosedClassification(t *testing.T) {
	for _, tc := range []struct{ message, category string }{
		{"Open /proc/self/fd/4 failed!", "config-open"},
		{"Parse /proc/self/fd/4 failed!", "config-parse"},
		{"Can't found socks5.port!", "config-required"},
		{"Can't found socks5.address!", "config-required"},
		{"Must be set both socks5 username and password!", "config-required"},
		{mihomoOutputTestEnvelope + "socks5 tunnel open (Permission denied)", "tun-open"},
		{mihomoOutputTestEnvelope + "socks5 tunnel mtu", "tun-mtu"},
		{mihomoOutputTestEnvelope + "socks5 tunnel ipv4", "tun-ipv4"},
		{mihomoOutputTestEnvelope + "socks5 tunnel ipv6", "tun-ipv6"},
		{mihomoOutputTestEnvelope + "socks5 tunnel state", "tun-up"},
		{mihomoOutputTestEnvelope + "socks5 tunnel netif", "lwip-netif"},
		{mihomoOutputTestEnvelope + "socks5 tunnel tcp", "lwip-tcp"},
		{mihomoOutputTestEnvelope + "socks5 tunnel udp", "lwip-udp"},
		{mihomoOutputTestEnvelope + "socks5 tunnel event", "event-socketpair"},
		{mihomoOutputTestEnvelope + "socks5 tunnel event nonblock", "event-nonblock"},
		{mihomoOutputTestEnvelope + "socks5 tunnel task event", "event-task"},
		{mihomoOutputTestEnvelope + "socks5 tunnel task lwip", "lwip-task"},
		{mihomoOutputTestEnvelope + "socks5 tunnel task timer", "timer-task"},
	} {
		t.Run(tc.category+"/"+fmt.Sprint(len(tc.message)), func(t *testing.T) {
			wire := []byte(tc.message + "\n")
			for split := 0; split <= len(wire); split++ {
				o := &mihomoSidecarOutput{}
				for _, part := range [][]byte{wire[:split], wire[split:]} {
					if n, err := o.Write(part); n != len(part) || err != nil {
						t.Fatal("diagnostic changed write result")
					}
				}
				if o.finished || o.category != "" {
					t.Fatal("classification published before original Wait")
				}
				o.finish()
				if o.category != tc.category || o.truncated || o.used != 0 || !bytes.Equal(o.buffer[:], make([]byte, mihomoSidecarOutputLimit)) {
					t.Fatal("split message classification or buffer clearing failed")
				}
			}
		})
	}
}

func TestMihomoSidecarOutputPrivacyAndOverflow(t *testing.T) {
	const secret = "private-password UUID /private/config 192.0.2.10"
	for _, wire := range []string{
		"", secret, "Open /private/config failed!", "Parse " + secret + " failed!",
		mihomoOutputTestEnvelope + "socks5 tunnel mtu " + secret,
		"[2026-11-16 12:34:56] [W] socks5 tunnel mtu",
		"[xxxx-xx-xx xx:xx:xx] [E] socks5 tunnel mtu",
		mihomoOutputTestEnvelope + "socks5 tunnel mtu\n" + secret,
		mihomoOutputTestEnvelope + "socks5 tunnel mtu\n" + mihomoOutputTestEnvelope + "socks5 tunnel state\n",
		strings.Repeat("x", mihomoSidecarOutputLimit+1) + mihomoOutputTestEnvelope + "socks5 tunnel mtu\n",
	} {
		o := &mihomoSidecarOutput{}
		if n, err := o.Write([]byte(wire)); n != len(wire) || err != nil || o.used > mihomoSidecarOutputLimit {
			t.Fatal("unknown output did not drain within memory bound")
		}
		o.finish()
		if o.category != "unknown" || o.truncated != (len(wire) > mihomoSidecarOutputLimit) || o.used != 0 {
			t.Fatal("unknown or truncated output became a recognized category")
		}
		if bytes.Contains(o.buffer[:], []byte("private")) {
			t.Fatal("diagnostic retained private output after Wait")
		}
	}
	// An arbitrary strerror suffix is never emitted or interpreted as errno.
	o := &mihomoSidecarOutput{}
	_, _ = o.Write([]byte(mihomoOutputTestEnvelope + "socks5 tunnel open (" + secret + ")\n"))
	o.finish()
	if o.category != "tun-open" || strings.Contains(o.category, "private") || o.used != 0 {
		t.Fatal("strerror suffix escaped fixed classification")
	}
}

func TestMihomoSidecarOutputConcurrentDrain(t *testing.T) {
	o := &mihomoSidecarOutput{}
	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range 100 {
				p := []byte("unrecognized private child output\n")
				if n, err := o.Write(p); n != len(p) || err != nil {
					t.Error("bounded diagnostic changed drain result")
				}
			}
		}()
	}
	writers.Wait()
	o.finish()
	if !o.truncated || o.category != "unknown" || o.used != 0 {
		t.Fatal("concurrent overflow changed closed summary")
	}
	_, _ = o.Write([]byte("late private output"))
	o.finish()
	if o.used != 0 || bytes.Contains(o.buffer[:], []byte("private")) {
		t.Fatal("finished diagnostic retained late output")
	}
}

func TestMihomoSidecarOutputOriginalWaitAndSharedPipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &mihomoLiveSidecar{done: make(chan struct{}), owner: &mihomoLiveResource{}}
	n.self = n
	n.owner.definition.Sidecar.Kind = "hev"
	n.command = exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s\\n' '[2026-11-16 12:34:56] [E] socks5 tunnel mtu' >&2; exit 254")
	mihomoLiveSidecarConfigureOutput(n)
	if n.command.Stdout != n.command.Stderr {
		t.Fatal("diagnostic changed the shared output pipe topology")
	}
	if err := n.command.Start(); err != nil {
		t.Fatal(err)
	}
	n.started = true
	go func() {
		n.waitErr = n.command.Wait()
		n.state = n.command.ProcessState
		mihomoLiveSidecarFinishOutput(n)
		close(n.done)
	}()
	for range 100 {
		mihomoLiveSidecarOutputSummary(n)
	}
	<-n.done
	available, category, truncated := mihomoLiveSidecarOutputSummary(n)
	if !available || category != "tun-mtu" || truncated || n.waitErr == nil || n.state.ExitCode() != 254 {
		t.Fatal("original Wait result or closed diagnostic changed")
	}
	copied := &mihomoLiveSidecar{self: n, started: true, command: n.command, done: n.done}
	if available, _, _ := mihomoLiveSidecarOutputSummary(copied); available {
		t.Fatal("copied owner supplied original output summary")
	}
	n.command = exec.Command("/bin/sh")
	n.owner.definition.Sidecar.Kind = "sing-box"
	mihomoLiveSidecarConfigureOutput(n)
	if n.command.Stdout != io.Discard || n.command.Stderr != io.Discard {
		t.Fatal("HEV diagnostic affected another sidecar")
	}
}

func TestMihomoSidecarOutputPresenceAfterOriginalJoin(t *testing.T) {
	for _, wire := range []string{"", "private unrecognized bytes", strings.Repeat("x", mihomoSidecarOutputLimit+5)} {
		n := &mihomoLiveSidecar{done: make(chan struct{}), started: true, command: exec.Command("unused"), owner: &mihomoLiveResource{}}
		n.self = n
		n.owner.definition.Sidecar.Kind = "hev"
		mihomoLiveSidecarConfigureOutput(n)
		o := n.command.Stdout.(*mihomoSidecarOutput)
		_, _ = o.Write([]byte(wire))
		mihomoLiveSidecarFinishOutput(n)
		if available, count := mihomoLiveSidecarOutputBytes(n); available || count != 0 {
			t.Fatal("count published before original done")
		}
		close(n.done)
		available, count := mihomoLiveSidecarOutputBytes(n)
		if !available || count != min(len(wire), mihomoSidecarOutputLimit) || o.used != 0 || !bytes.Equal(o.buffer[:], make([]byte, mihomoSidecarOutputLimit)) {
			t.Fatal("bounded count or raw zeroing changed")
		}
		if _, category, _ := mihomoLiveSidecarOutputSummary(n); category != "unknown" {
			t.Fatal("presence invented a startup cause")
		}
	}
}
