//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual native JSON ingestion with the same command constructor used by the
// original selected-TCP and domain publishers. Admission is an explicit model;
// this does not certify Manager Apply, policy effects or router/client routing.
func TestXraySelectedTCPNativeHeldJSONConfig(t *testing.T) {
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if binary == "" {
		t.Skip("isolated actual Xray required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute Xray required")
	}
	if os.Getenv("RAZVILKA_XRAY_SELECTED_NATIVE_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--fork", os.Args[0], "-test.run=^TestXraySelectedTCPNativeHeldJSONConfig$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_XRAY_SELECTED_NATIVE_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated selected native: %v %s", err, output)
		}
		t.Log(string(output))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "192.168.1.1/32", "dev", "lo"}} {
		if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated LAN listener address: %v %s", err, output)
		}
	}
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "192.168.1.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	listener.Close()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "inbounds": []any{map[string]any{"listen": endpoint.Addr().String(), "port": endpoint.Port(), "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "blackhole"}}})
	config, err := root.WriteAtomicRetained("xray-redirect.json", data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	executable, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	log, err := root.OpenFile("native-fixture.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd, err := xrayHeldJSONCommand(binary, directory, executable, config, log)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reserveXraySelectedTCPProcessWait(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		p.abandonUnstartedWait()
		t.Fatal(err)
	}
	if err := p.acknowledgeStart(); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(err)
	}
	defer func() {
		if !p.waitStarted {
			p.beginReservedWait()
		}
		p.child.Signal(syscall.SIGTERM)
		cleanup, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := p.Joined(cleanup); err != nil {
			p.child.Kill()
			t.Error(p.Joined(cleanup))
		}
	}()
	if err := p.beginReservedWait(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = p.observeListener(ctx, provider, identity, endpoint); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual selected listener", err)
		case <-p.done:
			output, _ := root.ReadLimited("native-fixture.log", 8192)
			t.Fatal("actual selected Xray exited", string(output))
		case <-time.After(25 * time.Millisecond):
		}
	}
	cmd.Stdin = nil
	if _, err := p.observe(ctx, provider, identity); err == nil {
		t.Fatal("changed original stdin command binding accepted")
	}
	cmd.Stdin = config
	if _, err := p.observe(ctx, provider, identity); err != nil {
		t.Fatal("restored original command association", err)
	}
	if err := root.WriteAtomic("xray-redirect.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.observe(ctx, provider, identity); err == nil {
		t.Fatal("same-byte named config replacement adopted")
	}
	t.Log("actual native JSON stdin+FD4, verified listener, exact command binding, inode replacement refusal and sole Wait; admission modeled")
}
