//go:build linux

package routeidentity

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Uses real procfs and an ephemeral loopback listener, never a system service,
// firewall rule or external destination. CI exercises the host-endian parser.
func TestLiveProcfsOwnership(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	inode, err := listenerInode(systemProc(), os.Getpid(), listener.Addr().String())
	if err != nil || inode == "" {
		t.Fatalf("live listener ownership: %s %v", inode, err)
	}
	config := filepath.Join(t.TempDir(), "engine.json")
	data := []byte(`{"test":true}`)
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordStart(os.Getpid(), os.Args[0], os.Args[1:], config, Hash(data)); err != nil {
		t.Fatalf("live process identity: %v", err)
	}
	if _, err := RecordStart(os.Getpid(), os.Args[0], os.Args[1:], config, Hash([]byte("old"))); err == nil {
		t.Fatal("config drift accepted")
	}
}
