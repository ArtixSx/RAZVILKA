//go:build linux

package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWGInactivityProcessInventoryUsesExecutableAndExactWrapper(t *testing.T) {
	for _, cut := range []string{"unrelated", "spoofed-argv", "owned-wrapper", "shell-command", "unreadable-exe", "empty-inventory", "kernel-thread"} {
		t.Run(cut, func(t *testing.T) {
			root := t.TempDir()
			if cut != "empty-inventory" {
				dir := filepath.Join(root, "123")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				command := []byte("daemon\x00")
				exe := "/usr/bin/daemon"
				if cut == "spoofed-argv" {
					exe = "/opt/bin/wireguard-go"
				}
				if cut == "owned-wrapper" {
					exe = "/bin/sh"
					command = []byte("sh\x00/opt/bin/wg-quick\x00down\x00/opt/private/rz-wg.conf\x00")
				}
				if cut == "shell-command" {
					exe = "/bin/sh"
					command = []byte("sh\x00-c\x00/opt/bin/wg-quick up /opt/private/rz-wg.conf\x00")
				}
				if cut == "kernel-thread" {
					command = nil
				}
				if cut != "unreadable-exe" && cut != "kernel-thread" {
					if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(dir, "cmdline"), command, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyWGProcessesInactiveAt(context.Background(), root, []string{"rz-wg", "rz-wg-canary"})
			if cut == "unrelated" || cut == "kernel-thread" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("partial or owned process inventory accepted", cut)
			}
		})
	}
}
