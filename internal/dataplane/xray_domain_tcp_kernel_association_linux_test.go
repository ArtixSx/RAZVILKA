//go:build linux

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"golang.org/x/sys/unix"
)

// Ordinary Go test children and actual procfs/FD comparisons only. These
// children cannot satisfy the fixed Xray argv/version, original DNS material,
// typed scope/map/journal or domain read-interval issuer. No native readiness.
func TestXrayDomainTCPKernelAssociationsRejectChangeBehindLocalDescriptors(t *testing.T) {
	for _, changed := range []string{"missing-fd4", "different-fd4", "exec-argv"} {
		t.Run(changed, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := ownedfs.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			data := []byte("same-config-bytes-in-two-original-files")
			original, err := root.WriteAtomicRetained("original", data, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			replacement, err := root.WriteAtomicRetained("replacement", data, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer replacement.Close()
			originalInfo, err := original.Stat()
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			executableFile, err := os.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
			defer executableFile.Close()
			executableInfo, err := executableFile.Stat()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestXrayDomainTCPKernelAssociationHelper$")
			cmd.Env = append(os.Environ(), "RAZVILKA_DOMAIN_FD4_HELPER="+changed, "RAZVILKA_DOMAIN_FD4_AFTER_EXEC=0")
			cmd.ExtraFiles = []*os.File{original, original, replacement} // Actual inherited FD3/4/5.
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = stdin.Close()
				_ = cmd.Process.Kill() // This SAME ordinary test child only.
				_ = cmd.Wait()         // Its sole actual Wait, including failure paths.
			}()
			output := bufio.NewScanner(stdout)
			read := func(want string) {
				t.Helper()
				if !output.Scan() || output.Text() != want {
					t.Fatalf("ordinary helper handshake: want %q, error %v", want, output.Err())
				}
			}
			read("ready")
			proc, err := openXraySelectedTCPProc(ctx, cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			defer proc.close()
			// Keep a LOCAL duplicated FD4 open across the child's mutation.
			directory, err := proc.open(ctx, proc.child, "fd", true)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(directory)
			fd, err := unix.Openat(directory, "4", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			local := os.NewFile(uintptr(fd), "[local original test FD4 duplicate]")
			defer local.Close()
			openingConfig, err := proc.domainConfigFDInfo(ctx)
			if err != nil || !sameXrayDomainTCPFile(originalInfo, openingConfig) {
				t.Fatal("actual opening FD4 association failed", err)
			}
			network, err := netidentity.NewProcProvider().Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			openingImage, err := proc.domainKernelImage(ctx, network)
			if err != nil || !openingImage.matches(cmd.Args, executable, executableInfo) {
				t.Fatal("actual opening image comparison failed", err)
			}
			openingStat, err := proc.read(ctx, proc.child, "stat", 8192)
			start, parent, group, parseErr := xraySelectedTCPStat(openingStat, cmd.Process.Pid)
			if err != nil || parseErr != nil {
				t.Fatal(err, parseErr)
			}
			if _, err := io.WriteString(stdin, "change\n"); err != nil {
				t.Fatal(err)
			}
			read("changed")
			localInfo, err := local.Stat()
			localBytes := make([]byte, len(data))
			count, readErr := local.ReadAt(localBytes, 0)
			if err != nil || !sameXrayDomainTCPFile(originalInfo, localInfo) || readErr != nil || count != len(data) || !bytes.Equal(localBytes, data) {
				t.Fatal("local descriptor did not retain the unchanged original config", err, readErr)
			}
			closingStat, err := proc.read(ctx, proc.child, "stat", 8192)
			closeStart, closeParent, closeGroup, parseErr := xraySelectedTCPStat(closingStat, cmd.Process.Pid)
			if err != nil || parseErr != nil || closeStart != start || closeParent != parent || closeGroup != group || proc.current(ctx) != nil {
				t.Fatal("test mutation changed the stat/proc association instead of exposing its gap", err, parseErr)
			}
			if changed == "exec-argv" {
				closingImage, err := proc.domainKernelImage(ctx, network)
				heldExecutable, heldErr := executableFile.Stat()
				if err != nil || heldErr != nil || !sameXrayDomainTCPFile(executableInfo, heldExecutable) || !sameXrayDomainTCPFile(executableInfo, closingImage.executable) || openingImage.same(closingImage) || closingImage.matches(cmd.Args, executable, executableInfo) {
					t.Fatal("same-image exec argv drift supplied the opening image", err)
				}
			} else {
				closingConfig, err := proc.domainConfigFDInfo(ctx)
				if err == nil && sameXrayDomainTCPFile(originalInfo, closingConfig) {
					t.Fatal("local original duplicate hid missing/replaced child FD4")
				}
				if changed == "different-fd4" && err != nil {
					t.Fatal("replacement comparison failed before observing its different inode", err)
				}
			}
		})
	}
}

func TestXrayDomainTCPKernelAssociationHelper(t *testing.T) {
	mode := os.Getenv("RAZVILKA_DOMAIN_FD4_HELPER")
	if mode == "" {
		return
	}
	if os.Getenv("RAZVILKA_DOMAIN_FD4_AFTER_EXEC") == "1" {
		fmt.Println("changed")
	} else {
		fmt.Println("ready")
	}
	commands := bufio.NewScanner(os.Stdin)
	for commands.Scan() {
		switch commands.Text() {
		case "change":
			switch mode {
			case "missing-fd4":
				if err := unix.Close(4); err != nil {
					t.Fatal(err)
				}
			case "different-fd4":
				if err := unix.Dup3(5, 4, 0); err != nil {
					t.Fatal(err)
				}
			case "exec-argv":
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Exec(executable, []string{executable, "-test.run=^TestXrayDomainTCPKernelAssociationHelper$", "--", "changed-child-argv"}, append(os.Environ(), "RAZVILKA_DOMAIN_FD4_AFTER_EXEC=1")); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("unknown ordinary helper mutation")
			}
			fmt.Println("changed")
		case "quit":
			return
		default:
			t.Fatal("unknown ordinary helper command")
		}
	}
	if err := commands.Err(); err != nil {
		t.Fatal(err)
	}
}
