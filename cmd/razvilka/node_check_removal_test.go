package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

const removalTCPHeader = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func removalTCPRow(width, port int, state string) string {
	return fmt.Sprintf("0: %s:%04X %s:0000 %s 00000000:00000000 00:00000000 00000000 0 0 991 1\n", strings.Repeat("0", width), port, strings.Repeat("0", width), state)
}

func TestExactNodeRemovalListenerInventoryIsClosed(t *testing.T) {
	for _, width := range []int{8, 32} {
		for _, port := range []int{19180, 19181, 19182, 19184, 19185, 19188, 19189} {
			for _, state := range []string{"0A", "01", "06"} {
				raw := []byte(removalTCPHeader + removalTCPRow(width, port, state))
				ports, err := exactNodeListenerPorts(raw, width)
				want := state == "0A" && port >= 19181 && port <= 19188
				if err != nil || (len(ports[port]) > 0) != want || len(ports) != map[bool]int{true: 1, false: 0}[want] {
					t.Fatal("wrong reserved listener classification", width, port, state, ports, err)
				}
			}
		}
	}
	valid := removalTCPHeader + removalTCPRow(8, 80, "0A")
	for _, raw := range []string{"", "unknown\n", strings.TrimSuffix(valid, "\n"), strings.Replace(valid, "00000000:00000000", "invalid", 1), strings.Replace(valid, "991", "inode", 1), strings.Replace(valid, "991", "0", 1), strings.Replace(valid, "00000000:0050", "ZZ000000:0050", 1), valid + "truncated\n", valid + "\x00\n", strings.Repeat("x", (1<<20)+1)} {
		if _, err := exactNodeListenerPorts([]byte(raw), 8); err == nil {
			t.Fatal("malformed inventory accepted")
		}
	}
}

func TestExactNodeRemovalRecoveryOrderingAndRefusal(t *testing.T) {
	for _, mode := range []string{"owned", "empty", "missing-pid", "foreign-inode", "cleanup-failed", "surviving-listener", "missing-ipv6", "ipv6-unsupported", "malformed", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			retained := filepath.Join(t.TempDir(), "engine.pid.identity.json")
			if err := os.WriteFile(retained, []byte("retained original evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			recovered, reads := false, 0
			err := settleExactNodeRemoval(ctx, func(c context.Context) error {
				if reads != 2 {
					t.Fatal("recovery preceded complete preflight")
				}
				if deadline, ok := c.Deadline(); !ok || time.Until(deadline) > 45*time.Second {
					t.Fatal("unbounded cleanup")
				}
				recovered = true
				if err := os.Remove(retained); err != nil {
					t.Fatal(err)
				}
				if mode == "cleanup-failed" {
					return errors.New("original cleanup refused")
				}
				return nil
			}, func(_ context.Context, path string) ([]byte, error) {
				reads++
				if (mode == "missing-ipv6" || mode == "ipv6-unsupported") && strings.HasSuffix(path, "tcp6") {
					return nil, os.ErrNotExist
				}
				if mode == "malformed" {
					return []byte("unknown\n"), nil
				}
				if mode == "canceled" {
					cancel()
				}
				raw := removalTCPHeader
				if strings.HasSuffix(path, "tcp") && mode != "empty" && (!recovered || mode == "surviving-listener") {
					raw += removalTCPRow(8, 19182, "0A")
				}
				return []byte(raw), nil
			}, func(_ context.Context, port int, inodes []string) bool {
				if port != 19182 || recovered || len(inodes) != 1 || inodes[0] != "991" {
					t.Fatal("PID presence treated as post-cleanup authority")
				}
				return mode != "missing-pid" && mode != "foreign-inode"
			}, func() bool { return mode == "ipv6-unsupported" })
			if (err == nil) != (mode == "owned" || mode == "empty" || mode == "ipv6-unsupported") {
				t.Fatal("wrong retirement admission", mode, err)
			}
			if (mode == "missing-pid" || mode == "foreign-inode" || mode == "missing-ipv6" || mode == "malformed" || mode == "canceled") && recovered {
				t.Fatal("uncertain preflight destroyed retained cleanup metadata")
			}
			if !recovered {
				raw, readErr := os.ReadFile(retained)
				if readErr != nil || string(raw) != "retained original evidence" {
					t.Fatal("denied preflight lost original evidence", readErr)
				}
			}
			if mode == "cleanup-failed" && reads != 2 {
				t.Fatal("cleanup failure continued toward retirement")
			}
		})
	}
}

func TestExactNodeRemovalOrdinaryDeactivateDoesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	if err := recoverExactNodeCheckersForRemoval(nil, root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ordinary deactivate constructed checker state", err)
	}
}

func TestExactNodeRemovalPIDAloneNeverGrantsAdmission(t *testing.T) {
	root := t.TempDir()
	for port := 19181; port <= 19188; port++ {
		slot, engine := port-19181, "node-check"
		if slot >= 4 {
			slot, engine = slot-4, "node-check-xray"
		}
		dir := filepath.Join(root, engine)
		if slot != 0 {
			dir = filepath.Join(dir, fmt.Sprint("slot-", slot))
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "engine.pid")
		if err := os.WriteFile(path, []byte("77\n"), 0600); err != nil || exactNodeRemovalOwnedListener(context.Background(), root, port, []string{"991"}) {
			t.Fatal("PID alone granted removal admission", port, err)
		}
		if err := os.WriteFile(path, []byte("077\n"), 0600); err != nil || exactNodeRemovalOwnedListener(context.Background(), root, port, []string{"991"}) {
			t.Fatal("noncanonical PID accepted", port, err)
		}
	}
	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(root, "node-check", "engine.pid")
		target := filepath.Join(root, "foreign-pid")
		if err := os.WriteFile(target, []byte("77\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skip("symlinks unavailable on this host")
		}
		if exactNodeRemovalOwnedListener(context.Background(), root, 19181, []string{"991"}) {
			t.Fatal("linked PID file granted preflight admission")
		}
	})
}

func TestExactNodeRemovalNativeRetainedChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native managed child cleanup requires Linux procfs")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	available, err := net.Listen("tcp4", "127.0.0.1:19182")
	if err != nil {
		t.Skip("reserved native test port is already in use")
	}
	_ = available.Close()
	// A private copy has the same executable/argv shape as the real checker.
	binary := filepath.Join(root, "sing-box")
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, source)
	source.Close()
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy private child fixture", copyErr, closeErr)
	}
	dir := filepath.Join(root, "node-check", "slot-1")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(config, []byte(`{"outbounds":[{"type":"vless","server":"node.example","server_port":443}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	spec := dataplane.ProcessSpec{ID: "node-check-sing-box-1", Binary: binary, Args: []string{"run", "-c", config}, Dir: dir, PIDPath: filepath.Join(dir, "engine.pid"), LogPath: filepath.Join(dir, "engine.log"), MatchArg: config, RouteProof: true}
	controller := dataplane.OSProcessController{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := controller.Start(ctx, spec); err != nil {
		t.Fatal(err)
	}
	pidRaw, err := os.ReadFile(spec.PIDPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(context.Background(), spec) })
	for {
		raw, err := readExactNodeRemovalProc(ctx, "/proc/net/tcp")
		ports, parseErr := exactNodeListenerPorts(raw, 8)
		if err == nil && parseErr == nil && len(ports[19182]) > 0 && exactNodeRemovalOwnedListener(ctx, root, 19182, ports[19182]) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("native child did not establish retained listener ownership")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A stale valid PID cannot explain someone else's observed listener inode.
	receiptBefore, err := os.ReadFile(spec.PIDPath + ".identity.json")
	if err != nil {
		t.Fatal(err)
	}
	if exactNodeRemovalOwnedListener(ctx, root, 19182, []string{"1"}) {
		t.Fatal("foreign inode admitted by valid retained PID")
	}
	if err := settleExactNodeRemoval(ctx, func(context.Context) error {
		t.Fatal("foreign listener reached recovery and could erase original receipt")
		return nil
	}, func(c context.Context, path string) ([]byte, error) {
		if strings.HasSuffix(path, "tcp") {
			return []byte(strings.Replace(removalTCPHeader+removalTCPRow(8, 19182, "0A"), "991", "1", 1)), nil
		}
		return readExactNodeRemovalProc(c, path)
	}, func(c context.Context, port int, inodes []string) bool {
		return exactNodeRemovalOwnedListener(c, root, port, inodes)
	}, exactNodeIPv6Unavailable); err == nil {
		t.Fatal("stale valid PID explained a foreign listener")
	}
	receiptAfter, err := os.ReadFile(spec.PIDPath + ".identity.json")
	if err != nil || string(receiptBefore) != string(receiptAfter) || !controller.Running(spec) {
		t.Fatal("foreign inode refusal changed original ownership", err)
	}
	// Exercise the actual removal wrapper with a relative state root. Its
	// recovery constructor and ownership observation must use the same root.
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeRoot, err := filepath.Rel(cwd, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverExactNodeCheckersForRemoval(ctx, relativeRoot, true); err != nil {
		t.Fatal("retained child did not retire", err)
	}
	if controller.Running(spec) {
		t.Fatal("original managed child survived recovery")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original child was not reaped after canonical recovery")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, path := range []string{spec.PIDPath, spec.PIDPath + ".identity.json", config, spec.LogPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("settled original session retained live artifacts", err)
		}
	}
}

func init() {
	if len(os.Args) != 4 || filepath.Base(os.Args[0]) != "sing-box" || os.Args[1] != "run" || os.Args[2] != "-c" {
		return
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	listener, err := net.Listen("tcp4", "127.0.0.1:19182")
	if err != nil {
		os.Exit(97)
	}
	<-interrupt
	_ = listener.Close()
	os.Exit(0)
}
