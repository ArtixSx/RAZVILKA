package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var errExactNodeRemoval = errors.New("exact node checker cleanup or listener absence is unconfirmed")

// The canonical uninstaller has stopped the panel before this removal-only
// command. Recover retains the existing protected PID/spec cleanup authority;
// socket inventory can only refuse removal, never authorize a signal.
func recoverExactNodeCheckersForRemoval(ctx context.Context, root string, removal bool) error {
	if !removal {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errExactNodeRemoval
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return errExactNodeRemoval
	}
	dispatch, _, err := configuredNodeCheckers(root)
	if err != nil {
		return errExactNodeRemoval
	}
	return settleExactNodeRemoval(ctx, dispatch.Recover, readExactNodeRemovalProc, func(c context.Context, port int, inodes []string) bool {
		return exactNodeRemovalOwnedListener(c, root, port, inodes)
	}, exactNodeIPv6Unavailable)
}

func exactNodeRemovalOwnedListener(ctx context.Context, root string, port int, inodes []string) bool {
	if port < 19181 || port >= 19181+2*dataplane.MaxExactNodeSlots {
		return false
	}
	engine, slot := "node-check", port-19181
	if slot >= dataplane.MaxExactNodeSlots {
		engine, slot = "node-check-xray", slot-dataplane.MaxExactNodeSlots
	}
	dir := filepath.Join(root, engine)
	if slot > 0 {
		dir = filepath.Join(dir, "slot-"+strconv.Itoa(slot))
	}
	owned, err := ownedfs.Open(dir)
	if err != nil {
		return false
	}
	defer owned.Close()
	raw, err := owned.ReadLimited("engine.pid", 64)
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || parseErr != nil || pid <= 1 || string(raw) != strconv.Itoa(pid)+"\n" || ctx.Err() != nil {
		return false
	}
	receiptRaw, err := owned.ReadLimited("engine.pid"+routeidentity.ReceiptSuffix, 4096)
	var receipt routeidentity.Receipt
	if err != nil || json.Unmarshal(receiptRaw, &receipt) != nil || receipt.PID != pid || len(inodes) == 0 {
		return false
	}
	flag, binary := "-c", "sing-box"
	if engine == "node-check-xray" {
		flag, binary = "-config", "xray"
	}
	if filepath.Base(receipt.Executable) != binary {
		return false
	}
	verify := func() bool {
		// Match OSProcessController.Start's 8 MiB config limit before the
		// shared capture's plain ReadFile. In particular, never open a FIFO.
		info, err := owned.Stat("engine.json")
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 8<<20 || ctx.Err() != nil {
			return false
		}
		// This read-only capture must equal the ORIGINAL producer receipt.
		// It is never saved as a replacement receipt or a new cleanup grant.
		current, err := routeidentity.RecordStart(pid, receipt.Executable, []string{"run", flag, filepath.Join(dir, "engine.json")}, filepath.Join(dir, "engine.json"), receipt.ConfigHash)
		return err == nil && bytes.Equal(current, receiptRaw) && ctx.Err() == nil
	}
	if !verify() {
		return false
	}
	fdRoot := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdRoot)
	if err != nil || len(entries) == 0 || len(entries) > 4096 {
		return false
	}
	found := map[string]bool{}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdRoot, entry.Name()))
		if err != nil || ctx.Err() != nil {
			return false
		}
		found[link] = true
	}
	for _, inode := range inodes {
		if !found["socket:["+inode+"]"] {
			return false
		}
	}
	closingPID, e1 := owned.ReadLimited("engine.pid", 64)
	closingReceipt, e2 := owned.ReadLimited("engine.pid"+routeidentity.ReceiptSuffix, 4096)
	return e1 == nil && e2 == nil && bytes.Equal(raw, closingPID) && bytes.Equal(receiptRaw, closingReceipt) && verify()
}

func settleExactNodeRemoval(parent context.Context, recover func(context.Context) error, read func(context.Context, string) ([]byte, error), owner func(context.Context, int, []string) bool, noIPv6 func() bool) error {
	if parent == nil || parent.Err() != nil || recover == nil || read == nil || owner == nil || noIPv6 == nil {
		return errExactNodeRemoval
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	for pass := 0; pass < 2; pass++ {
		for _, table := range []struct {
			path  string
			width int
		}{{"/proc/net/tcp", 8}, {"/proc/net/tcp6", 32}} {
			raw, err := read(ctx, table.path)
			if table.width == 32 && errors.Is(err, os.ErrNotExist) && noIPv6() && ctx.Err() == nil {
				continue
			}
			ports, parseErr := exactNodeListenerPorts(raw, table.width)
			if err != nil || ctx.Err() != nil || parseErr != nil {
				return errExactNodeRemoval
			}
			for port, inodes := range ports {
				if pass == 1 || !owner(ctx, port, inodes) {
					return errExactNodeRemoval
				}
			}
		}
		if pass == 0 {
			if err := recover(ctx); err != nil || ctx.Err() != nil {
				return errExactNodeRemoval
			}
		}
	}
	return ctx.Err()
}

func readExactNodeRemovalProc(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err // Missing IPv6 inventory is not an absence certificate.
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || ctx.Err() != nil {
		return nil, errExactNodeRemoval
	}
	return raw, nil
}

func exactNodeListenerPorts(raw []byte, width int) (map[int][]string, error) {
	portsFound := map[int][]string{}
	if len(raw) == 0 || len(raw) > 1<<20 || raw[len(raw)-1] != '\n' || width != 8 && width != 32 || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, errExactNodeRemoval
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 8192 {
		return nil, errExactNodeRemoval
	}
	header := strings.Fields(lines[0])
	if len(header) != 12 || header[0] != "sl" || header[1] != "local_address" ||
		header[2] != "rem_address" && header[2] != "remote_address" ||
		strings.Join(header[3:], " ") != "st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode" {
		return nil, errExactNodeRemoval
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 10 || len(f) > 32 || !strings.HasSuffix(f[0], ":") {
			return nil, errExactNodeRemoval
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 10, 32); err != nil {
			return nil, errExactNodeRemoval
		}
		ports := [2]uint64{}
		for i, endpoint := range f[1:3] {
			parts := strings.Split(endpoint, ":")
			if len(parts) != 2 || len(parts[0]) != width || len(parts[1]) != 4 {
				return nil, errExactNodeRemoval
			}
			for _, digit := range parts[0] {
				if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
					return nil, errExactNodeRemoval
				}
			}
			port, err := strconv.ParseUint(parts[1], 16, 16)
			if err != nil {
				return nil, errExactNodeRemoval
			}
			ports[i] = port
		}
		state, e1 := strconv.ParseUint(f[3], 16, 8)
		inode, e2 := strconv.ParseUint(f[9], 10, 64)
		if len(f[3]) != 2 || e1 != nil || e2 != nil || state == 0 || state > 12 || state == 0x0a && inode == 0 {
			return nil, errExactNodeRemoval
		}
		for i, sizes := range [][2]int{{8, 8}, {2, 8}} {
			parts := strings.Split(f[4+i], ":")
			if len(parts) != 2 {
				return nil, errExactNodeRemoval
			}
			for j, part := range parts {
				if _, err := strconv.ParseUint(part, 16, 32); err != nil || len(part) != sizes[j] {
					return nil, errExactNodeRemoval
				}
			}
		}
		for i, base := range []int{16, 10, 10} {
			if _, err := strconv.ParseUint(f[6+i], base, 64); err != nil {
				return nil, errExactNodeRemoval
			}
		}
		if state == 0x0a && ports[0] >= 19181 && ports[0] < 19181+2*dataplane.MaxExactNodeSlots {
			portsFound[int(ports[0])] = append(portsFound[int(ports[0])], f[9])
		}
	}
	return portsFound, nil
}
