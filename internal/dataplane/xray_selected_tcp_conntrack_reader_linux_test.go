//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual Linux FD reads of real fixture files. No fake procfs/provider or
// execution owner is issued; this tests the bounded reader, not native routing.
func TestXraySelectedTCPConntrackReaderReadsExistingEmptyAndWholeTable(t *testing.T) {
	spec := xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64))
	row := "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.40 dst=1.1.1.1 sport=52000 dport=443 src=192.168.1.1 dst=192.168.1.40 sport=16443 dport=52000 [ASSURED] mark=0 use=1\n"
	for _, content := range []string{"", row} {
		t.Run(map[bool]string{true: "empty", false: "selected-flow"}[content == ""], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nf_conntrack")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := xraySelectedTCPReadFD(ctx, int(file.Fd()), xraySelectedTCPConntrackLimit); !errors.Is(err, errXraySelectedTCPRuntime) {
				t.Fatal("ordinary proc reader unexpectedly widened its 8 MiB bound", err)
			}
			data, err := xraySelectedTCPReadConntrackFD(ctx, int(file.Fd()))
			if err != nil || string(data) != content {
				t.Fatal("existing file refused before actual whole FD read", err)
			}
			settled := xraySelectedTCPConntrackSettled(data, false, spec)
			if content == "" && settled != nil || content != "" && !errors.Is(settled, ErrXraySelectedTCPConntrackPending) {
				t.Fatal("whole-table result changed", settled)
			}
		})
	}
}

func TestXraySelectedTCPConntrackReaderOverflowAndMissingRemainUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	file, err := os.CreateTemp(t.TempDir(), "nf_conntrack-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(xraySelectedTCPConntrackLimit + 1); err != nil {
		t.Fatal(err)
	}
	if data, err := xraySelectedTCPReadConntrackFD(ctx, int(file.Fd())); !errors.Is(err, errXraySelectedTCPRuntime) || data != nil {
		t.Fatal("bounded prefix supplied whole-table absence", len(data), err)
	}
	if data, err := xraySelectedTCPReadConntrackFD(ctx, -1); !errors.Is(err, errXraySelectedTCPRuntime) || data != nil {
		t.Fatal("missing descriptor supplied empty-table success", data, err)
	}
	if _, err := os.Open(filepath.Join(t.TempDir(), "missing-nf_conntrack")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing-file fixture unexpectedly exists", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if data, err := xraySelectedTCPReadConntrackFD(canceled, int(file.Fd())); !errors.Is(err, errXraySelectedTCPRuntime) || data != nil {
		t.Fatal("canceled reader supplied empty-table success", data, err)
	}
}
