//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Actual original journal FDs/rename metadata. The process/scope here is only
// a comparison model, never a native standby or writer capability fixture.
func domainTCPGlobalHistoryFixture(t *testing.T) (*domainTCPGlobalHistory, context.Context) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-original")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	record := Execution{PlanID: "dp-check-" + strings.Repeat("a", 32), Digest: strings.Repeat("a", 64), State: "resource-failed"}
	raw, _ := json.Marshal(record)
	file, err := writeDataplaneJournalRetained(filepath.Join(root, "latest-execution.json"), raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	d := &xraySelectedTCPExecutionRecords{}
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.root.Close() })
	p := &XrayDomainTCPExecutionResource{scope: &executionResourceScope{managerRoot: root}, records: d}
	p.self = p
	owner := &domainTCPStandbyOwner{process: p, latest: file, latestInfo: info}
	owner.self = owner
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	b, err := borrowDomainTCPGlobalHistory(ctx, owner, record)
	if err != nil {
		t.Fatal(err)
	}
	return b, ctx
}

// A test-only synchronization context reports its real parent's cancellation.
// It changes an actual private file only AFTER the FD read's closing metadata,
// forcing the constructor's reviewed-record bookend to observe that change.
type domainGlobalClosingWitness struct {
	context.Context
	once        sync.Once
	directCalls atomic.Int32
	change      func()
}

func (c *domainGlobalClosingWitness) Err() error {
	err := c.Context.Err()
	pc, _, _, ok := runtime.Caller(1)
	if ok {
		fn := runtime.FuncForPC(pc)
		if fn != nil && strings.HasSuffix(fn.Name(), "(*domainTCPGlobalHistory).currentFile") {
			// The first direct call is its cancellation preflight; the second
			// is the closing call after the actual FD/byte metadata bookends.
			if c.directCalls.Add(1) == 2 {
				c.once.Do(c.change)
			}
		}
	}
	return err
}

func TestDomainGlobalHistoricalFDRequiresReviewedBodyAtClosingBorrow(t *testing.T) {
	b, ctx := domainTCPGlobalHistoryFixture(t)
	path := filepath.Join(b.rootPath, "latest-execution.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record Execution
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte("resource-failed"), []byte("resource-failEd"), 1)
	if bytes.Equal(raw, changed) || len(raw) != len(changed) {
		t.Fatal("invalid same-length witness")
	}
	fired := false
	var mutationErr error
	witness := &domainGlobalClosingWitness{Context: ctx}
	witness.change = func() {
		fired = true
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			mutationErr = err
			return
		}
		_, writeErr := file.WriteAt(changed, 0)
		mutationErr = errors.Join(writeErr, file.Close(), os.Chtimes(path, b.original.ModTime(), b.original.ModTime()))
	}
	borrowed, err := borrowDomainTCPGlobalHistory(witness, b.owner, record)
	if !fired || mutationErr != nil {
		t.Fatal("actual closing witness did not run", fired, mutationErr)
	}
	if borrowed != nil || !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("unreviewed actual bytes became a frozen successor anchor", err)
	}
}

func TestDomainGlobalHistoricalFDRequiresOriginalRenameAndFrozenBytes(t *testing.T) {
	for _, change := range []string{"none", "before-rename", "wrong-new-FD", "in-place", "root-replaced", "owner-FD-rebound", "canceled"} {
		t.Run(change, func(t *testing.T) {
			b, ctx := domainTCPGlobalHistoryFixture(t)
			if b.currentHistorical(ctx) == nil {
				t.Fatal("unsealed global became historical")
			}
			if change == "before-rename" {
				if b.sealOriginalRename(ctx, b.file) == nil {
					t.Fatal("same global FD admitted as successor")
				}
				return
			}
			produced, err := b.root.WriteAtomicRetained("latest-execution.json", []byte(`{"actual_new_writer":true}`), 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer produced.Close()
			if change == "wrong-new-FD" {
				wrong, err := b.root.WriteAtomicRetained("other.json", []byte("other original file"), 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer wrong.Close()
				if b.sealOriginalRename(ctx, wrong) == nil {
					t.Fatal("foreign named FD sealed history")
				}
				return
			}
			if err := b.sealOriginalRename(ctx, produced); err != nil {
				t.Fatal(err)
			}
			if err := b.currentHistorical(ctx); err != nil {
				t.Fatal("actual original FD rename transition refused", err)
			}
			switch change {
			case "in-place":
				writable, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(b.file.Fd())), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writable.WriteAt([]byte("X"), 0); err != nil {
					t.Fatal(err)
				}
				if err := writable.Close(); err != nil {
					t.Fatal(err)
				}
			case "root-replaced":
				if err := os.Rename(b.rootPath, b.rootPath+".old"); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(b.rootPath + ".old")
				if err := os.Mkdir(b.rootPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "owner-FD-rebound":
				b.owner.latestMu.Lock()
				b.owner.latest = produced
				b.owner.latestMu.Unlock()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = b.currentHistorical(ctx)
			if (err == nil) != (change == "none") {
				t.Fatal("historical original source changed", change, err)
			}
		})
	}
}
