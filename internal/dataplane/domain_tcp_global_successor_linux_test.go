//go:build linux

package dataplane

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual FD/rename/durability comparison only. The old model has no native
// standby/kernel source, so this fixture cannot call publish or issue a flow.
func TestDomainGlobalSuccessorRecoversOnlyAcceptedOriginalFD(t *testing.T) {
	for _, change := range []string{"none", "foreign-latest", "old-bytes", "copied-cursor", "missing-capture"} {
		t.Run(change, func(t *testing.T) {
			old, ctx := domainTCPGlobalHistoryFixture(t)
			m := New(old.rootPath)
			plan := domainTCPProofPlanModel(t)
			e := &Execution{PlanID: "dp-check-" + strings.Repeat("f", 32), ResourcePlanID: plan.PlanID, Digest: plan.Digest, State: "checking"}
			root := filepath.Join(m.StateRoot, "transactions", e.PlanID)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			s := &executionResourceScope{manager: m, managerRoot: m.StateRoot, root: root, plan: plan, execution: e}
			records, err := newXraySelectedTCPRecords(s)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = records.close() })
			pool := &domainTCPStandbyPool{manager: m, entries: []*domainTCPStandbyPoolEntry{{history: old}}}
			pool.self = pool
			m.domainPool = pool
			c := &domainTCPGlobalSuccessor{pool: pool, scope: s, records: records, pending: true}
			c.self = c
			s.domainSuccessor = c
			pool.successor = c
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if err := records.publishOriginalDurable(0, raw, syncDataplaneJournalDirectory); err != nil {
				t.Fatal(err)
			}
			lostACK := errors.New("lost durability ACK after actual capture")
			err = records.publishOriginalDurable(1, raw, func(dir *ownedfs.Root) error {
				c.globalAccepted = true
				return errors.Join(syncDataplaneJournalDirectory(dir), lostACK)
			})
			if !errors.Is(err, lostACK) {
				t.Fatal("fixture did not retain actual authored FD before refusal", err)
			}
			switch change {
			case "foreign-latest":
				if err := records.root.WriteAtomic("latest-execution.json", raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "old-bytes":
				// Unlinked original inode remains writable only through its exact
				// original descriptor; this models concurrent byte corruption.
				w, err := os.OpenFile(filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(old.file.Fd()), 10)), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := w.WriteAt([]byte("!"), 0)
				closeErr := w.Close()
				if err := errors.Join(writeErr, closeErr); err != nil {
					t.Fatal(err)
				}
			case "copied-cursor":
				c.self = &domainTCPGlobalSuccessor{}
			case "missing-capture":
				c.globalAccepted = false
			}
			err = c.sealAcceptedGlobal(ctx)
			if change != "none" {
				if err == nil {
					t.Fatal("foreign/unauthored transition became sealed", change)
				}
				return
			}
			if err != nil {
				t.Fatal("same accepted FD could not finish original rename proof", err)
			}
			if !c.pending {
				t.Fatal("file proof created forward admission without native owners")
			}
			if err := c.sealAcceptedGlobal(ctx); err != nil {
				t.Fatal("same sealed cursor retry lost original FD", err)
			}
			if err := old.currentHistorical(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
