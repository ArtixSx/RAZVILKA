//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual original journal/root FDs and actual Gate, without a native/source
// issuer. A rejected/copy/late stage must not touch either authored image.
func TestDomainFailureRejectedStageKeepsActualWriterFDs(t *testing.T) {
	k, ctx := domainTCPKeeperFilesFixture(t)
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(held, root); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	cleanup, err := control.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	c, s := k.cursor, k.cursor.scope
	p := &XrayDomainTCPExecutionResource{scope: s, records: k.records, id: "original-process"}
	p.self = p
	m := &XrayDomainTCPOperationMaterial{resource: p, control: control}
	m.self = m
	p.material = m
	r := &domainTCPFailureCleanup{cursor: c, resource: p, control: control, cleanup: cleanup, image: bytes.Clone(k.image), imageStage: "process"}
	r.self = r
	c.cleanup = r
	c.failedCustody.Store(true)
	r.ctx = context.WithValue(held, domainTCPFailureCleanupKey{}, r)
	r.active.Store(true)
	defer r.active.Store(false)
	k.records.mu.Lock()
	before := [2]os.FileInfo{k.records.infos[0], k.records.infos[1]}
	k.records.mu.Unlock()
	for _, mode := range []string{"new-pinned-image", "next-before-ACK", "foreign-context", "copied-cursor", "expired"} {
		t.Run(mode, func(t *testing.T) {
			call, owner, stage := r.ctx, r, "process"
			image := append(bytes.Clone(k.image), ' ')
			switch mode {
			case "next-before-ACK":
				stage = "capture"
			case "foreign-context":
				call = held
			case "copied-cursor":
				owner = &domainTCPFailureCleanup{self: r, cursor: c, resource: p, control: control, cleanup: cleanup, ctx: r.ctx}
				owner.active.Store(true)
			case "expired":
				r.active.Store(false)
				defer r.active.Store(true)
			}
			if err := owner.publishStageLocked(call, stage, p.id, image); err == nil {
				t.Fatal("refused metadata minted a writer")
			}
			if err := k.records.current(ctx, true); err != nil {
				t.Fatal("refused stage changed original FD/bytes", err)
			}
			k.records.mu.Lock()
			defer k.records.mu.Unlock()
			for i := range 2 {
				info, err := k.records.files[i].Stat()
				if err != nil || !os.SameFile(before[i], info) || !bytes.Equal(k.records.images[i], k.image) {
					t.Fatal("refusal replaced accepted original", i, err)
				}
			}
		})
	}
}

// Filesystem publication model only, not a source/receipt/native issuer. It
// uses the exact production retained-FD writer primitive and the SAME pinned
// cursor through a cut BEFORE writer1. No pathname is reopened as custody.
func TestDomainFailurePairModelRetriesOriginalFDImages(t *testing.T) {
	for _, stage := range []string{"capture", "standby"} {
		for _, foreign := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/retry", true: "/foreign"}[foreign], func(t *testing.T) {
				k, ctx := domainTCPKeeperFilesFixture(t)
				before := *k.cursor.scope.execution
				before.Resources = []ExecutionResource{{ID: "capture-model", Kind: "domain-tcp-capture", State: "prepared", Phase: "capture-prepared"}}
				if stage == "standby" {
					before.Resources[0] = ExecutionResource{ID: "baseline-model", Kind: "synthetic-baseline", State: "prepared", Phase: "capture-ready"}
				}
				old, err := json.Marshal(before)
				if err != nil {
					t.Fatal(err)
				}
				// The retained writer accepts only its original scope's current
				// execution, just as the real metadata producer does.
				*k.cursor.scope.execution = before
				for i := range 2 {
					if err := k.records.publishOriginalDurable(i, old, syncDataplaneJournalDirectory); err != nil {
						t.Fatal(err)
					}
				}
				after := before
				after.Resources = append([]ExecutionResource(nil), before.Resources...)
				if stage == "capture" {
					after.Resources[0].State, after.Resources[0].Phase = "removed", "removed"
				} else {
					after.Resources[0].Phase = "standby-retained"
				}
				image, err := json.Marshal(after)
				if err != nil {
					t.Fatal(err)
				}
				*k.cursor.scope.execution = after
				r := &domainTCPFailureCleanup{cursor: k.cursor, image: bytes.Clone(image), imageStage: stage}
				r.self = r
				k.records.mu.Lock()
				oldGlobal := k.records.files[1]
				oldInfo := k.records.infos[1]
				k.records.mu.Unlock()
				cut := errors.New("model writer1 unavailable after original writer0 ACK")
				publish := func(stop bool) error {
					if err := k.records.current(ctx, false); err != nil {
						return err
					}
					if err := k.records.publishOriginalDurable(0, r.image, syncDataplaneJournalDirectory); err != nil {
						return err
					}
					if stop {
						return cut
					}
					if err := k.records.current(ctx, false); err != nil {
						return err
					}
					if err := k.records.publishOriginalDurable(1, r.image, syncDataplaneJournalDirectory); err != nil {
						return err
					}
					if err := k.records.current(ctx, true); err != nil {
						return err
					}
					r.imageACK = true
					return nil
				}
				if err := publish(true); !errors.Is(err, cut) {
					t.Fatal(err)
				}
				if r.imageACK || !bytes.Equal(r.image, image) || r.imageStage != stage {
					t.Fatal("partial ACK lost pinned cursor")
				}
				if err := k.records.current(ctx, false); err != nil {
					t.Fatal("original partial pair refused", err)
				}
				if err := k.records.current(ctx, true); err == nil {
					t.Fatal("partial pair accepted as equal")
				}
				if foreign {
					if err := k.records.root.WriteAtomic("latest-execution.json", old, 0600); err != nil {
						t.Fatal(err)
					}
					if err := publish(false); err == nil {
						t.Fatal("foreign equal-byte global adopted")
					}
					k.records.mu.Lock()
					same := k.records.files[1] == oldGlobal && os.SameFile(k.records.infos[1], oldInfo)
					k.records.mu.Unlock()
					if !same || r.imageACK || !bytes.Equal(r.image, image) {
						t.Fatal("refused retry discarded original custody")
					}
					return
				}
				if err := publish(false); err != nil {
					t.Fatal("same original pair retry", err)
				}
				if !r.imageACK || !bytes.Equal(r.image, image) {
					t.Fatal("retry changed pinned image")
				}
			})
		}
	}
}
