package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

// Real original journal descriptors exercise the documentary prerequisite.
// This model deliberately has no native/source/cleanup authority: even its
// accepted removed image must never produce a verified runtime rollback.
func TestMihomoLiveRollbackRecordRequiresOriginalTerminalWriters(t *testing.T) {
	for _, mode := range []string{"original", "active", "committed", "sticky-error", "copied-owner", "foreign-inode", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			_, a, r, e := mihomoLiveRecordModel(t)
			// The older retention-only fixture uses an unnormalized definition;
			// use the same cloned intent as its actual original row here.
			r.definition = e.Resources[0].MihomoLive.Clone()
			e.State = "rolling-back"
			e.Resources[0].State, e.Resources[0].Phase = "removed", "removed"
			if mode == "active" {
				e.Resources[0].State, e.Resources[0].Phase = "active", "active"
			}
			if mode == "committed" {
				e.State = "committed"
			}
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.publishRecords(raw); err != nil {
				t.Fatal(err)
			}
			ctx := r.scope.contextWith(r.scope.ctx)
			check := r
			switch mode {
			case "sticky-error":
				r.scope.failure = errors.New("original publication failed")
			case "copied-owner":
				check = &mihomoLiveResource{self: r, adapter: a, scope: r.scope, records: r.records}
			case "foreign-inode":
				if err := r.records.root.WriteAtomic("latest-execution.json", raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = check.rollbackRecordCurrent(ctx)
			if (err == nil) != (mode == "original") {
				t.Fatalf("original documentary prerequisite: %v (writers=%v local=%v terminal=%v)", err, r.records.current(ctx, true), r.localRecord(ctx, false), validateExecutionResources(*e, true))
			}
			if mode == "original" {
				r.proxy = &ProxyTunnelAdapter{}
				verified, err := a.VerifyRollback(ctx, r.definition.Plan, filepath.Join(r.scope.root, "mihomo"))
				if verified || err == nil {
					t.Fatal("removed document manufactured native rollback evidence", verified, err)
				}
			}
		})
	}
}
