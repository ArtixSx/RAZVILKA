package selfupdatejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var stoppedBinding = StoppedBinding{InstallationID: "fedcba9876543210fedcba9876543210", PreStopSequence: 7, StopSequence: 8, Revision: 11, RequiredReader: 3}

func stoppedFixture(t *testing.T) *fixture {
	t.Helper()
	f := fixtureAt(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(f.installation, "etc/init.d"), 0700); err != nil {
		t.Fatal(err)
	}
	for i, target := range []string{"etc/init.d/S99razvilka", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json"} {
		data := []byte("candidate " + target)
		name := filepath.Join(f.candidate, filepath.Base(target))
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := os.WriteFile(filepath.Join(f.installation, filepath.FromSlash(target)), []byte("old "+target), 0640); err != nil {
				t.Fatal(err)
			}
		}
		hash := sha256.Sum256(data)
		f.files = append(f.files, File{Target: target, Candidate: name, SHA256: hex.EncodeToString(hash[:])})
	}
	f.prepare(t)
	f.install(t)
	if err := f.store.Restore(context.Background(), transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStoppedSettlementDataTerminalAndLiveRefusal(t *testing.T) {
	f := stoppedFixture(t)
	ctx := context.Background()
	if err := f.store.SettleStoppedRollback(ctx, transaction, stoppedBinding, okay, okay, okay); err != nil {
		t.Fatal(err)
	}
	r, present, err := f.store.Current()
	if err != nil || !present || r.Pending() || r.Schema != 3 || r.Phase != "rolled-back-stopped" || r.Stopped == nil || *r.Stopped != stoppedBinding {
		t.Fatal(r, err)
	}
	f.old(t)
	if version, err := f.store.RequiredReadVersion(ctx); err != nil || version != 3 {
		t.Fatal(version, err)
	}
	if _, err := f.store.RetainedBinaryImages(ctx); err != nil {
		t.Fatal(err)
	}
	liveCalls := 0
	if err := f.store.Accept(ctx, transaction, true, okay, func(context.Context) error { liveCalls++; return nil }); !errors.Is(err, ErrPending) || liveCalls != 0 {
		t.Fatal("stopped terminal borrowed live acceptance", err, liveCalls)
	}
	if err := f.store.Execute(ctx, transaction, "start-rollback-panel", okay, okay); !errors.Is(err, ErrPending) {
		t.Fatal("terminal replay", err)
	}
	if err := f.store.SettleStoppedRollback(ctx, transaction, stoppedBinding, okay, okay, okay); err != nil {
		t.Fatal("idempotent retry", err)
	}
	wrong := stoppedBinding
	wrong.Revision++
	if err := f.store.SettleStoppedRollback(ctx, transaction, wrong, okay, okay, okay); !errors.Is(err, ErrMismatch) {
		t.Fatal("terminal rebind", err)
	}
}

func TestStoppedSettlementRejectsUntrustedEvidence(t *testing.T) {
	for _, test := range []string{"authority", "reader", "inactive", "reader-refused", "revision", "epoch", "reader2", "unknown", "foreign-file", "missing-file"} {
		t.Run(test, func(t *testing.T) {
			f := stoppedFixture(t)
			binding := stoppedBinding
			authority, readers, inactive := okay, okay, okay
			switch test {
			case "authority":
				authority = nil
			case "reader":
				readers = nil
			case "inactive":
				inactive = nil
			case "reader-refused":
				readers = func(context.Context) error { return interrupted }
			case "revision":
				binding.Revision = 0
			case "epoch":
				binding.StopSequence++
			case "reader2":
				binding.RequiredReader = 2
			case "unknown":
				_ = f.store.Execute(context.Background(), transaction, "restore-private-state", okay, func(context.Context) error { return interrupted })
			case "foreign-file":
				_ = os.WriteFile(filepath.Join(f.installation, "bin/razvilka"), []byte("foreign"), 0755)
			case "missing-file":
				_ = os.Remove(filepath.Join(f.installation, "bin/razvilka"))
			}
			before, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
			if err := f.store.SettleStoppedRollback(context.Background(), transaction, binding, authority, readers, inactive); err == nil {
				t.Fatal("evidence admitted", test)
			}
			after, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
			if string(before) != string(after) {
				t.Fatal("refusal changed receipt")
			}
		})
	}
}

func TestStoppedSettlementPublicationCuts(t *testing.T) {
	for _, point := range []string{"before:receipt:rolled-back-stopped", "after:receipt:rolled-back-stopped", "before:stopped-current", "after:stopped-current"} {
		t.Run(point, func(t *testing.T) {
			f := stoppedFixture(t)
			f.store.fault = func(p string) error {
				if p == point {
					return interrupted
				}
				return nil
			}
			if err := f.store.SettleStoppedRollback(context.Background(), transaction, stoppedBinding, okay, okay, okay); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			f.reopen(t)
			r, present, err := f.store.Current()
			if err != nil || !present || (r.Phase != "restored" && r.Phase != "rolled-back-stopped") {
				t.Fatal("unreadable cut", r, err)
			}
			calls := 0
			fresh := func(context.Context) error { calls++; return nil }
			if err := f.store.SettleStoppedRollback(context.Background(), transaction, stoppedBinding, fresh, fresh, fresh); err != nil || calls < 9 {
				t.Fatal("retry skipped fresh evidence", calls, err)
			}
			f.old(t)
		})
	}
}

func TestStoppedReceiptRejectsSchemaDowngradeOrPointerMismatch(t *testing.T) {
	f := stoppedFixture(t)
	if err := f.store.SettleStoppedRollback(context.Background(), transaction, stoppedBinding, okay, okay, okay); err != nil {
		t.Fatal(err)
	}
	r, _, _ := f.store.Current()
	r.Schema = 2
	data, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(f.journal, transaction, "receipt.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Current(); !errors.Is(err, ErrMismatch) {
		t.Fatal("downgraded stopped receipt read", err)
	}
}
