//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func runOfflineRetryNative(f *priorArchiveFixture, receipt selfupdatejournal.Receipt, data *[]byte, cut func(string) error, effects *[]string) error {
	return restorePairedOfflineWithRetry(f.ctx, f.installation, receipt, func(string) error { return nil }, func(c context.Context) error { return c.Err() }, func(effect string, begin func() error) error { *effects = append(*effects, effect); return begin() }, commitOfflinePriorReplacement, cut, &offlineRetryState{data: *data, bind: func(next []byte, _ selfupdatejournal.Check) error {
		if len(*data) != 0 {
			return ErrPairedOfflineRestore
		}
		*data = bytes.Clone(next)
		return nil
	}})
}

func TestPairedOfflineRetryNativeResumesEveryKnownPrefix(t *testing.T) {
	for _, point := range []string{"before:offline-replace:etc/init.d/S99razvilka", "after:offline-replace:etc/init.d/S99razvilka", "after:offline-replace:etc/razvilka/config.json", "before:offline-replace:bin/razvilka", "after:offline-replace:bin/razvilka", "after:offline-restore"} {
		t.Run(point, func(t *testing.T) {
			f, r := offlineRestoreFixture(t, false)
			protected := map[string][]byte{}
			for _, name := range []string{"razvilka/state/strategy-lab.json", "etc/razvilka/private-restore-strategylab-v1/current.json", "razvilka/state/self-update-stop/current-v1.json", "etc/razvilka/private-restore-future-v9/unknown"} {
				data, err := os.ReadFile(filepath.Join(f.installation, filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				protected[name] = data
			}
			var data []byte
			var first, retry []string
			cut := errors.New("native known CAS cut")
			err := runOfflineRetryNative(f, r, &data, func(name string) error {
				if name == point {
					return cut
				}
				return nil
			}, &first)
			if !errors.Is(err, cut) || len(data) == 0 {
				t.Fatal("did not reach bound known cut", err)
			}
			if err := runOfflineRetryNative(f, r, &data, nil, &retry); err != nil {
				t.Fatal("known native prefix did not resume", err)
			}
			doc, err := decodeOfflinePriorPlan(r, data)
			if err != nil {
				t.Fatal(err)
			}
			if len(first)+len(retry) != len(doc.Items) {
				t.Fatal("known successful CAS replayed", len(first), len(retry), len(doc.Items))
			}
			if got, err := os.ReadFile(filepath.Join(f.installation, "bin/razvilka")); err != nil || string(got) != "old controller with no read capability claim" {
				t.Fatal("old binary not restored", err)
			}
			for name, want := range protected {
				got, err := os.ReadFile(filepath.Join(f.installation, filepath.FromSlash(name)))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("independent history/fence changed", name, err)
				}
			}
			if err := restorePairedOfflineWithRetry(f.ctx, f.installation, r, func(string) error { return nil }, func(c context.Context) error { return c.Err() }, func(string, func() error) error {
				t.Fatal("completed verification issued an effect")
				return ErrPairedOfflineRestore
			}, commitOfflinePriorReplacement, nil, &offlineRetryState{data: data, verifyOnly: true}); err != nil {
				t.Fatal("completed receipt4 verification failed", err)
			}
		})
	}
}

func TestPairedOfflineRetryNativeRejectsForeignLayouts(t *testing.T) {
	for _, failure := range []string{"third-target", "stage-inode", "missing-stage", "foreign-stage", "non-prefix", "owner", "unchanged-file", "ordinary-child", "unbound-plan"} {
		t.Run(failure, func(t *testing.T) {
			f, r := offlineRestoreFixture(t, false)
			var data []byte
			var first, retry []string
			cut := errors.New("cut")
			err := runOfflineRetryNative(f, r, &data, func(name string) error {
				if name == "before:offline-replace:etc/init.d/S99razvilka" {
					return cut
				}
				return nil
			}, &first)
			if !errors.Is(err, cut) {
				t.Fatal(err)
			}
			doc, err := decodeOfflinePriorPlan(r, data)
			if err != nil {
				t.Fatal(err)
			}
			item := doc.Items[0]
			stage := filepath.Join(f.installation, filepath.Dir(filepath.FromSlash(item.Path)), item.Stage)
			switch failure {
			case "unchanged-file":
				err = os.WriteFile(filepath.Join(f.installation, "etc/razvilka/sources.json"), []byte("foreign unchanged file"), 0600)
			case "ordinary-child":
				err = os.WriteFile(filepath.Join(f.installation, "etc/razvilka/foreign-normal-file"), []byte("ordinary foreign descendant"), 0600)
			case "third-target":
				err = os.WriteFile(filepath.Join(f.installation, filepath.FromSlash(item.Path)), []byte("foreign edit"), 0600)
			case "stage-inode":
				payload, readErr := os.ReadFile(stage)
				info, statErr := os.Stat(stage)
				if readErr != nil || statErr != nil {
					t.Fatal("stage unavailable")
				}
				err = os.WriteFile(stage+"-foreign", payload, info.Mode())
				if err == nil {
					err = os.Rename(stage+"-foreign", stage)
				}
			case "missing-stage":
				err = os.Rename(stage, stage+"-retained")
			case "foreign-stage":
				err = os.WriteFile(filepath.Join(f.installation, "bin", pairedOfflineStagePrefix+"11111111111111111111111111111111"), []byte("unowned retained data"), 0600)
			case "non-prefix":
				late := doc.Items[len(doc.Items)-1]
				parent, fd, openErr := offlineRetryParent(f.installation, late, func(string) error { return nil })
				if openErr != nil {
					t.Fatal(openErr)
				}
				_, seen, layoutErr := offlineRetryLayout(f.ctx, parent, late)
				if layoutErr != nil {
					t.Fatal(layoutErr)
				}
				p := offlinePriorReplacement{path: late.Path, stage: late.Stage, parent: parent, parentFD: fd, seen: seen, before: map[string]offlinePriorNode{}, after: map[string]offlinePriorNode{}}
				p.parentInfo, _ = parent.Stat(".")
				p.staged, _ = parent.Lstat(late.Stage)
				for _, row := range late.Before {
					p.before[row.Path] = offlinePriorNode{}
				}
				for _, row := range late.After {
					p.after[row.Path] = offlinePriorNode{}
				}
				err = commitOfflinePriorReplacement(f.ctx, &p, func(begin func() error) error { return begin() })
				fd.Close()
				parent.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if failure == "unbound-plan" {
				err := restorePairedOfflineWithRetry(f.ctx, f.installation, r, func(string) error { return nil }, func(c context.Context) error { return c.Err() }, func(string, func() error) error { t.Fatal("unbound plan obtained effects"); return nil }, commitOfflinePriorReplacement, nil, &offlineRetryState{data: data, verifyOnly: true})
				if err == nil {
					t.Fatal("plan-only cut mistaken for completion")
				}
				return
			}
			boundary := func(string) error { return nil }
			if failure == "owner" {
				boundary = func(string) error { return cut }
			}
			if err := runOfflineRetryNative(f, r, &data, boundary, &retry); err == nil || len(retry) != 0 {
				t.Fatal("foreign/unauthorized state supplied retry authority", len(retry), err)
			}
		})
	}
}

func TestPairedOfflineRetryNativeStopAtAdmissionKeepsExactPreimage(t *testing.T) {
	f, r := offlineRestoreFixture(t, false)
	before, err := os.ReadFile(filepath.Join(f.installation, "etc/init.d/S99razvilka"))
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	admissions := 0
	denied := errors.New("fresh Stop epoch denied original effect")
	err = restorePairedOfflineWithRetry(f.ctx, f.installation, r, func(string) error { return nil }, func(c context.Context) error { return c.Err() }, func(_ string, begin func() error) error {
		admissions++
		// Refuse immediately around the prepared native rename. No begin means no
		// installation CAS; merely reaching a positive owner check is insufficient.
		return denied
	}, commitOfflinePriorReplacement, nil, &offlineRetryState{bind: func(next []byte, _ selfupdatejournal.Check) error { data = bytes.Clone(next); return nil }})
	if !errors.Is(err, denied) || admissions != 1 || len(data) == 0 {
		t.Fatal("did not exercise exact admission window", admissions, err)
	}
	after, err := os.ReadFile(filepath.Join(f.installation, "etc/init.d/S99razvilka"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused admission changed live init", err)
	}
	doc, err := decodeOfflinePriorPlan(r, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range doc.Items {
		parent, fd, err := offlineRetryParent(f.installation, item, func(string) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		post, _, err := offlineRetryLayout(f.ctx, parent, item)
		fd.Close()
		parent.Close()
		if err != nil || post {
			t.Fatal("denied admission changed a frozen preimage", err)
		}
	}
	var effects []string
	if err := runOfflineRetryNative(f, r, &data, nil, &effects); err != nil || len(effects) != len(doc.Items) {
		t.Fatal("fresh authority could not resume retained stages", len(effects), err)
	}
}

func TestPairedOfflinePlanOnlyNativeReDerivesBeforeFencing(t *testing.T) {
	for _, failure := range []string{"none", "preconfig", "stage-inode", "forged-post", "mixed-prefix", "stop-before-fence"} {
		t.Run(failure, func(t *testing.T) {
			f, r := offlineRestoreFixture(t, false)
			var data []byte
			var initial []string
			cut := errors.New("plan publication cut")
			point := "before:offline-replace:etc/init.d/S99razvilka"
			if failure == "mixed-prefix" {
				point = "after:offline-replace:etc/init.d/S99razvilka"
			}
			err := runOfflineRetryNative(f, r, &data, func(name string) error {
				if name == point {
					return cut
				}
				return nil
			}, &initial)
			if !errors.Is(err, cut) {
				t.Fatal(err)
			}
			doc, err := decodeOfflinePriorPlan(r, data)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "preconfig":
				err = os.WriteFile(filepath.Join(f.installation, "etc/razvilka/config.json"), []byte(`{"schema":1}`), 0600)
			case "stage-inode", "forged-post":
				item := &doc.Items[0]
				stage := filepath.Join(f.installation, filepath.Dir(filepath.FromSlash(item.Path)), item.Stage)
				payload, readErr := os.ReadFile(stage)
				info, statErr := os.Stat(stage)
				if readErr != nil || statErr != nil {
					t.Fatal("stage unavailable")
				}
				if failure == "stage-inode" {
					err = os.WriteFile(stage+"-foreign", payload, info.Mode())
					if err == nil {
						err = os.Rename(stage+"-foreign", stage)
					}
				} else {
					payload = []byte("#!/bin/sh\nexit 0\n")
					err = os.WriteFile(stage, payload, info.Mode())
					info, statErr = os.Stat(stage)
					if statErr != nil {
						t.Fatal(statErr)
					}
					row := &item.After[0]
					row.Size = int64(len(payload))
					row.SHA256 = digestBytes(payload)
					row.Identity, err = offlinePersistentIdentity(info)
					data, err = json.Marshal(doc)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			fenced, effects := 0, 0
			revoked := false
			err = restorePairedOfflineWithRetry(f.ctx, f.installation, r, func(string) error { return nil }, func(c context.Context) error {
				if revoked {
					return cut
				}
				return c.Err()
			}, func(_ string, begin func() error) error { effects++; return begin() }, commitOfflinePriorReplacement, nil, &offlineRetryState{data: data, verifyOnly: true, bind: func(got []byte, ready selfupdatejournal.Check) error {
				if !bytes.Equal(got, data) || ready == nil {
					t.Fatal("plan changed or missing prepared full proof")
				}
				if failure == "stop-before-fence" {
					revoked = true
				}
				if err := ready(f.ctx); err != nil {
					return err
				}
				fenced++
				return nil
			}})
			if failure == "none" {
				if err != nil || fenced != 1 || effects != len(doc.Items) {
					t.Fatal("known plan-only cut did not safely finish", fenced, effects, err)
				}
			} else if err == nil || fenced != 0 || effects != 0 {
				t.Fatal("invalid plan-only state obtained fence/effects", fenced, effects, err)
			}
		})
	}
}
