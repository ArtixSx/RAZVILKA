//go:build linux

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func strictManualFixture(t *testing.T) (*Store, Config, context.Context) {
	t.Helper()
	ordinary, _, ctx := offlineNFQWS2StopConfig(t, true)
	mode := "auto"
	if err := ordinary.UpdateServiceControl(&mode, nil, ordinary.Get().Revision); err != nil {
		t.Fatal(err)
	}
	strict, err := LoadExistingStrict(ctx, ordinary.path)
	if err != nil {
		t.Fatal(err)
	}
	return strict, ordinary.Get(), ctx
}

func strictRaw(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStrictManualChangesOnlyModeAndDraftRevision(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "auto", true: "legacy-auto"}[legacy], func(t *testing.T) {
			s, before, ctx := strictManualFixture(t)
			if legacy {
				ordinary, err := LoadExisting(s.path)
				if err != nil {
					t.Fatal(err)
				}
				mode := ""
				if err := ordinary.UpdateServiceControl(&mode, nil, ordinary.Get().Revision); err != nil {
					t.Fatal(err)
				}
				s, err = LoadExistingStrict(ctx, s.path)
				if err != nil {
					t.Fatal(err)
				}
				before = s.Get()
			}
			beforeBytes := strictRaw(t, s.path)
			beforeHash, err := s.StrictImageSHA256()
			wantHash := sha256.Sum256(beforeBytes)
			if err != nil || beforeHash != hex.EncodeToString(wantHash[:]) || s.CheckStrictImage() != nil {
				t.Fatal("before-image identity unavailable", err)
			}
			manual := "manual"
			if err := s.UpdateServiceControl(&manual, nil, before.Revision); err != nil {
				t.Fatal("manual transition refused", err)
			}
			after := s.Get()
			if after.ServiceControl.Mode != "manual" || after.Revision != before.Revision+1 {
				t.Fatal("manual mode or draft revision not saved")
			}
			unchanged := cloneConfig(after)
			unchanged.ServiceControl.Mode, unchanged.Revision = before.ServiceControl.Mode, before.Revision
			if !reflect.DeepEqual(unchanged, before) {
				t.Fatal("manual save changed applied scope, draft, policies, recipes, SafeMode, schedule or exclusions")
			}
			reloaded, err := LoadExisting(s.path)
			if err != nil || !reflect.DeepEqual(reloaded.Get(), after) || s.CheckStrictImage() != nil {
				t.Fatal("exact manual image did not survive fresh read", err)
			}
			afterHash, err := s.StrictImageSHA256()
			wantHash = sha256.Sum256(strictRaw(t, s.path))
			if err != nil || afterHash == beforeHash || afterHash != hex.EncodeToString(wantHash[:]) {
				t.Fatal("after hash does not identify current retained image", err)
			}
			committedBytes := strictRaw(t, s.path)
			if err := s.UpdateServiceControl(&manual, nil, after.Revision); err == nil {
				t.Fatal("one-shot Store wrote a second revision")
			}
			if !bytes.Equal(strictRaw(t, s.path), committedBytes) {
				t.Fatal("repeat changed disk")
			}
		})
	}
}

func TestStrictManualUsesRawImageCASAtSameRevision(t *testing.T) {
	for _, change := range []string{"whitespace", "draft"} {
		t.Run(change, func(t *testing.T) {
			s, before, _ := strictManualFixture(t)
			foreign := append([]byte("\n"), strictRaw(t, s.path)...)
			if change == "draft" {
				next := cloneConfig(before)
				next.CatalogPath = "/opt/etc/razvilka/other-catalog.json"
				foreign, _ = json.MarshalIndent(next, "", "  ")
			}
			if err := os.WriteFile(s.path, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := s.CheckStrictImage(); !errors.Is(err, restorejournal.ErrConflict) {
				t.Fatal("raw conflict not observed", err)
			}
			manual := "manual"
			if err := s.UpdateServiceControl(&manual, nil, before.Revision); !errors.Is(err, restorejournal.ErrConflict) {
				t.Fatal("same-revision disk change admitted", err)
			}
			if !bytes.Equal(strictRaw(t, s.path), foreign) || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("CAS refusal replaced current disk or retained config")
			}
			if err := s.UpdateServiceControl(&manual, nil, before.Revision); err == nil {
				t.Fatal("same Store retried a refused write")
			}
		})
	}
}

func TestStrictLoadRefusesMigrationAmbiguityAndNormalization(t *testing.T) {
	tests := map[string]func([]byte) []byte{
		"old-schema": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version": 2`), []byte(`"schema_version": 1`), 1)
		},
		"future-schema": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version": 2`), []byte(`"schema_version": 99`), 1)
		},
		"missing-listen":      func(b []byte) []byte { return bytes.Replace(b, []byte(`"listen": ":8787"`), []byte(`"listen": ""`), 1) },
		"route-normalization": func(b []byte) []byte { return bytes.Replace(b, []byte(`"mode": "nfqws2"`), []byte(`"mode": ""`), 1) },
		"unknown-field": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{\n"), []byte("{\n  \"new_option\": true,\n"), 1)
		},
		"duplicate-top-level": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{\n"), []byte("{\n  \"schema_version\": 1,\n"), 1)
		},
		"duplicate-nested": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"route": "nfqws2"`), []byte(`"route": "direct", "route": "nfqws2"`), 1)
		},
		"case-alias": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)
		},
		"explicit-omitted-zero": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"mode": "auto"`), []byte(`"stopped": false, "mode": "auto"`), 1)
		},
		"trailing-value": func(b []byte) []byte { return append(b, []byte("\n{}")...) },
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			s, _, ctx := strictManualFixture(t)
			old := strictRaw(t, s.path)
			bad := modify(append([]byte(nil), old...))
			if bytes.Equal(bad, old) {
				t.Fatal("fixture did not introduce the reviewed case")
			}
			if err := os.WriteFile(s.path, bad, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadExistingStrict(ctx, s.path); !errors.Is(err, restorejournal.ErrInvalid) {
				t.Fatal("ambiguous or normalizing image accepted", err)
			}
			if !bytes.Equal(strictRaw(t, s.path), bad) {
				t.Fatal("loader rewrote refused input")
			}
		})
	}
}

func TestStrictLoadMissingPathsAndBoundedContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	for _, path := range []string{filepath.Join(dir, "config.json"), filepath.Join(dir, "absent", "config.json")} {
		if _, err := LoadExistingStrict(ctx, path); err == nil {
			t.Fatal("missing file admitted", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("strict loader created paths or markers", err)
	}
	s, _, _ := strictManualFixture(t)
	for _, unbounded := range []context.Context{nil, context.Background()} {
		if _, err := LoadExistingStrict(unbounded, s.path); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("unbounded context accepted", err)
		}
	}
	canceled, stop := context.WithTimeout(context.Background(), time.Minute)
	stop()
	if _, err := LoadExistingStrict(canceled, s.path); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled loader admitted", err)
	}
	expired, stopExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stopExpired()
	if _, err := LoadExistingStrict(expired, s.path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired loader admitted", err)
	}
	if _, err := LoadExistingStrict(ctx, "config.json"); !errors.Is(err, restorejournal.ErrInvalid) {
		t.Fatal("relative strict target admitted", err)
	}
}

func TestStrictManualDoesNotCreateMissingFileLease(t *testing.T) {
	s, before, _ := strictManualFixture(t)
	original := strictRaw(t, s.path)
	markers, err := filepath.Glob(filepath.Join(filepath.Dir(s.path), ".state-*.lock"))
	if err != nil || len(markers) != 1 {
		t.Fatal("actual Store lease marker missing", err)
	}
	if err := os.Remove(markers[0]); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadExistingStrict(s.strict.ctx, s.path); loaded != nil || err == nil {
		t.Fatal("strict loader admitted missing original file marker", err)
	}
	manual := "manual"
	if err := s.CheckStrictImage(); err == nil {
		t.Fatal("missing file marker admitted for readback")
	}
	if err := s.UpdateServiceControl(&manual, nil, before.Revision); err == nil {
		t.Fatal("missing file marker admitted for write")
	}
	if _, err := os.Lstat(markers[0]); !errors.Is(err, os.ErrNotExist) || !bytes.Equal(original, strictRaw(t, s.path)) {
		t.Fatal("strict save recreated marker or changed config", err)
	}
}

func TestStrictLoadRequiresOriginalPrivateFileOwnership(t *testing.T) {
	for _, object := range []string{"root", "marker", "target"} {
		t.Run(object, func(t *testing.T) {
			s, _, ctx := strictManualFixture(t)
			before := strictRaw(t, s.path)
			markers, err := filepath.Glob(filepath.Join(filepath.Dir(s.path), ".state-*.lock"))
			if err != nil || len(markers) != 1 {
				t.Fatal("missing actual file lease marker", err)
			}
			path := map[string]string{"root": filepath.Dir(s.path), "marker": markers[0], "target": s.path}[object]
			mode := os.FileMode(0o660)
			if object == "root" {
				mode = 0o770
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if loaded, err := LoadExistingStrict(ctx, s.path); loaded != nil || err == nil {
				t.Fatal("strict loader accepted an unsafe original owner", err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode || !bytes.Equal(before, strictRaw(t, s.path)) {
				t.Fatal("strict loader repaired refused ownership or contents", err)
			}
		})
	}
}

func TestStrictManualPreservesOriginalContextAndRejectsOtherWriters(t *testing.T) {
	s, before, _ := strictManualFixture(t)
	original := strictRaw(t, s.path)
	auto, manual := "auto", "manual"
	for name, action := range map[string]func() error{
		"save":      func() error { return s.Save() },
		"auto":      func() error { return s.UpdateServiceControl(&auto, nil, before.Revision) },
		"schedule":  func() error { return s.UpdateServiceControl(&manual, &before.ServiceControl.Schedule, before.Revision) },
		"draft":     func() error { return s.UpdateService("extra", ServiceState{Enabled: true, Route: "nfqws2"}) },
		"safe-mode": func() error { return s.SetSafeMode(!before.SafeMode) },
		"restore": func() error {
			x, err := s.BeginRestore(context.Background())
			if x != nil {
				x.Close()
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := action(); err == nil {
				t.Fatal("strict Store admitted unrelated writer")
			}
			if !bytes.Equal(original, strictRaw(t, s.path)) || !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("refused writer changed file or cache")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	loaded, err := LoadExistingStrict(ctx, s.path)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := loaded.UpdateServiceControl(&manual, nil, before.Revision); !errors.Is(err, context.Canceled) {
		t.Fatal("manual write renewed expired authority", err)
	}
	if err := loaded.CheckStrictImage(); !errors.Is(err, context.Canceled) {
		t.Fatal("readback renewed expired authority", err)
	}
	if _, err := loaded.StrictImageSHA256(); !errors.Is(err, context.Canceled) {
		t.Fatal("hash renewed expired authority", err)
	}
	if !bytes.Equal(original, strictRaw(t, s.path)) {
		t.Fatal("expired strict writer changed config")
	}
}

type strictFaultTarget struct {
	strictConfigTarget
	beforeWrite   bool
	afterWrite    bool
	afterClose    bool
	cancelOnWrite context.CancelFunc
	cancelOnClose context.CancelFunc
}

func (f *strictFaultTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if f.beforeWrite {
		return restorejournal.ErrRecovery
	}
	err := f.strictConfigTarget.CompareAndSwap(ctx, before, after)
	if err == nil && f.cancelOnWrite != nil {
		f.cancelOnWrite()
	}
	if err == nil && f.afterWrite {
		return restorejournal.ErrRecovery
	}
	return err
}

func (f *strictFaultTarget) Close() error {
	err := f.strictConfigTarget.Close()
	if f.cancelOnClose != nil {
		f.cancelOnClose()
	}
	if f.afterClose {
		return errors.Join(err, errors.New("modeled descriptor close failure"))
	}
	return err
}

func TestStrictManualWriteAndClosingUncertaintyNeverRetries(t *testing.T) {
	for _, fault := range []string{"before-write", "after-write", "after-close", "context-after-write", "context-on-close"} {
		t.Run(fault, func(t *testing.T) {
			s, before, _ := strictManualFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var err error
			s, err = LoadExistingStrict(ctx, s.path)
			if err != nil {
				t.Fatal(err)
			}
			original := strictRaw(t, s.path)
			actualOpen := s.strict.openTarget
			writes := 0
			s.strict.openTarget = func(path string) (strictConfigTarget, error) {
				writes++
				target, err := actualOpen(path)
				if err != nil {
					return nil, err
				}
				wrapper := &strictFaultTarget{strictConfigTarget: target, beforeWrite: fault == "before-write", afterWrite: fault == "after-write", afterClose: fault == "after-close"}
				if fault == "context-after-write" {
					wrapper.cancelOnWrite = cancel
				}
				if fault == "context-on-close" {
					wrapper.cancelOnClose = cancel
				}
				return wrapper, nil
			}
			manual := "manual"
			err = s.UpdateServiceControl(&manual, nil, before.Revision)
			if fault == "before-write" {
				if !errors.Is(err, restorejournal.ErrAborted) || s.writeUncertain || !bytes.Equal(original, strictRaw(t, s.path)) {
					t.Fatal("proven unchanged write not retained", err)
				}
			} else {
				if !errors.Is(err, restorejournal.ErrRecovery) || !s.writeUncertain || bytes.Equal(original, strictRaw(t, s.path)) {
					t.Fatal("possibly committed write not fenced", err)
				}
				if err := s.CheckStrictImage(); !errors.Is(err, restorejournal.ErrRecovery) {
					t.Fatal("readback converted uncertain write to success", err)
				}
				if _, err := s.StrictImageSHA256(); !errors.Is(err, restorejournal.ErrRecovery) {
					t.Fatal("hash exposed uncertain image as accepted", err)
				}
			}
			if !reflect.DeepEqual(s.Get(), before) {
				t.Fatal("failed save did not restore prior cache")
			}
			retained := strictRaw(t, s.path)
			if err := s.UpdateServiceControl(&manual, nil, before.Revision); err == nil || writes != 1 || !bytes.Equal(retained, strictRaw(t, s.path)) {
				t.Fatal("uncertain/refused save automatically retried", err)
			}
		})
	}
}

func TestStrictManualAlreadyManualAndRevisionOverflowRefuseWithoutWrite(t *testing.T) {
	for _, mode := range []string{"manual", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			s, _, ctx := strictManualFixture(t)
			ordinary, err := LoadExisting(s.path)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "manual" {
				ordinary.cfg.ServiceControl.Mode = "manual"
			} else {
				ordinary.cfg.Revision = ^uint64(0)
			}
			if err := ordinary.Save(); err != nil {
				t.Fatal(err)
			}
			s, err = LoadExistingStrict(ctx, s.path)
			if err != nil {
				t.Fatal(err)
			}
			original := strictRaw(t, s.path)
			if err := s.CheckStrictImage(); err != nil {
				t.Fatal("verified no-op image unavailable", err)
			}
			manual := "manual"
			if err := s.UpdateServiceControl(&manual, nil, s.Get().Revision); err == nil || !bytes.Equal(original, strictRaw(t, s.path)) {
				t.Fatal("no-op/overflow wrote a revision", err)
			}
		})
	}
}

func TestStrictJSONUniqueDepthAndNormalWhitespace(t *testing.T) {
	if err := strictUniqueJSON([]byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66))); err == nil {
		t.Fatal("over-deep value accepted")
	}
	s, _, ctx := strictManualFixture(t)
	raw := strictRaw(t, s.path)
	if err := os.WriteFile(s.path, append(append([]byte(" \n"), raw...), []byte("\n\t")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExistingStrict(ctx, s.path); err != nil {
		t.Fatal("harmless whitespace rejected", err)
	}
}
