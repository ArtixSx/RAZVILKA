package restorejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var testScope = sum([]byte("trusted-test-bindings-v1"))
var injected = errors.New("private-content-or-path-must-not-escape")

type memoryTarget struct {
	image  Image
	writes int
	hook   func(Image, Image) error
}

func (m *memoryTarget) Read(ctx context.Context) (Image, error) {
	if err := ctx.Err(); err != nil {
		return Image{}, err
	}
	return clone(m.image), nil
}

func (m *memoryTarget) CompareAndSwap(ctx context.Context, before, after Image) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.writes++
	if m.hook != nil {
		if err := m.hook(before, after); err != nil {
			return err
		}
	}
	if !equal(m.image, before) {
		return injected
	}
	m.image = clone(after)
	return nil
}

func content(value string) Image { return Image{Exists: true, Data: []byte(value)} }

func fixture(t *testing.T) (*Journal, string, map[string]Target, []*memoryTarget) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	list := []*memoryTarget{{image: content("old-a")}, {image: Image{}}, {image: content("")}}
	targets := map[string]Target{"a": list[0], "b": list[1], "c": list[2]}
	j, err := Open(path, testScope, targets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, targets, list
}

func changes() map[string]Image {
	return map[string]Image{"a": content("new-a"), "b": content("new-b"), "c": {}}
}

func expectOld(t *testing.T, targets []*memoryTarget) {
	t.Helper()
	for i, old := range []Image{content("old-a"), {}, content("")} {
		if !equal(targets[i].image, old) {
			t.Fatalf("target %d not restored", i)
		}
	}
}

func reopen(t *testing.T, j *Journal, path string, targets map[string]Target) *Journal {
	t.Helper()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(path, testScope, targets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	return next
}

func prepared(t *testing.T, j *Journal) document {
	t.Helper()
	doc := document{Kind: journalKind, Schema: 1, Scope: testScope, ID: strings.Repeat("a", 32), State: "prepared"}
	for _, id := range []string{"a", "b", "c"} {
		before, _ := j.targets[id].Read(context.Background())
		doc.Records = append(doc.Records, record{Target: id, Before: before, After: changes()[id]})
	}
	if err := j.save(doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestJournalSuccessAndNoOp(t *testing.T) {
	j, path, targets, list := fixture(t)
	if out, err := j.Execute(context.Background(), changes()); out != Applied || err != nil {
		t.Fatalf("%s %v", out, err)
	}
	for id, after := range changes() {
		got, _ := targets[id].Read(context.Background())
		if !equal(got, after) {
			t.Fatal("wrong committed state")
		}
	}
	raw, err := os.ReadFile(filepath.Join(path, journalFile))
	if err != nil || bytes.Contains(raw, []byte("bmV3LWE=")) || bytes.Contains(raw, []byte("b2xkLWE=")) {
		t.Fatal("idle journal retained images")
	}
	j = reopen(t, j, path, targets)
	if out, err := j.Recover(context.Background()); out != Clean || err != nil {
		t.Fatalf("%s %v", out, err)
	}
	if out, err := j.Execute(context.Background(), changes()); out != Clean || err != nil {
		t.Fatalf("%s %v", out, err)
	}
	for _, target := range list {
		if target.writes != 1 {
			t.Fatal("no-op rewrote target")
		}
	}
	if _, err := os.Stat(filepath.Join(path, leaseFile)); err != nil {
		t.Fatal("persistent lease missing")
	}
}

func TestJournalForwardFailureEveryTarget(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		for _, afterWrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", failAt, afterWrite), func(t *testing.T) {
				j, path, targets, list := fixture(t)
				failed := false
				list[failAt].hook = func(_, after Image) error {
					if failed {
						return nil
					}
					failed = true
					if afterWrite {
						list[failAt].image = clone(after)
					}
					return injected
				}
				out, err := j.Execute(context.Background(), changes())
				if out != RolledBack || !errors.Is(err, ErrAborted) || strings.Contains(fmt.Sprint(err), injected.Error()) {
					t.Fatalf("%s %v", out, err)
				}
				expectOld(t, list)
				j = reopen(t, j, path, targets)
				if out, err := j.Recover(context.Background()); out != Clean || err != nil {
					t.Fatalf("%s %v", out, err)
				}
			})
		}
	}
}

func TestJournalInterruptedWrites(t *testing.T) {
	for writeAt := 1; writeAt <= 3; writeAt++ {
		for _, afterWrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("journal-write-%d/after-%t", writeAt, afterWrite), func(t *testing.T) {
				j, path, targets, list := fixture(t)
				write := j.write
				n := 0
				j.write = func(data []byte) error {
					n++
					if n == writeAt {
						if afterWrite {
							if err := write(data); err != nil {
								return err
							}
						}
						return injected
					}
					return write(data)
				}
				out, err := j.Execute(context.Background(), changes())
				if out != Blocked || !errors.Is(err, ErrRecovery) {
					t.Fatalf("%s %v", out, err)
				}
				j = reopen(t, j, path, targets)
				out, err = j.Recover(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				expect := RolledBack
				if writeAt == 1 && !afterWrite || writeAt == 3 && afterWrite {
					expect = Clean
				}
				if writeAt == 2 && afterWrite || writeAt == 3 && !afterWrite {
					expect = Applied
				}
				if out != expect {
					t.Fatalf("outcome %s want %s", out, expect)
				}
				if writeAt == 1 || writeAt == 2 && !afterWrite {
					expectOld(t, list)
				} else {
					for id, after := range changes() {
						got, _ := targets[id].Read(context.Background())
						if !equal(got, after) {
							t.Fatal("committed state was rolled back")
						}
					}
				}
			})
		}
	}
}

func TestJournalRecoveryFailureIsResumable(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		for _, afterWrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("undo-%d/after-%t", failAt, afterWrite), func(t *testing.T) {
				j, path, targets, list := fixture(t)
				doc := prepared(t, j)
				for i, entry := range doc.Records {
					list[i].image = clone(entry.After)
				}
				list[failAt].hook = func(_, after Image) error {
					if afterWrite {
						list[failAt].image = clone(after)
					}
					return injected
				}
				if out, err := j.Recover(context.Background()); out != Blocked || !errors.Is(err, ErrRecovery) {
					t.Fatalf("%s %v", out, err)
				}
				if out, err := j.Execute(context.Background(), changes()); out != Blocked || !errors.Is(err, ErrPending) {
					t.Fatal("pending plan overwritten")
				}
				list[failAt].hook = nil
				j = reopen(t, j, path, targets)
				if out, err := j.Recover(context.Background()); out != RolledBack || err != nil {
					t.Fatalf("%s %v", out, err)
				}
				expectOld(t, list)
			})
		}
	}
}

func TestJournalConflictNeverOverwritesThirdState(t *testing.T) {
	for _, state := range []string{"prepared", "committed"} {
		t.Run(state, func(t *testing.T) {
			j, path, _, list := fixture(t)
			doc := prepared(t, j)
			doc.State = state
			if err := j.save(doc); err != nil {
				t.Fatal(err)
			}
			for i, entry := range doc.Records {
				list[i].image = clone(entry.After)
			}
			list[2].image = content("newer-user-edit")
			before, _ := os.ReadFile(filepath.Join(path, journalFile))
			if out, err := j.Recover(context.Background()); out != Blocked || !errors.Is(err, ErrRecovery) {
				t.Fatalf("%s %v", out, err)
			}
			for _, target := range list {
				if target.writes != 0 {
					t.Fatal("recovery mutated before checking all targets")
				}
			}
			after, _ := os.ReadFile(filepath.Join(path, journalFile))
			if !bytes.Equal(before, after) {
				t.Fatal("conflicting journal replaced")
			}
		})
	}
}

func TestJournalLateConflictDuringUndo(t *testing.T) {
	j, _, _, list := fixture(t)
	doc := prepared(t, j)
	for i, entry := range doc.Records {
		list[i].image = clone(entry.After)
	}
	list[1].hook = func(_, _ Image) error { list[2].image = content("late-newer-edit"); return nil }
	if out, err := j.Recover(context.Background()); out != Blocked || !errors.Is(err, ErrRecovery) {
		t.Fatalf("%s %v", out, err)
	}
	if !equal(list[2].image, content("late-newer-edit")) {
		t.Fatal("late edit overwritten")
	}
	if doc, err := j.load(); err != nil || doc.State != "prepared" {
		t.Fatal("recovery record lost")
	}
}

func TestJournalCancellation(t *testing.T) {
	for _, point := range []string{"before", "between", "last", "recovery"} {
		t.Run(point, func(t *testing.T) {
			j, _, _, list := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if point == "before" {
				cancel()
			}
			if point == "between" {
				list[0].hook = func(_, _ Image) error { cancel(); return nil }
			}
			if point == "last" {
				list[2].hook = func(_, _ Image) error { cancel(); return nil }
			}
			if point == "recovery" {
				prepared(t, j)
				cancel()
				if out, err := j.Recover(ctx); out != Blocked || err == nil {
					t.Fatal("cancelled recovery accepted")
				}
				return
			}
			out, err := j.Execute(ctx, changes())
			switch point {
			case "last":
				if out != Applied || err != nil {
					t.Fatalf("%s %v", out, err)
				}
			case "before":
				if out != Clean || err == nil {
					t.Fatalf("%s %v", out, err)
				}
				expectOld(t, list)
			case "between":
				if out != RolledBack || err == nil {
					t.Fatalf("%s %v", out, err)
				}
				expectOld(t, list)
			}
		})
	}
}

func TestJournalUntrustedDataAndBindings(t *testing.T) {
	for _, mode := range []string{"truncated", "digest", "scope", "unknown", "duplicate", "case", "extra", "foreign-target", "path-target", "order", "schema", "oversize", "directory"} {
		t.Run(mode, func(t *testing.T) {
			j, path, targets, list := fixture(t)
			doc := prepared(t, j)
			switch mode {
			case "foreign-target":
				doc.Records[0].Target = "unknown"
			case "path-target":
				doc.Records[0].Target = "../secret"
			case "order":
				doc.Records[0], doc.Records[1] = doc.Records[1], doc.Records[0]
			case "schema":
				doc.Schema = 99
			case "scope":
				doc.Scope = sum([]byte("other-router"))
			}
			if err := j.save(doc); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, journalFile)
			raw, _ := os.ReadFile(file)
			switch mode {
			case "truncated":
				raw = raw[:len(raw)/2]
			case "digest":
				raw = bytes.Replace(raw, []byte(`"state":"prepared"`), []byte(`"state":"committed"`), 1)
			case "unknown":
				raw = append([]byte(`{"unexpected":1,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"state":"idle",`), raw[1:]...)
			case "case":
				raw = bytes.Replace(raw, []byte(`"scope"`), []byte(`"Scope"`), 1)
			case "extra":
				raw = append(raw, []byte(`{}`)...)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), maxJournalBytes+1)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "directory" {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(file, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if next, err := Open(path, testScope, targets); err == nil {
				_ = next.Close()
				t.Fatal("invalid journal accepted")
			}
			for _, target := range list {
				if target.writes != 0 {
					t.Fatal("target changed on invalid journal")
				}
			}
			if mode != "directory" {
				now, _ := os.ReadFile(file)
				if !bytes.Equal(now, raw) {
					t.Fatal("unknown journal overwritten")
				}
			}
		})
	}
}

func TestJournalLimitsAndSecretErrors(t *testing.T) {
	j, path, _, list := fixture(t)
	for _, input := range []map[string]Image{nil, {"../escape": content("x")}, {"a": {Exists: false, Data: []byte("not-absent")}}, {"a": content(strings.Repeat("x", MaxImageBytes+1))}} {
		if out, err := j.Execute(context.Background(), input); out != Clean || !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %v", out, err)
		}
	}
	for _, target := range list {
		if target.writes != 0 {
			t.Fatal("invalid plan wrote target")
		}
	}
	if _, err := os.Stat(filepath.Join(path, journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid plan created journal")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", content(injected.Error()), content(injected.Error())), injected.Error()) {
		t.Fatal("image formatting leaked")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", j, j), path) {
		t.Fatal("journal formatting leaked")
	}
	list[0].image = content(strings.Repeat("x", MaxImageBytes))
	list[1].image = content(strings.Repeat("y", MaxImageBytes))
	if out, err := j.Execute(context.Background(), map[string]Image{"a": content("a"), "b": content("b")}); out != Clean || !errors.Is(err, ErrInvalid) {
		t.Fatalf("%s %v", out, err)
	}
}

func TestJournalLeaseAndOwnership(t *testing.T) {
	j, path, targets, _ := fixture(t)
	if second, err := Open(path, testScope, targets); !errors.Is(err, ErrBusy) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("second writer admitted")
	}
	j = reopen(t, j, path, targets)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"", "foreign", leaseMarker[:8], leaseMarker + "extra"} {
		if err := os.WriteFile(filepath.Join(path, leaseFile), []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		if next, err := Open(path, testScope, targets); err == nil {
			_ = next.Close()
			t.Fatal("foreign lock accepted")
		}
		raw, _ := os.ReadFile(filepath.Join(path, leaseFile))
		if string(raw) != marker {
			t.Fatal("foreign lock overwritten")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if next, err := Open(path, testScope, targets); err == nil {
			_ = next.Close()
			t.Fatal("public journal directory accepted")
		}
	}
}

func TestJournalRestoredIdleHasValidChecksum(t *testing.T) {
	j, _, _, _ := fixture(t)
	prepared(t, j)
	if out, err := j.Recover(context.Background()); out != RolledBack || err != nil {
		t.Fatalf("%s %v", out, err)
	}
	doc, err := j.load()
	if err != nil || doc.State != "idle" {
		t.Fatal("invalid idle")
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
}

func TestJournalBusyAndClosed(t *testing.T) {
	j, _, _, list := fixture(t)
	entered := make(chan struct{})
	resume := make(chan struct{})
	list[0].hook = func(_, _ Image) error {
		close(entered)
		<-resume
		return nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := j.Execute(context.Background(), changes())
		done <- err
	}()
	<-entered
	// These must reject immediately, not queue another import or recovery.
	_, executeErr := j.Execute(context.Background(), changes())
	_, recoverErr := j.Recover(context.Background())
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(executeErr, ErrBusy) || !errors.Is(recoverErr, ErrBusy) {
		t.Fatal("concurrent journal operation was admitted")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Execute(context.Background(), changes()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed journal accepted import")
	}
	if _, err := j.Recover(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed journal accepted recovery")
	}
}
