package warp

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestNativeRestoreCannotRewindPreexistingLocalEnrollment(t *testing.T) {
	m := newNativeTestManager(t)
	calls := 0
	installNativeTestAPI(m, &calls, true, nil)
	if _, err := m.Generate(context.Background(), true, false); err != nil {
		t.Fatal(err)
	}
	installNativeTestAPI(m, &calls, false, context.DeadlineExceeded)
	if _, err := m.Generate(context.Background(), true, true); !errors.Is(err, ErrEnrollmentPending) {
		t.Fatal(err)
	}
	session, err := m.BeginNativeRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := session.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	document, err := nativeenrollment.Decode(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range document.Files {
		for _, mutation := range []string{"remove", "replace"} {
			afterDoc, _ := nativeenrollment.Decode(before)
			if mutation == "remove" {
				afterDoc.Delete(file.Name)
			} else {
				afterDoc.Set(file.Name, []byte("replaced"))
			}
			data, err := nativeenrollment.Encode(afterDoc)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.CompareAndSwap(context.Background(), before, restorejournal.Image{Exists: true, Data: data}); !errors.Is(err, nativeenrollment.ErrConflict) {
				t.Fatalf("%s of initial %s allowed: %v", mutation, file.Name, err)
			}
		}
	}
	after, _ := session.Read(context.Background())
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("rejected rollback changed retained state")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Read(context.Background()); !errors.Is(err, ErrEnrollmentStore) {
		t.Fatal("closed session still usable")
	}
	restarted := New(m.Root, m.BackupRoot, m.EngineConfigs)
	installNativeTestAPI(restarted, &calls, true, nil)
	if _, err := restarted.Generate(context.Background(), true, true); !errors.Is(err, ErrEnrollmentPending) || calls != 2 {
		t.Fatal("restore guard permitted replay", err, calls)
	}
}

func TestNativeRestoreAllowsRollbackOfOnlyUncommittedImportedBytes(t *testing.T) {
	for _, existing := range []bool{false, true} {
		m := newNativeTestManager(t)
		calls := 0
		if existing {
			installNativeTestAPI(m, &calls, true, nil)
			if _, err := m.Generate(context.Background(), true, false); err != nil {
				t.Fatal(err)
			}
		}
		session, err := m.BeginNativeRestore(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		before, err := session.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		document, _ := nativeenrollment.Decode(before)
		// Added bytes are inert, copy-only private-import material. There was no
		// remote POST in this session, so journal rollback may remove only these.
		document.Set("attempt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/response.private.json", []byte("imported-response"))
		snapshot, err := nativeenrollment.SnapshotOf(document)
		if err != nil {
			t.Fatal(err)
		}
		after, err := session.MergeImage(context.Background(), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := session.CompareAndSwap(context.Background(), before, after); err != nil {
			t.Fatal(err)
		}
		if err := session.CompareAndSwap(context.Background(), after, before); err != nil {
			t.Fatal("copy-only rollback blocked", err)
		}
		actual, err := session.Read(context.Background())
		if err != nil || actual.Exists != before.Exists || !bytes.Equal(actual.Data, before.Data) {
			t.Fatal("before-image not restored exactly")
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
