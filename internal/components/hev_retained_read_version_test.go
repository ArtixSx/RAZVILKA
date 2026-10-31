package components

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func hevRetainedBytes(doc hevRetainedDocument) []byte {
	doc.Digest = ""
	unsigned, _ := json.Marshal(doc)
	doc.Digest = digest(unsigned)
	raw, _ := json.Marshal(doc)
	return raw
}

func TestHEVRetainedTypedEnvelopeRejectsUnknownTargetsAndSchemas(t *testing.T) {
	base := hevRetainedDocument{Kind: "razvilka-private-restore", Schema: 1, Scope: strings.Repeat("a", 64), ID: strings.Repeat("b", 32), State: "prepared", Records: []hevRetainedRecord{{Target: "a_binary", After: restorejournal.Image{Exists: true, Data: []byte("model verified bytes")}}}}
	if !validHEVRetainedJournal(hevRetainedBytes(base)) {
		t.Fatal("closed HEV journal format lost")
	}
	for _, mutate := range []func(*hevRetainedDocument){func(d *hevRetainedDocument) { d.Schema = 2 }, func(d *hevRetainedDocument) { d.Kind = "foreign" }, func(d *hevRetainedDocument) { d.Records[0].Target = "arbitrary_path" }, func(d *hevRetainedDocument) { d.State = "future" }, func(d *hevRetainedDocument) { d.Records[0].After.Exists = false }, func(d *hevRetainedDocument) { d.Records = append(d.Records, d.Records[0]) }} {
		copy := base
		copy.Records = append([]hevRetainedRecord(nil), base.Records...)
		mutate(&copy)
		if validHEVRetainedJournal(hevRetainedBytes(copy)) {
			t.Fatal("unknown format admitted")
		}
	}
	raw := hevRetainedBytes(base)
	if validHEVRetainedJournal(append(raw, '\n')) {
		t.Fatal("noncanonical journal admitted")
	}
	if validHEVRetainedJournal([]byte(strings.Replace(string(raw), `"kind":`, `"unknown":1,"kind":`, 1))) {
		t.Fatal("unknown field admitted")
	}
}

func TestHEVRetainedReaderObservesOriginalWriterPublicationCuts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("original private metadata ownership requires Linux")
	}
	m, spec, info := hevReleaseFixture(t)
	session, err := m.openHEVRelease(true)
	if err != nil {
		t.Fatal(err)
	}
	// The permanent original marker alone already requires reader5. Reading it
	// while the original journal lease is held must not initialize or lock again.
	version, markerSeal, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
	if err != nil || version != HEVReleaseReadVersion || len(markerSeal) != 64 {
		t.Fatal(version, err)
	}
	if err := session.close(); err != nil {
		t.Fatal(err)
	}
	observed := false
	m.updateFault = func(phase string) error {
		if phase == "hev:before:a_binary" {
			v, s, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
			if err != nil || v != HEVReleaseReadVersion || s == markerSeal {
				t.Fatalf("actual prepared publication not read under original writer: %d %v", v, err)
			}
			observed = true
		}
		return nil
	}
	if _, err := m.installHEVImage(context.Background(), spec, info, []byte("model verified bytes")); err != nil || !observed {
		t.Fatal("install cut not observed", err)
	}
	version, first, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
	if err != nil || version != 5 || first == markerSeal {
		t.Fatal(version, err)
	}
	_, second, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir)
	if err != nil || second != first {
		t.Fatal("passive inspection changed history", err)
	}
}

func TestHEVRetainedReaderPreservesMissingUnknownAndForeignMetadata(t *testing.T) {
	for _, mutation := range []string{"missing-marker", "foreign-marker", "future-journal", "unknown-entry", "public-directory", "hardlink-marker"} {
		t.Run(mutation, func(t *testing.T) {
			if runtime.GOOS != "linux" {
				t.Skip("original private metadata ownership requires Linux")
			}
			m, _, _ := hevReleaseFixture(t)
			session, err := m.openHEVRelease(true)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.close(); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(m.StateDir, "hev-release-v1")
			marker := filepath.Join(root, ".restore.lock")
			switch mutation {
			case "missing-marker":
				err = os.Remove(marker)
			case "foreign-marker":
				err = os.WriteFile(marker, []byte("foreign"), 0600)
			case "future-journal":
				err = os.WriteFile(filepath.Join(root, "restore.private.json"), hevRetainedBytes(hevRetainedDocument{Kind: "razvilka-private-restore", Schema: 2, Scope: strings.Repeat("a", 64), State: "idle"}), 0600)
			case "unknown-entry":
				err = os.WriteFile(filepath.Join(root, "extra"), []byte("unknown"), 0600)
			case "public-directory":
				err = os.Chmod(root, 0755)
			case "hardlink-marker":
				err = os.Link(marker, filepath.Join(m.StateDir, "foreign-alias"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if version, _, err := InspectRetainedManagedUpdateReadVersion(context.Background(), m.StateDir); !errors.Is(err, ErrRetainedManagedUpdate) || version != 0 {
				t.Fatal("unknown metadata admitted", version, err)
			}
			if mutation == "missing-marker" {
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("reader manufactured writer marker")
				}
			}
		})
	}
}
