package dnscontrol

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func serviceSelectionFixture(t *testing.T) *Manager {
	t.Helper()
	m, err := New(filepath.Join(t.TempDir(), "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetServiceDraft("example", "private"); err != nil {
		t.Fatal(err)
	}
	return m
}

func selectionReview(t *testing.T, m *Manager, target string) ServiceSelectionReview {
	t.Helper()
	r, err := m.ReviewServiceSelection("example", target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServiceSelectionJointCommitAndDurableUndoPreserveDrafts(t *testing.T) {
	m := serviceSelectionFixture(t)
	r := selectionReview(t, m, "private")
	// Receipt is serialized before mutation, just like the adapter snapshot.
	data, _ := json.Marshal(r.Receipt())
	if err := m.CommitServiceSelection(r); err != nil {
		t.Fatal(err)
	}
	if m.Dirty() {
		t.Fatal("selected draft did not become applied")
	}
	if err := m.SetServiceDraft("example", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetServiceDraft("other", "security"); err != nil {
		t.Fatal(err)
	}
	m.doc.LastProbe = []ProbeResult{{Status: "pass"}}
	if err := m.saveLocked(); err != nil {
		t.Fatal(err)
	}
	m, err := New(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ServiceSelectionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := m.RestoreServiceSelection(receipt); err != nil {
			t.Fatal(err)
		}
	}
	s := m.Snapshot()
	if s.ServiceApplied["example"] != "" || s.ServiceDrafts["example"] != "unfiltered" || s.ServiceDrafts["other"] != "security" || len(s.LastProbe) != 1 || !s.Dirty {
		t.Fatalf("undo clobbered state: %+v", s)
	}
	if err := m.CommitServiceSelection(r); !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatalf("old review reused: %v", err)
	}
}

func TestServiceSelectionChangedDraftProviderAndGlobalDNSRefuse(t *testing.T) {
	for _, change := range []string{"draft", "global", "provider", "revision", "target"} {
		t.Run(change, func(t *testing.T) {
			m := serviceSelectionFixture(t)
			r := selectionReview(t, m, "private")
			switch change {
			case "draft":
				_ = m.SetServiceDraft("example", "security")
			case "global":
				_ = m.SetDraft("private")
			case "provider":
				r.ProfileIdentity = "stale"
			case "revision":
				r.Revision++
			case "target":
				r.Target = "unfiltered"
			}
			before := m.Snapshot()
			if err := m.CommitServiceSelection(r); !errors.Is(err, ErrServiceDNSChanged) {
				t.Fatalf("accepted changed review: %v", err)
			}
			if !reflect.DeepEqual(before, m.Snapshot()) {
				t.Fatal("refusal mutated settings")
			}
		})
	}
}

func TestServiceSelectionWriteFailureAndUnwrittenReceipt(t *testing.T) {
	m := serviceSelectionFixture(t)
	r := selectionReview(t, m, "private")
	before := cloneDocument(m.doc)
	path := m.Path
	m.Path = t.TempDir() // rename cannot replace an existing directory
	if err := m.CommitServiceSelection(r); err == nil {
		t.Fatal("write failure missing")
	}
	if !reflect.DeepEqual(before, m.doc) {
		t.Fatal("memory changed after failed write")
	}
	m.Path = path
	if err := m.RestoreServiceSelection(r.Receipt()); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.doc, reopened.doc) {
		t.Fatal("memory and durable settings diverged")
	}
}

func TestServiceSelectionUndoNeverOverwritesLaterAppliedGeneration(t *testing.T) {
	m := serviceSelectionFixture(t)
	r := selectionReview(t, m, "private")
	if err := m.CommitServiceSelection(r); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"unfiltered", "private"} {
		if err := m.SetServiceDraft("example", profile); err != nil {
			t.Fatal(err)
		}
		if err := m.CommitServiceSelection(selectionReview(t, m, profile)); err != nil {
			t.Fatal(err)
		}
	}
	before := cloneDocument(m.doc)
	if err := m.RestoreServiceSelection(r.Receipt()); !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatalf("undo overwrote later generation: %v", err)
	}
	if !reflect.DeepEqual(before, m.doc) {
		t.Fatal("undo clobbered later transaction")
	}
}

func TestServiceSelectionRetainRemoveRestoreAndBounds(t *testing.T) {
	m := serviceSelectionFixture(t)
	if err := m.CommitServiceSelection(selectionReview(t, m, "private")); err != nil {
		t.Fatal(err)
	}
	if err := m.SetServiceDraft("example", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	keep := selectionReview(t, m, "private")
	if err := m.CommitServiceSelection(keep); err != nil {
		t.Fatal(err)
	}
	if m.doc.ServiceRevisions["example"] != keep.Revision || !m.Dirty() {
		t.Fatal("retain consumed pending draft")
	}
	remove := selectionReview(t, m, "")
	if err := m.CommitServiceSelection(remove); err != nil {
		t.Fatal(err)
	}
	if err := m.RestoreServiceSelection(remove.Receipt()); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyServiceSelection("example", "private"); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().ServiceDrafts["example"] != "unfiltered" {
		t.Fatal("draft lost")
	}
	for _, target := range []string{"security", "automatic", "unknown", "xbox-dns"} {
		if _, err := m.ReviewServiceSelection("example", target); err == nil {
			t.Fatalf("unreviewed target accepted: %s", target)
		}
	}
	m.doc.ServiceRevisions["example"] = math.MaxUint64 - 1
	if _, err := m.ReviewServiceSelection("example", "private"); err == nil {
		t.Fatal("revision overflow")
	}
}

func TestServiceSelectionSchemaFourMigrationPreservesApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	old := `{"schema":4,"draft":{"profile_id":"automatic"},"applied":{"profile_id":"automatic"},"service_drafts":{"example":"unfiltered"},"service_applied":{"example":"private"}}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	r := selectionReview(t, m, "unfiltered")
	if r.Applied != "private" || r.Revision != 0 {
		t.Fatal(r)
	}
	if err := m.CommitServiceSelection(r); err != nil {
		t.Fatal(err)
	}
	m, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RestoreServiceSelection(r.Receipt()); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().Schema != schema {
		t.Fatal("schema not migrated")
	}
}
