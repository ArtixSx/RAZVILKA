package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Writer-only regression: real atomic publication and held inodes, without
// issuing a terminal, native retirement or a runtime admission capability.
func TestXrayStoppedPlanWriterRejectsSameBytesReplacementWithoutAdoption(t *testing.T) {
	path := t.TempDir()
	root, anchor, err := openNetworkPolicyObservationRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	plan, err := BuildAt(Input{Revision: 2}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := &xrayStoppedPlanPublication{manager: New(path), root: root, path: path, anchor: anchor, plan: plan, data: data}
	defer func() {
		for _, held := range p.files {
			if held.file != nil {
				held.file.Close()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := p.publish(ctx); err != nil {
		t.Fatal(err)
	}
	original := p.files[1].info
	if err := root.WriteAtomic(xrayStoppedPlanNames[1], data, 0600); err != nil {
		t.Fatal(err)
	}
	replaced, err := os.Lstat(filepath.Join(path, xrayStoppedPlanNames[1]))
	if err != nil || os.SameFile(original, replaced) {
		t.Fatal("replacement fixture did not replace the inode", err)
	}
	if err := p.publish(ctx); !errors.Is(err, ErrExecutionJournal) {
		t.Fatal("same bytes supplied a replacement publication owner", err)
	}
	if p.files[1].info != original || p.failure == nil {
		t.Fatal("failed publication adopted a path or lost its sticky refusal")
	}
	after, err := os.Lstat(filepath.Join(path, xrayStoppedPlanNames[1]))
	if err != nil || !os.SameFile(replaced, after) {
		t.Fatal("refused publication overwrote the replacement", err)
	}
}

func TestXrayStoppedPlanPublicationRequiresOriginalTerminalBeforeWriting(t *testing.T) {
	root := t.TempDir()
	m := New(root)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, terminal := range []*XraySelectedTCPTerminal{nil, {}, {closed: true}} {
		if _, err := m.CommitRetiredManagedXraySelectedTCP(ctx, terminal, nil, 2); !errors.Is(err, ErrXrayOperationOwner) {
			t.Fatal("cold documentary terminal supplied an issuer", err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused terminal wrote a stopped plan", entries, err)
	}
}
