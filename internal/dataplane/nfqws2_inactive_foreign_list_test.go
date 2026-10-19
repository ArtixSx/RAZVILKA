package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The package installs its exclude lists as its own user. A block-free stock
// list proves nothing of RAZVILKA runs, whoever owns it; a list that holds a
// RAZVILKA block still refuses the inactivity proof.
func TestNFQWS2InactivityAcceptsForeignOwnedBlockFreeLists(t *testing.T) {
	f := newNFQWS2InactiveFixture(t)
	lists := f.a.ownedListPaths()
	for _, path := range lists[2:] {
		if err := os.WriteFile(path, []byte("stock.example\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	owned := f.proof.protected
	// Model the package owner: the strict check refuses exactly those files.
	f.proof.protected = func(info os.FileInfo, directory, private bool) bool {
		if !directory && info != nil && (info.Name() == filepath.Base(lists[2]) || info.Name() == filepath.Base(lists[3])) {
			return false
		}
		return owned(info, directory, private)
	}
	f.proof.foreignList = nil
	if _, err := nfqws2ReadInactiveFiles(context.Background(), f.a, f.proof); err == nil {
		t.Fatal("the strict owner check no longer covers the lists")
	}
	// Windows models have no POSIX mode; the Linux reader also refuses group
	// or other write access.
	f.proof.foreignList = func(info os.FileInfo) bool { return info != nil && info.Mode().IsRegular() }
	if _, err := nfqws2ReadInactiveFiles(context.Background(), f.a, f.proof); err != nil {
		t.Fatal("a block-free stock list of another owner refused the proof:", err)
	}
	if err := os.WriteFile(lists[2], []byte("stock.example\n"+managedBegin+"\nx.example\n"+managedEnd+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nfqws2ReadInactiveFiles(context.Background(), f.a, f.proof); err == nil {
		t.Fatal("a list holding a RAZVILKA block passed the inactivity proof")
	}
}
