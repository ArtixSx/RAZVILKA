package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func retainedNodeFixture(t *testing.T, xray bool) []byte {
	t.Helper()
	return retainedNodeMaterialFixture(t, false, xray)
}

func retainedXHTTPNodeFixture(t *testing.T) []byte {
	t.Helper()
	return retainedNodeMaterialFixture(t, true, false)
}

func retainedNodeMaterialFixture(t *testing.T, xhttp, xray bool) []byte {
	t.Helper()
	ctx := context.Background()
	path := t.TempDir()
	// testing.TempDir's numbered child directory follows the process umask.
	// NodeStore deliberately requires a private POSIX parent, even in fixtures.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal("private node fixture permissions:", err)
	}
	s, err := nodestore.Open(path)
	if err != nil {
		t.Fatal("open private node fixture:", err)
	}
	defer s.Close()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	material := "vless://123e4567-e89b-12d3-a456-426614174000@private-host.example:443?security=tls&sni=private-sni.example"
	if xhttp {
		material += "&type=xhttp&mode=packet-up&host=private-front.example&path=%2Ffixture"
	}
	nodes, err := s.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, material+"#private", at, time.Hour, false)
	if err != nil {
		t.Fatal("import private node fixture:", err)
	}
	if xray {
		id := nodes.Nodes[0].ID
		record := nodestore.CheckRecord{ProbeID: "history-pass", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: at, ExpiresAt: at.Add(30 * time.Minute)}
		if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
			t.Fatal("record exact Xray fixture check:", err)
		}
	}
	snapshot, err := s.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), snapshot.Content...)
}
func retainedFile(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func sealedRetainedJournal(t *testing.T, before, after restorejournal.Image) []byte {
	t.Helper()
	doc := retainedRestoreNodeJournal{Kind: "razvilka-private-restore", Schema: 1, Scope: digestBytes([]byte("trusted-scope")), ID: "0123456789abcdef0123456789abcdef", State: "prepared", Records: []retainedRestoreNodeRecord{{Target: "nodes", Before: before, After: after}}}
	unsigned, _ := json.Marshal(doc)
	doc.Digest = digestBytes(unsigned)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRetainedNodeHistoryMaximumIncludesBackupsAndBothRestoreSides(t *testing.T) {
	plain, xray := retainedNodeFixture(t, false), retainedNodeFixture(t, true)
	for _, where := range []string{"plain-backup", "restore-before", "restore-after", "directory-empty-before"} {
		t.Run(where, func(t *testing.T) {
			configRoot, stateRoot := t.TempDir(), t.TempDir()
			retainedFile(t, configRoot, "nodes-private/nodes.private.json", plain)
			switch where {
			case "plain-backup":
				retainedFile(t, stateRoot, "backups/old/nodes.private.json", xray)
			case "restore-before":
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: xray}, restorejournal.Image{Exists: true, Data: plain}))
			case "restore-after":
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: plain}, restorejournal.Image{Exists: true, Data: xray}))
			case "directory-empty-before":
				empty, _ := json.Marshal(directoryImage{Mode: 0700})
				tree, _ := json.Marshal(directoryImage{Mode: 0700, Entries: []directoryEntry{{Name: "nodes.private.json", Mode: 0600, Data: xray}}})
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: empty}, restorejournal.Image{Exists: true, Data: tree}))
			}
			before, _ := os.ReadFile(filepath.Join(configRoot, "nodes-private", "nodes.private.json"))
			required, err := RequiredRetainedNodeHistoryReadVersion(context.Background(), configRoot, stateRoot, validatedNodeHistoryRead)
			if err != nil || required != 2 {
				t.Fatal("retained Xray capability lost", err)
			}
			after, _ := os.ReadFile(filepath.Join(configRoot, "nodes-private", "nodes.private.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("read-only compatibility scan mutated live nodes")
			}
		})
	}
}

func TestRetainedNodeHistoryCorruptAndUnknownNeverDowngrade(t *testing.T) {
	plain := retainedNodeFixture(t, false)
	for _, kind := range []string{"corrupt-nodes", "future-node-schema", "journal-checksum", "journal-state", "journal-duplicate", "snapshot-incomplete", "cancelled", "unknown-reader"} {
		t.Run(kind, func(t *testing.T) {
			configRoot, stateRoot := t.TempDir(), t.TempDir()
			ctx := context.Background()
			retainedFile(t, configRoot, "nodes-private/nodes.private.json", plain)
			reader := NodeHistoryReader(validatedNodeHistoryRead)
			switch kind {
			case "corrupt-nodes":
				retainedFile(t, stateRoot, "backup/nodes.private.json", []byte("{}"))
			case "future-node-schema":
				retainedFile(t, stateRoot, "backup/nodes.private.json", bytes.Replace(plain, []byte(`"schema":4`), []byte(`"schema":5`), 1))
			case "journal-checksum", "journal-state", "journal-duplicate":
				data := sealedRetainedJournal(t, restorejournal.Image{}, restorejournal.Image{Exists: true, Data: plain})
				if kind == "journal-checksum" {
					data[len(data)-3] ^= 1
				}
				if kind == "journal-state" {
					data = bytes.Replace(data, []byte("prepared"), []byte("future-state"), 1)
				}
				if kind == "journal-duplicate" {
					data = bytes.Replace(data, []byte("{"), []byte("{\"schema\":1,"), 1)
				}
				retainedFile(t, stateRoot, "restore/restore.private.json", data)
			case "snapshot-incomplete":
				data, _ := json.Marshal(privateFileSnapshot{Schema: 1, ID: "0123456789abcdef0123456789abcdef", Images: map[string]restorejournal.Image{"nodes": {}}})
				retainedFile(t, stateRoot, "job/private-snapshot.json", data)
				retainedFile(t, stateRoot, "job/private-snapshot.sha256", []byte(digestBytes(data)))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unknown-reader":
				reader = func(nodestore.PrivateSnapshot) (int, error) { return nodestore.ExactHistoryReadVersion + 1, nil }
			}
			required, err := RequiredRetainedNodeHistoryReadVersion(ctx, configRoot, stateRoot, reader)
			if err == nil || required != 0 {
				t.Fatal("unknown/corrupt retained state authorized a downgrade")
			}
		})
	}
}

func TestRetainedNodeHistoryUncheckedXHTTPMaterialRequiresReader3Everywhere(t *testing.T) {
	plain, raw, xhttp := retainedNodeFixture(t, false), retainedNodeFixture(t, true), retainedXHTTPNodeFixture(t)
	for _, test := range []struct {
		where    string
		required int
	}{
		{"legacy-live", 1}, {"raw-live", 2}, {"xhttp-live", 3},
		{"retained-backup", 3}, {"restore-before", 3}, {"restore-after", 3},
		{"directory-restore-before", 3}, {"private-snapshot", 3},
	} {
		t.Run(test.where, func(t *testing.T) {
			ctx := context.Background()
			configRoot, stateRoot := t.TempDir(), t.TempDir()
			live := plain
			if test.where == "raw-live" {
				live = raw
			} else if test.where == "xhttp-live" {
				live = xhttp
			}
			retainedFile(t, configRoot, "nodes-private/nodes.private.json", live)
			treeBytes, err := json.Marshal(directoryImage{Mode: 0700, Entries: []directoryEntry{{Name: "nodes.private.json", Mode: 0600, Data: xhttp}}})
			if err != nil {
				t.Fatal(err)
			}
			switch test.where {
			case "retained-backup":
				retainedFile(t, stateRoot, "backups/deleted-live/nodes.private.json", xhttp)
			case "restore-before":
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: xhttp}, restorejournal.Image{Exists: true, Data: raw}))
			case "restore-after":
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: raw}, restorejournal.Image{Exists: true, Data: xhttp}))
			case "directory-restore-before":
				retainedFile(t, stateRoot, "restore/restore.private.json", sealedRetainedJournal(t, restorejournal.Image{Exists: true, Data: treeBytes}, restorejournal.Image{}))
			case "private-snapshot":
				snapshot := privateFileSnapshot{Schema: 2, ID: "0123456789abcdef0123456789abcdef", Images: map[string]restorejournal.Image{}}
				for name := range fileMutablePrivateDirectories {
					snapshot.Images[name] = restorejournal.Image{}
				}
				for name := range filePrivateFiles {
					snapshot.Images[name] = restorejournal.Image{}
				}
				snapshot.Images["nodes"] = restorejournal.Image{Exists: true, Data: treeBytes}
				data, err := json.Marshal(snapshot)
				if err != nil || validatePrivateSnapshot(snapshot) != nil {
					t.Fatal("private snapshot fixture", err)
				}
				retainedFile(t, stateRoot, "self-update/retained/private-snapshot.json", data)
				retainedFile(t, stateRoot, "self-update/retained/private-snapshot.sha256", []byte(digestBytes(data)))
			}
			configBefore, err := readDirectoryImage(ctx, configRoot)
			if err != nil {
				t.Fatal(err)
			}
			stateBefore, err := readDirectoryImage(ctx, stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			required, err := RequiredRetainedNodeHistoryReadVersion(ctx, configRoot, stateRoot, validatedNodeHistoryRead)
			if err != nil || required != test.required {
				t.Fatal("typed material/history capability lost", required, err)
			}
			configAfter, err := readDirectoryImage(ctx, configRoot)
			if err != nil || !bytes.Equal(configBefore.Data, configAfter.Data) {
				t.Fatal("compatibility scan mutated live private tree", err)
			}
			stateAfter, err := readDirectoryImage(ctx, stateRoot)
			if err != nil || !bytes.Equal(stateBefore.Data, stateAfter.Data) {
				t.Fatal("compatibility scan rewrote/cleared retained images", err)
			}
		})
	}
}
