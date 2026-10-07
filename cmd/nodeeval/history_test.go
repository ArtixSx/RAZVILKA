package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func isolatedFixture(t *testing.T) (*workspace, *nodestore.Store) {
	t.Helper()
	w, err := newWorkspace(filepath.Join(t.TempDir(), "isolated"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	s, err := w.createStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return w, s
}

func TestIsolatedHistoryAdmissionUsesTypedReaderWithoutLiveHistoryAuthority(t *testing.T) {
	ctx := context.Background()
	live := privateStoreFixture(t, 1)
	before, err := live.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w, store := isolatedFixture(t)
	admit, err := w.historyAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= nodestore.ExactHistoryReadVersion; version++ {
		if err := admit(ctx, version); err != nil {
			t.Fatal("current reader capability refused in owned fresh store", version)
		}
	}
	for _, version := range []int{0, nodestore.ExactHistoryReadVersion + 1} {
		if admit(ctx, version) == nil {
			t.Fatal("unknown reader capability granted")
		}
	}
	// Actual canonical material requires reader 3 before any check exists.
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@private-xhttp.example:443?security=tls&sni=private-sni.example&type=xhttp&mode=packet-up&host=front.example&path=%2Ftunnel"
	version, err := nodestore.RequiredImportReadVersion(raw, false)
	if err != nil || version != 3 || admit(ctx, version) != nil {
		t.Fatal("XHTTP was downgraded to reader 1", version, err)
	}
	snap, err := store.Import(ctx, nodestore.Source{ID: "isolated-test", Kind: "community"}, raw, time.Now(), time.Hour, false)
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Transport != "xhttp" || snap.Nodes[0].Health.State != "not_checked" || len(snap.Nodes[0].Health.History) != 0 {
		t.Fatal("canonical import lost transport or gained check authority", err)
	}
	if version, err := store.RequiredHistoryReadVersion(ctx); err != nil || version != 3 {
		t.Fatal("actual stored reader fence disappeared", version, err)
	}
	if err := admit(ctx, 3); err != nil {
		t.Fatal("guard cannot read its own accepted XHTTP state")
	}
	if _, err := w.historyAdmission(ctx); err == nil {
		t.Fatal("nonempty store manufactured fresh admission")
	}
	if _, err := w.createStore(); err == nil {
		t.Fatal("store could be replaced after authority construction")
	}
	after, err := live.ExportPrivate(ctx)
	if err != nil || !bytes.Equal(before.Content, after.Content) {
		t.Fatal("isolated grant changed live history", err)
	}
	// Validation reads real state on every call; corruption is never reader 1.
	path := filepath.Join(w.storePath, "nodes.private.json")
	corrupt := []byte(`{"schema":999,"owner":"razvilka-nodes"}`)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if admit(ctx, 1) == nil {
		t.Fatal("future/corrupt private state granted a legacy write")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(corrupt, unchanged) {
		t.Fatal("failed admission repaired or replaced corrupt state", err)
	}
}

func TestIsolatedHistoryAdmissionRefusesCanceledClosedOrDifferentDirectory(t *testing.T) {
	ctx := context.Background()
	w, store := isolatedFixture(t)
	admit, err := w.historyAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if admit(canceled, 3) == nil || admit(nil, 3) == nil {
		t.Fatal("canceled or absent context gained admission")
	}
	if _, err := w.historyAdmission(canceled); err == nil {
		t.Fatal("canceled constructor granted authority")
	}
	invocation, stop := context.WithCancel(ctx)
	bound, err := w.historyAdmission(invocation)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if bound(ctx, 3) == nil {
		t.Fatal("fresh authority outlived its invocation")
	}
	other, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, storeInfo := w.info, w.storeInfo
	w.info = other
	if admit(ctx, 3) == nil {
		t.Fatal("different workspace directory identity accepted")
	}
	w.info, w.storeInfo = rootInfo, other
	if admit(ctx, 3) == nil {
		t.Fatal("different store directory identity accepted")
	}
	w.storeInfo = storeInfo
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if admit(ctx, 3) == nil {
		t.Fatal("closed original store granted authority")
	}
}

func TestExistingStoreAliasCannotContainWorkspaceWrites(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "live")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	if !separatedExistingStore(filepath.Join(base, "outside"), store) || separatedExistingStore(filepath.Join(store, "inside"), store) {
		t.Fatal("existing store boundary is wrong")
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(store, alias); err != nil {
		t.Skip("directory symlink unavailable on this host")
	}
	root := filepath.Join(alias, "new-workspace")
	if separatedExistingStore(root, store) {
		t.Fatal("alias permitted writes under live store")
	}
	var output bytes.Buffer
	if run(context.Background(), []string{"-root", root, "-store", store}, &output) != 1 {
		t.Fatal("alias invocation accepted")
	}
	if _, err := os.Lstat(filepath.Join(store, "new-workspace")); !os.IsNotExist(err) {
		t.Fatal("refused invocation created a live-store descendant")
	}
}

func TestReportIsPrivateExclusiveAndExistingStoreLeaseIsRespected(t *testing.T) {
	w, store := isolatedFixture(t)
	if _, err := nodestore.Open(w.storePath); err == nil {
		t.Fatal("existing store's OS lease was bypassed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := w.reportFile()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("owned report\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.reportFile(); err == nil {
		t.Fatal("existing report was overwritten")
	}
	data, err := os.ReadFile(filepath.Join(w.path, "results.jsonl"))
	if err != nil || string(data) != "owned report\n" {
		t.Fatal("exclusive report changed", err)
	}
}
