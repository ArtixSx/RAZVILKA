package selfupdatejournal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedBinaryInventoryRejectsPendingOrTamperedImages(t *testing.T) {
	ctx := context.Background()
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	if _, err := f.store.RetainedBinaryImages(ctx); err == nil {
		t.Fatal("pending file transaction supplied writer capability")
	}
	f.install(t)
	if err := f.store.Accept(ctx, transaction, false, okay, okay); err != nil {
		t.Fatal(err)
	}
	images, err := f.store.RetainedBinaryImages(ctx)
	if err != nil || len(images) != 2 {
		t.Fatal("old/new controller inventory missing", err)
	}
	if err := os.WriteFile(images[0].Path, []byte("tampered image"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RetainedBinaryImages(ctx); err == nil {
		t.Fatal("damaged frozen controller accepted")
	}
}
func TestRetainedBinaryInventoryDoesNotConcealOrphanPreparation(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(f.journal, transaction), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RetainedBinaryImages(context.Background()); err == nil {
		t.Fatal("orphan file preparation ignored")
	}
}
