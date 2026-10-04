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

func TestRetainedBinaryInventoryRequiresCanonicalPointerMarkerAndController(t *testing.T) {
	for _, kind := range []string{"pointer", "marker", "missing-marker", "no-controller"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureAt(t, t.TempDir())
			if kind == "no-controller" {
				f.files = f.files[1:]
			}
			f.prepare(t)
			f.install(t)
			if err := f.store.Accept(context.Background(), transaction, false, okay, okay); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "pointer":
				if err := os.WriteFile(filepath.Join(f.journal, "current.json"), []byte(`{"schema":1,"schema":1,"id":"`+transaction+`"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				if err := os.WriteFile(filepath.Join(f.journal, ".writer.lock"), []byte("foreign marker"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-marker":
				if err := os.Remove(filepath.Join(f.journal, ".writer.lock")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.RetainedBinaryImages(context.Background()); err == nil {
				t.Fatal("incomplete controller evidence accepted", kind)
			}
		})
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
