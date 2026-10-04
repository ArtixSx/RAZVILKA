package strategylab

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const compatibilityFixtureSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func compatibilityFilesFixture(t *testing.T) (string, []string, compatibilityReview) {
	t.Helper()
	root := t.TempDir()
	binary := filepath.Join(root, "nfqws2")
	for _, name := range []string{"nfqws2", "zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "tls_clienthello.bin"} {
		// These are digest-only data files. No binary or Lua is executed.
		if err := os.WriteFile(filepath.Join(root, name), []byte("abc"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := compatibilityBase(root)
	program, assets, err := compatibilityCaptureFiles(binary, base)
	if err != nil {
		t.Fatal(err)
	}
	return binary, base, compatibilityReview{Binary: program, Assets: assets, BaseArguments: slices.Clone(base)}
}

func TestCompatibilitySupervisedFileDigestBounds(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reviewed.data")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{3, 4} {
		binding, err := compatibilityFileBindingAt(path, limit)
		if err != nil || binding.Path != path || binding.Size != 3 || binding.SHA256 != compatibilityFixtureSHA256 {
			t.Fatalf("actual bounded bytes were not bound: limit=%d binding=%+v err=%v", limit, binding, err)
		}
	}
	empty := filepath.Join(root, "empty.data")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		path  string
		limit int64
	}{
		{"over-size-bound", path, 2},
		{"zero-bound", path, 0},
		{"negative-bound", path, -1},
		{"empty-file", empty, 3},
		{"missing-file", filepath.Join(root, "missing.data"), 3},
		{"directory", root, 3},
		{"relative-path", filepath.Base(path), 3},
		{"empty-path", "", 3},
		{"unclean-path", root + string(os.PathSeparator) + "." + string(os.PathSeparator) + filepath.Base(path), 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binding, err := compatibilityFileBindingAt(tc.path, tc.limit)
			if err == nil || binding != (compatibilityFileBinding{}) {
				t.Fatalf("unsafe file acquired a binding: %+v err=%v", binding, err)
			}
		})
	}
}

func TestCompatibilitySupervisedFileDigestRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	path, link := filepath.Join(root, "reviewed.data"), filepath.Join(root, "linked.data")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("host cannot create the symlink fixture: %v", err)
	}
	if binding, err := compatibilityFileBindingAt(link, 3); err == nil || binding != (compatibilityFileBinding{}) {
		t.Fatalf("symlink acquired a reviewed file binding: %+v err=%v", binding, err)
	}
}

func TestCompatibilitySupervisedCapturesStandardAssetIdentity(t *testing.T) {
	binary, base, review := compatibilityFilesFixture(t)
	if review.Binary.Path != binary || review.Binary.Size != 3 || review.Binary.SHA256 != compatibilityFixtureSHA256 {
		t.Fatalf("wrong actual binary byte binding: %+v", review.Binary)
	}
	wantNames := []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "tls_clienthello.bin"}
	if len(review.Assets) != len(wantNames) {
		t.Fatalf("standard assets were omitted or mixed: %+v", review.Assets)
	}
	for i, name := range wantNames {
		binding := review.Assets[i]
		if binding.Path != filepath.Join(filepath.Dir(binary), name) || binding.Size != 3 || binding.SHA256 != compatibilityFixtureSHA256 {
			t.Fatalf("wrong asset identity at %d: %+v", i, binding)
		}
	}
	if err := compatibilityFilesUnchanged(review); err != nil {
		t.Fatal("fresh actual files invalidated their byte review", err)
	}
	if !slices.Equal(base, review.BaseArguments) {
		t.Fatal("capture changed immutable base arguments")
	}
}

func TestCompatibilitySupervisedDuplicatePathsDeduplicate(t *testing.T) {
	binary, base, review := compatibilityFilesFixture(t)
	duplicate := append(slices.Clone(base), base[0], base[1], base[3])
	duplicate = append(duplicate, "--blob=quic_initial:@"+review.Assets[3].Path)
	before := slices.Clone(duplicate)
	program, assets, err := compatibilityCaptureFiles(binary, duplicate)
	if err != nil || program != review.Binary || !slices.Equal(assets, review.Assets) || !slices.Equal(duplicate, before) {
		t.Fatalf("duplicate paths changed first-occurrence asset identity: program=%+v assets=%+v err=%v", program, assets, err)
	}
	review.BaseArguments = duplicate
	if err := compatibilityFilesUnchanged(review); err != nil {
		t.Fatal("duplicate path aliases changed an unchanged review", err)
	}
}

func TestCompatibilitySupervisedByteChangesInvalidateReview(t *testing.T) {
	for _, target := range []string{"binary", "zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "tls_clienthello.bin"} {
		for _, change := range []string{"same-size-preserved-time", "size", "removed"} {
			t.Run(target+"/"+change, func(t *testing.T) {
				binary, _, review := compatibilityFilesFixture(t)
				path := binary
				if target != "binary" {
					path = filepath.Join(filepath.Dir(binary), target)
				}
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "same-size-preserved-time":
					if err := os.WriteFile(path, []byte("abd"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
						t.Fatal(err)
					}
				case "size":
					if err := os.WriteFile(path, []byte("abcd"), 0600); err != nil {
						t.Fatal(err)
					}
				case "removed":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if err := compatibilityFilesUnchanged(review); err == nil {
					t.Fatal("changed actual file bytes retained compatibility review")
				}
			})
		}
	}
}

func TestCompatibilitySupervisedMissingAssetsRejectCapture(t *testing.T) {
	for _, name := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "tls_clienthello.bin"} {
		t.Run(name, func(t *testing.T) {
			binary, base, _ := compatibilityFilesFixture(t)
			if err := os.Remove(filepath.Join(filepath.Dir(binary), name)); err != nil {
				t.Fatal(err)
			}
			if _, assets, err := compatibilityCaptureFiles(binary, base); err == nil || len(assets) != 0 {
				t.Fatalf("missing Lua/blob produced a partial review: assets=%+v err=%v", assets, err)
			}
		})
	}
}

func TestCompatibilitySupervisedAssetLimitUsesActualSize(t *testing.T) {
	binary, base, review := compatibilityFilesFixture(t)
	path := review.Assets[3].Path
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, assets, err := compatibilityCaptureFiles(binary, base); err != nil || len(assets) != 4 || assets[3].Size != 4<<20 {
		t.Fatalf("actual asset limit rejected: assets=%+v err=%v", assets, err)
	}
	if err := os.Truncate(path, (4<<20)+1); err != nil {
		t.Fatal(err)
	}
	if _, assets, err := compatibilityCaptureFiles(binary, base); err == nil || len(assets) != 0 {
		t.Fatalf("oversized actual blob acquired a review: assets=%+v err=%v", assets, err)
	}
}

func TestCompatibilitySupervisedBinaryLimitUsesActualSize(t *testing.T) {
	binary, base, _ := compatibilityFilesFixture(t)
	if err := os.Truncate(binary, (64<<20)+1); err != nil {
		t.Fatal(err)
	}
	if program, assets, err := compatibilityCaptureFiles(binary, base); err == nil || program != (compatibilityFileBinding{}) || len(assets) != 0 {
		t.Fatalf("oversized actual binary acquired a review: program=%+v assets=%+v err=%v", program, assets, err)
	}
}
