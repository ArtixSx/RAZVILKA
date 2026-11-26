package strategylab

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func compatibilityApprovalFixture(t *testing.T) CompatibilityApproval {
	t.Helper()
	binary, base, files := compatibilityFilesFixture(t)
	approval := CompatibilityApproval{
		BinaryPath: binary, BinarySHA256: compatibilityFixtureSHA256,
		BaseArguments: slices.Clone(base), ControlPath: filepath.Join(filepath.Dir(binary), "control.state"),
		InstallationID: "0123456789abcdef0123456789abcdef", Sequence: 7,
	}
	for _, file := range files.Assets {
		// Expected digests are fixed fixture evidence, never learned by hashing
		// the launch files. These data-only files are not executed as NFQWS/Lua.
		approval.Assets = append(approval.Assets, CompatibilityApprovedAsset{Path: file.Path, SHA256: compatibilityFixtureSHA256})
	}
	return approval
}

func TestCompatibilityApprovalMatchesExplicitEvidence(t *testing.T) {
	approval := compatibilityApprovalFixture(t)
	review, err := compatibilityReviewApproved(approval)
	if err != nil {
		t.Fatal(err)
	}
	if review.Binary.Path != approval.BinaryPath || review.Binary.SHA256 != compatibilityFixtureSHA256 || review.Binary.Size != 3 {
		t.Fatalf("wrong approved binary bytes: %+v", review.Binary)
	}
	if review.ControlPath != approval.ControlPath || review.InstallationID != approval.InstallationID || review.Sequence != approval.Sequence || !slices.Equal(review.BaseArguments, approval.BaseArguments) {
		t.Fatal("approved control/installation/base binding changed", review)
	}
	if len(review.Assets) != len(approval.Assets) {
		t.Fatal("approved assets omitted", review.Assets)
	}
	for i, file := range review.Assets {
		if file.Path != approval.Assets[i].Path || file.SHA256 != compatibilityFixtureSHA256 || file.Size != 3 {
			t.Fatalf("wrong approved asset bytes at %d: %+v", i, file)
		}
	}
	if err := validateCompatibilityReview(review); err != nil {
		t.Fatal("approved actual review failed its model", err)
	}
}

func TestCompatibilityApprovalDoesNotRequireManagedBasename(t *testing.T) {
	approval := compatibilityApprovalFixture(t)
	managed := filepath.Join(filepath.Dir(approval.BinaryPath), "rzv-nfqws2")
	if err := os.Rename(approval.BinaryPath, managed); err != nil {
		t.Fatal(err)
	}
	approval.BinaryPath = managed
	review, err := compatibilityReviewApproved(approval)
	if err != nil || review.Binary.Path != managed {
		t.Fatalf("explicit approved managed path rejected: %+v err=%v", review, err)
	}
}

func TestCompatibilityApprovalRejectsInvalidEvidence(t *testing.T) {
	changeSHA := strings.Repeat("0", 64)
	cases := []struct {
		name   string
		change func(*CompatibilityApproval)
	}{
		{"zero-approval", func(a *CompatibilityApproval) { *a = CompatibilityApproval{} }},
		{"binary-digest-absent", func(a *CompatibilityApproval) { a.BinarySHA256 = "" }},
		{"binary-digest-different", func(a *CompatibilityApproval) { a.BinarySHA256 = changeSHA }},
		{"binary-digest-uppercase", func(a *CompatibilityApproval) { a.BinarySHA256 = strings.ToUpper(a.BinarySHA256) }},
		{"binary-digest-nonhex", func(a *CompatibilityApproval) { a.BinarySHA256 = strings.Repeat("g", 64) }},
		{"binary-digest-short", func(a *CompatibilityApproval) { a.BinarySHA256 = a.BinarySHA256[1:] }},
		{"binary-path-relative", func(a *CompatibilityApproval) { a.BinaryPath = filepath.Base(a.BinaryPath) }},
		{"binary-path-unclean", func(a *CompatibilityApproval) {
			a.BinaryPath = filepath.Dir(a.BinaryPath) + string(os.PathSeparator) + "." + string(os.PathSeparator) + filepath.Base(a.BinaryPath)
		}},
		{"binary-path-null", func(a *CompatibilityApproval) { a.BinaryPath += "\x00" }},
		{"binary-path-invalid-utf8", func(a *CompatibilityApproval) { a.BinaryPath += "\xff" }},
		{"assets-absent", func(a *CompatibilityApproval) { a.Assets = nil }},
		{"asset-missing", func(a *CompatibilityApproval) { a.Assets = a.Assets[:len(a.Assets)-1] }},
		{"asset-extra", func(a *CompatibilityApproval) { a.Assets = append(a.Assets, a.Assets[0]) }},
		{"assets-reordered", func(a *CompatibilityApproval) { a.Assets[0], a.Assets[1] = a.Assets[1], a.Assets[0] }},
		{"asset-duplicate-replaces-required", func(a *CompatibilityApproval) { a.Assets[1] = a.Assets[0] }},
		{"asset-digest-absent", func(a *CompatibilityApproval) { a.Assets[0].SHA256 = "" }},
		{"asset-digest-different", func(a *CompatibilityApproval) { a.Assets[0].SHA256 = changeSHA }},
		{"asset-digest-uppercase", func(a *CompatibilityApproval) { a.Assets[0].SHA256 = strings.ToUpper(a.Assets[0].SHA256) }},
		{"asset-path-relative", func(a *CompatibilityApproval) { a.Assets[0].Path = filepath.Base(a.Assets[0].Path) }},
		{"asset-path-different", func(a *CompatibilityApproval) { a.Assets[0].Path = a.Assets[1].Path }},
		{"base-empty", func(a *CompatibilityApproval) { a.BaseArguments = nil }},
		{"base-extra-runtime", func(a *CompatibilityApproval) { a.BaseArguments = append(a.BaseArguments, "--qnum=0") }},
		{"base-custom-lua", func(a *CompatibilityApproval) { a.BaseArguments[0] = "--lua-init=return true" }},
		{"base-library-not-standard", func(a *CompatibilityApproval) {
			a.BaseArguments[0] = "--lua-init=@" + filepath.Join(filepath.Dir(a.BinaryPath), "custom.lua")
			a.Assets[0].Path = strings.TrimPrefix(a.BaseArguments[0], "--lua-init=@")
		}},
		{"base-too-many", func(a *CompatibilityApproval) {
			for len(a.BaseArguments) <= compatibilityMaxFiles {
				a.BaseArguments = append(a.BaseArguments, a.BaseArguments[0])
			}
		}},
		{"base-path-relative", func(a *CompatibilityApproval) {
			a.BaseArguments[0] = "--lua-init=@zapret-lib.lua"
			a.Assets[0].Path = "zapret-lib.lua"
		}},
		{"control-empty", func(a *CompatibilityApproval) { a.ControlPath = "" }},
		{"control-relative", func(a *CompatibilityApproval) { a.ControlPath = "control.state" }},
		{"control-unclean", func(a *CompatibilityApproval) {
			a.ControlPath = filepath.Dir(a.ControlPath) + string(os.PathSeparator) + "." + string(os.PathSeparator) + filepath.Base(a.ControlPath)
		}},
		{"control-newline", func(a *CompatibilityApproval) { a.ControlPath += "\n" }},
		{"installation-empty", func(a *CompatibilityApproval) { a.InstallationID = "" }},
		{"installation-short", func(a *CompatibilityApproval) { a.InstallationID = a.InstallationID[1:] }},
		{"installation-uppercase", func(a *CompatibilityApproval) { a.InstallationID = strings.ToUpper(a.InstallationID) }},
		{"installation-nonhex", func(a *CompatibilityApproval) { a.InstallationID = strings.Repeat("z", 32) }},
		{"sequence-zero", func(a *CompatibilityApproval) { a.Sequence = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			approval := compatibilityApprovalFixture(t)
			tc.change(&approval)
			review, err := compatibilityReviewApproved(approval)
			if err == nil || !compatibilityReviewsEqual(review, compatibilityReview{}) {
				t.Fatalf("invalid declaration acquired an approved review: %+v err=%v", review, err)
			}
		})
	}
}

func TestCompatibilityApprovalByteChangesDoNotCreateTrust(t *testing.T) {
	for i, name := range []string{"binary", "lib", "antidpi", "auto", "blob"} {
		t.Run(name, func(t *testing.T) {
			approval := compatibilityApprovalFixture(t)
			path := approval.BinaryPath
			if i > 0 {
				path = approval.Assets[i-1].Path
			}
			if err := os.WriteFile(path, []byte("abd"), 0600); err != nil {
				t.Fatal(err)
			}
			review, err := compatibilityReviewApproved(approval)
			if err == nil || !compatibilityReviewsEqual(review, compatibilityReview{}) {
				t.Fatalf("locally hashed changed bytes acquired approval: %+v err=%v", review, err)
			}
		})
	}
}

func TestCompatibilityApprovalReturnedReviewIsDetached(t *testing.T) {
	approval := compatibilityApprovalFixture(t)
	review, err := compatibilityReviewApproved(approval)
	if err != nil {
		t.Fatal(err)
	}
	expected := review
	expected.BaseArguments = slices.Clone(review.BaseArguments)
	expected.Assets = slices.Clone(review.Assets)
	approval.BaseArguments[0] = "--lua-init=unreviewed"
	approval.Assets[0].Path = "unreviewed"
	approval.Assets[0].SHA256 = strings.Repeat("0", 64)
	if !compatibilityReviewsEqual(review, expected) {
		t.Fatal("caller mutation changed the returned review")
	}
	if err := compatibilityFilesUnchanged(review); err != nil {
		t.Fatal("caller mutation broke actual returned file review", err)
	}
}

func TestCompatibilityApprovalDeduplicatesBasePathsInFirstOrder(t *testing.T) {
	approval := compatibilityApprovalFixture(t)
	approval.BaseArguments = append(approval.BaseArguments, approval.BaseArguments[0], approval.BaseArguments[len(approval.BaseArguments)-1])
	review, err := compatibilityReviewApproved(approval)
	if err != nil || len(review.Assets) != len(approval.Assets) || !slices.Equal(review.BaseArguments, approval.BaseArguments) {
		t.Fatalf("deduplicated explicit approval changed: %+v err=%v", review, err)
	}
	approval.Assets = append(approval.Assets, approval.Assets[0])
	if _, err := compatibilityReviewApproved(approval); err == nil {
		t.Fatal("duplicated approved asset was accepted for repeated base path")
	}
}

func TestCompatibilityProtectedPathRequiresLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux denial only")
	}
	approval := compatibilityApprovalFixture(t)
	for _, missing := range []bool{false, true} {
		if err := compatibilityProtectedPath(approval.BinaryPath, missing); err == nil {
			t.Fatal("non-Linux host granted Linux path ownership proof")
		}
	}
}

func TestCompatibilityProtectedPathLinuxPrivateTemporaryParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ownership fixture requires Linux; not executed on this host")
	}
	root, err := os.MkdirTemp("/tmp", "rzv-approval-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "reviewed.data")
	if err := os.WriteFile(file, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := compatibilityProtectedPath(file, false); err != nil {
		t.Fatal("private owned temporary parent rejected", err)
	}
	missing := filepath.Join(root, "control.state")
	if err := compatibilityProtectedPath(missing, true); err != nil {
		t.Fatal("missing leaf with protected existing parent rejected", err)
	}
	if err := compatibilityProtectedPath(missing, false); err == nil {
		t.Fatal("required file absence was accepted")
	}
	if err := compatibilityProtectedPath(filepath.Join(root, "absent", "control.state"), true); err == nil {
		t.Fatal("missing parent acquired path protection")
	}
	if err := compatibilityProtectedPath(root, false); err == nil {
		t.Fatal("directory acquired regular-file path protection")
	}
	for _, mode := range []os.FileMode{0620, 0602, 0666} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if err := compatibilityProtectedPath(file, false); err == nil {
			t.Fatalf("writable file acquired protection with mode %o", mode)
		}
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0755, 0720, 0702, 0777} {
		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
		if err := compatibilityProtectedPath(file, false); err == nil {
			t.Fatalf("non-private temporary descendant acquired protection with mode %o", mode)
		}
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := compatibilityProtectedPath(link, false); err == nil {
		t.Fatal("symlink leaf acquired path protection")
	}
	parentLink := filepath.Join(root, "linked-parent")
	if err := os.Symlink(root, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := compatibilityProtectedPath(filepath.Join(parentLink, "reviewed.data"), false); err == nil {
		t.Fatal("symlink ancestor acquired path protection")
	}
	writable := filepath.Join(root, "sticky-writable")
	if err := os.Mkdir(writable, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	if err := compatibilityProtectedPath(filepath.Join(writable, "missing.state"), true); err == nil {
		t.Fatal("sticky writable directory outside exact /tmp acquired protection")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(file, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := compatibilityProtectedPath(file, false); err == nil {
			t.Fatal("file owned by another UID acquired protection")
		}
		if err := os.Chown(file, 0, -1); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(root, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := compatibilityProtectedPath(file, false); err == nil {
			t.Fatal("ancestor owned by another UID acquired protection")
		}
		if err := os.Chown(root, 0, -1); err != nil {
			t.Fatal(err)
		}
	}
}
