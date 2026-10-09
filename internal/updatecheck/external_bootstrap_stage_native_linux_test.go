//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// A modeled old source and an executing test ELF cannot create the original
// producer capability. Only Root's genuine public producer test can exercise
// that positive path; no fixture metadata may grant it.
func TestNativeStageExternalBootstrapReviewRejectsUnboundCandidate(t *testing.T) {
	for _, mode := range []string{"live", "offline"} {
		t.Run(mode, func(t *testing.T) { nativeStageExternalBootstrapReview(t, mode) })
	}
}

func nativeStageExternalBootstrapReview(t *testing.T, mode string) {
	a, u, _ := preparingReaderFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	program, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	sha := digestBytes(program)
	for _, path := range []string{filepath.Join(a.installation, "etc/razvilka"), filepath.Join(a.installation, "etc/init.d"), filepath.Join(a.installation, "var/lib/razvilka"), filepath.Join(a.installation, "bin")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldConfig, err := os.ReadFile(u.record.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	if mode == "offline" {
		var cfg config.Config
		if err := json.Unmarshal(oldConfig, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg.SafeMode, cfg.ServiceControl.Stopped = true, true
		oldConfig, err = json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		u.record.ConfigFingerprint = ConfigFingerprint(cfg)
	}
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	u.record.Deployment.Executable = filepath.Join(a.installation, "bin/razvilka")
	u.record.CurrentVersion = "0.19.3"
	if err := os.WriteFile(u.record.Deployment.Paths["config"], oldConfig, 0600); err != nil {
		t.Fatal(err)
	}
	oldSource := []byte("modeled old source with no executable reader ABI\n")
	if err := os.WriteFile(u.record.Deployment.Executable, oldSource, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "etc/init.d/S99razvilka"), []byte("old init fixture\n"), 0700); err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(a.directory, u.record.Job.ID)
	binary := filepath.Join(job, "bundle/dist", u.record.Job.Release.Binary.Name)
	if err := os.WriteFile(binary, program, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "bundle/dist/SHA256SUMS"), []byte(sha+"  "+u.record.Job.Release.Binary.Name+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	u.record.Job.Release.Binary.Digest, u.record.Job.Release.Binary.Size = "sha256:"+sha, int64(len(program))
	u.record.Job.Release.Archive.Digest = "sha256:" + strings.Repeat("a", 64)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	record := u.record
	record.Files, record.ExecutableHash = make(map[string]string), digestBytes(oldSource)
	for name := range requiredInstallFiles(*record.Job.Release) {
		data, err := os.ReadFile(filepath.Join(job, "bundle", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		record.Files[name] = digestBytes(data)
	}
	binding := &fileBootstrapBinding{Role: externalOld193InstallerRole, Mode: mode, HelperSHA256: sha, ArchivePath: filepath.Join(t.TempDir(), "consumed-package.tar.gz"), ArchiveSHA256: strings.Repeat("a", 64)}
	stagedBefore, err := os.ReadFile(filepath.Join(job, "staged/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	sealed, err := a.stageFileReviewWithBootstrap(ctx, record, func(c context.Context, id string) (SelfUpdateAuthority, error) {
		called = true
		if c != ctx || id != record.Job.ID {
			return SelfUpdateAuthority{}, ErrFileProtocol
		}
		return SelfUpdateAuthority{strings.Repeat("b", 32), 1}, nil
	}, binding)
	if !errors.Is(err, ErrExternalBootstrap) || sealed != "" || called {
		t.Fatal("unbound fixture acquired original preparation authority", err)
	}
	stagedAfter, err := os.ReadFile(filepath.Join(job, "staged/config.json"))
	if err != nil || !bytes.Equal(stagedBefore, stagedAfter) {
		t.Fatal("unbound fixture changed prior staged evidence", err)
	}
	for _, name := range []string{"control.bin", "file-review.json"} {
		if _, err := os.Lstat(filepath.Join(job, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unbound fixture produced staging effects", name, err)
		}
	}
}
