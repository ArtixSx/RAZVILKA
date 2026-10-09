//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Actual producer/ELF probe/migration path, with a modeled old source that
// cannot execute any ABI flag. This is not real0.19.3 migration acceptance.
func TestNativeStageExternalBootstrapReviewUsesCandidateOnly(t *testing.T) {
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
	sealed, err := a.stageFileReviewWithBootstrap(ctx, record, func(c context.Context, id string) (SelfUpdateAuthority, error) {
		if c != ctx || id != record.Job.ID {
			return SelfUpdateAuthority{}, ErrFileProtocol
		}
		return SelfUpdateAuthority{strings.Repeat("b", 32), 1}, nil
	}, binding)
	if err != nil || !validDigest("sha256:"+sealed) {
		t.Fatal("real producer demanded old reader ABI", err)
	}
	controlSHA, err := hashRegularFile(filepath.Join(job, "control.bin"), MaximumBinaryBytes)
	if err != nil || controlSHA != sha {
		t.Fatal("old source adopted as helper", err)
	}
	record.FileReviewSHA256, record.Job.State, record.Job.Stage = sealed, "restarting", "file-protocol"
	record.Job.CanCancel = false
	u.record = record
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	_, review, err := a.load(ctx, record.Job.ID)
	if err != nil || review.Schema != selfupdatejournal.PairedSchema || review.JournalReaders != nil || review.Bootstrap == nil || review.OldExecutableSHA256 != digestBytes(oldSource) {
		t.Fatal("producer erased old source or forged stopped proof", err)
	}
}
