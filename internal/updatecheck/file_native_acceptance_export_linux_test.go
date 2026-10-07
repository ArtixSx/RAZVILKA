//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This small test-only bridge lets the external integration test call the
// actual app consumer without importing app into updatecheck. It reuses the
// private native command fixture, including its explicit layout/capability
// overrides and synthetic network quiescer. It is absent from production.
type NativeFileAcceptanceCoordinates struct {
	ID, Installation, Directory, Journal, Control string
	Revision                                      uint64
}

func NativeFileAcceptanceFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, NativeFileAcceptanceCoordinates, func()) {
	t.Helper()
	a, u, review, profile := nativeFileFixture(t, "delayed")
	job := filepath.Join(a.directory, review.ID)
	panel := exec.Command(filepath.Join(job, "control.bin"), "fixture-old-panel")
	stdin, err := panel.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := panel.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := panel.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	join := func() {
		if !joined {
			_ = panel.Wait()
			joined = true
		}
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if !joined {
			_ = panel.Process.Kill()
			join()
		}
	})
	ready := make([]byte, 6)
	if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
		t.Fatal("old panel readiness", err)
	}
	oldPanel, err := fileProcessAt(panel.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(a.installation, "var/run/razvilka.pid")
	if err := os.WriteFile(pid, []byte(fmt.Sprintf("%d\n", panel.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	init := []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = stop ]; then kill -TERM %d; rm -f '%s'; fi\nexit 0\n", panel.Process.Pid, pid))
	if err := os.WriteFile(filepath.Join(a.installation, "etc/init.d/S99razvilka"), init, 0755); err != nil {
		t.Fatal(err)
	}
	review.OldInitSHA256 = digestBytes(init)
	candidateInit := append(append([]byte(nil), init...), []byte("# distinct candidate image\n")...)
	if err := os.WriteFile(filepath.Join(job, "bundle/scripts/S99razvilka"), candidateInit, 0755); err != nil {
		t.Fatal(err)
	}
	u.record.Files["scripts/S99razvilka"] = digestBytes(candidateInit)
	// An ELF overlay keeps the real copied executable runnable while making
	// candidate and old binary digests different at the actual rename cut.
	binary := filepath.Join(job, "bundle/dist", u.record.Job.Release.Binary.Name)
	image, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	image = append(image, []byte("\nRAZVILKA native acceptance candidate\n")...)
	if err := os.WriteFile(binary, image, 0700); err != nil {
		t.Fatal(err)
	}
	u.record.Job.Release.Binary.Digest = "sha256:" + digestBytes(image)
	u.record.Job.Release.Binary.Size = int64(len(image))
	u.record.Files["dist/"+u.record.Job.Release.Binary.Name] = digestBytes(image)
	manifest := []byte(fmt.Sprintf("%s  %s\n", digestBytes(image), u.record.Job.Release.Binary.Name))
	if err := os.WriteFile(filepath.Join(job, "bundle/dist/SHA256SUMS"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.Files["dist/SHA256SUMS"] = digestBytes(manifest)
	u.record.ParentPID = oldPanel.PID
	review.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, review.MigratedConfigSHA256)
	self, err := fileHelperProcess()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, review.ID, self, oldPanel})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "helper.identity.json"), identity, 0600); err != nil {
		t.Fatal(err)
	}
	saveStoppedReview(t, a, u, review)
	return a, u, NativeFileAcceptanceCoordinates{review.ID, a.installation, a.directory, a.fileJournal, profile.Control, review.Revision}, join
}

func NativeFileAcceptanceReopen(t *testing.T, directory, id string) *SelfUpdateFileAdapter {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, id, "native-fixture.json"))
	var profile nativeFileProfile
	if err != nil || decodeFileProtocol(data, &profile) != nil || !filepath.IsAbs(profile.Installation) || !filepath.IsAbs(profile.Control) {
		t.Fatal("native acceptance coordinates", err)
	}
	return nativeFileAdapter(directory, profile)
}

// Exit occurs inside the actual control-lock admission callback, adjacent to
// the real rename/unlink. No journal fault hook or synthetic success is used.
func NativeFileAcceptanceCrashAtEffect(a *SelfUpdateFileAdapter, effect string, after bool) {
	admission := a.admission
	a.admission = func(ctx context.Context, id, installation string, sequence uint64, action, actual string, begin func() error) error {
		return admission(ctx, id, installation, sequence, action, actual, func() error {
			if actual == effect && !after {
				os.Exit(86)
			}
			err := begin()
			if actual == effect && after && err == nil {
				os.Exit(86)
			}
			return err
		})
	}
}

func NativeFileAcceptanceCompletedCommands(t *testing.T, a *SelfUpdateFileAdapter, id string, commands ...string) {
	t.Helper()
	root, err := a.commandRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, command := range commands {
		r, err := readFileCommand(root, id, command)
		if err != nil || r.State != "reaped" || !r.WaitECHILD || r.Cancelled || r.ExitCode != 0 {
			t.Fatal("actual worker completion", command, r, err)
		}
		if command == "quiesce-old-runtime" && r.Reaped < 2 {
			t.Fatal("detached descendant not reaped", r)
		}
		t.Logf("command=%s parent=%d supervisor=%d boot=%s birth=%s device=%d inode=%d reaped=%d ECHILD=%t", command, r.Parent.PID, r.Supervisor.PID, r.Supervisor.Boot, r.Supervisor.Start, r.Supervisor.Device, r.Supervisor.Inode, r.Reaped, r.WaitECHILD)
	}
}

func NativeFileAcceptanceControl(t *testing.T, ctx context.Context, a *SelfUpdateFileAdapter, id string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(a.directory, id, "native-fixture.json"))
	var profile nativeFileProfile
	if err != nil || decodeFileProtocol(data, &profile) != nil {
		t.Fatal(err)
	}
	if _, present, err := operationgate.ReadSelfUpdateStop(ctx, profile.Control); err != nil || !present {
		t.Fatal("actual persistent control", err)
	}
	return profile.Control
}
