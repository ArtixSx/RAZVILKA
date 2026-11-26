//go:build linux && razvilka_native_fixture

package dataplane

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoProbeInactiveCopiedController(t *testing.T) {
	ready := os.Getenv("RAZVILKA_MIHOMO_INACTIVE_COPY")
	if ready == "" {
		t.Skip("owned copied-controller child only")
	}
	if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

func TestMihomoProbeInactiveActualProcesses(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_INACTIVE_NATIVE") != "1" {
		t.Skip("disposable mount/net/PID namespace only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	m := New(t.TempDir())
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyRuntimeInactive(ctx); err != nil {
		t.Fatal("idle finite adapter blocks the complete registry", err)
	}
	root := t.TempDir()
	archive, err := os.Open(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(archive)
	if err != nil {
		archive.Close()
		t.Fatal(err)
	}
	binary := filepath.Join(root, "renamed-worker")
	f, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(z, 128<<20))
	closeErr, gzipErr, archiveErr := f.Close(), z.Close(), archive.Close()
	approved := false
	for _, image := range components.ReviewedMihomoRuntimeImages() {
		approved = approved || image.Size == n && image.SHA256 == hex.EncodeToString(hash.Sum(nil))
	}
	if copyErr != nil || closeErr != nil || gzipErr != nil || archiveErr != nil || !approved {
		t.Fatal("official raw image not proven", copyErr, closeErr, gzipErr, archiveErr)
	}
	profile := filepath.Join(root, "probe.json")
	if err := os.WriteFile(profile, []byte(`{"socks-port":18090,"bind-address":"127.0.0.1","allow-lan":false,"mode":"direct","log-level":"error","proxies":[],"rules":["MATCH,DIRECT"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "-f", profile, "-d", root)
	command.Env = []string{}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := time.Now().Add(8 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", "127.0.0.1:18090", 50*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(ready) {
			t.Fatal("actual renamed Mihomo never listened", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := m.VerifyRuntimeInactive(ctx); err == nil {
		t.Fatal("renamed live official image was accepted as inactive")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait() // Sole Wait of this original native fixture owner.
	waited = true
	if err := m.VerifyRuntimeInactive(ctx); err != nil {
		t.Fatal("actual reaped image still blocks idle registry", err)
	}
	// A renamed byte copy of the current controller must also be refused.
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, "another-worker")
	copyFile, err := os.OpenFile(copyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr = io.Copy(copyFile, self)
	closeErr, archiveErr = copyFile.Close(), self.Close()
	if copyErr != nil || closeErr != nil || archiveErr != nil {
		t.Fatal(copyErr, closeErr, archiveErr)
	}
	readyPath := filepath.Join(root, "copy-ready")
	copyCommand := exec.CommandContext(ctx, copyPath, "-test.run=^TestMihomoProbeInactiveCopiedController$")
	copyCommand.Env = append(os.Environ(), "RAZVILKA_MIHOMO_INACTIVE_COPY="+readyPath)
	if err := copyCommand.Start(); err != nil {
		t.Fatal(err)
	}
	copyWaited := false
	defer func() {
		if !copyWaited {
			_ = copyCommand.Process.Kill()
			_ = copyCommand.Wait()
		}
	}()
	ready = time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(ready) {
			t.Fatal("copied controller did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := m.VerifyRuntimeInactive(ctx); err == nil {
		t.Fatal("renamed controller copy accepted as inactive")
	}
	if err := copyCommand.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = copyCommand.Wait()
	copyWaited = true
	if err := m.VerifyRuntimeInactive(ctx); err != nil {
		t.Fatal("reaped controller copy still blocks idle registry", err)
	}
	t.Log("actual idle registry, renamed official Mihomo refusal, copied controller refusal and original reaped absence: PASS; no route/service claim")
}
