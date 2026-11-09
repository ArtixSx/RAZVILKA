//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"golang.org/x/sys/unix"
)

// Same source, two real versioned executables. This is synthetic release
// transport and configured Ubuntu daemonization, not official provenance or
// Entware/router acceptance. Every updater and rollback receipt is real.
func TestNativeModernPublicRollback(t *testing.T) {
	if os.Getenv("RAZVILKA_MODERN_PAIR_NATIVE") != "1" {
		t.Skip("isolated modern pair not requested")
	}
	nativePairedPrivateScope(t)
	root := os.Getenv("TMPDIR")
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fixture has an outward interface", err)
	}
	for _, family := range []string{"-4", "-6"} {
		if len(bytes.TrimSpace(nativePairedHistoryCommand(t, "/usr/bin/ip", family, "route", "show", "default"))) != 0 {
			t.Fatal("fixture has an outward default route")
		}
	}
	// Publicfetch intentionally rejects documentation/private addresses. This
	// fixed address exists ONLY on lo in this isolated namespace, with no peer
	// reachable on the real Internet. Original DNS/address/TLS policy is intact.
	nativePairedHistoryCommand(t, "/usr/bin/ip", "addr", "add", "93.184.216.34/32", "dev", "lo")
	defer nativePairedHistoryCommand(t, "/usr/bin/ip", "addr", "del", "93.184.216.34/32", "dev", "lo")
	kernelBefore := nativePairedHistoryKernel(t, nil)
	stopPeer := nativeModernReleasePeer(t, root)
	defer stopPeer()
	initSHA := nativePairedRestoreFileHash(t, "/opt/etc/init.d/S99razvilka")
	sourceSHA := nativePairedRestoreFileHash(t, "/opt/bin/razvilka")
	nativeModernInit(t, root, "start")
	defer func() {
		if !t.Failed() {
			return
		}
		nativeModernInit(t, root, "stop")
	}()
	before := nativeModernStatus(t)
	if before.Version != "0.20.0" || before.PID <= 1 {
		t.Fatal("actual source panel not running")
	}
	nativeModernDaemonFD(t, before.PID)
	t.Setenv("RAZVILKA_PAIRED_NATIVE_HISTORY", "draft")
	draft := nativePairedPublicDraftBefore(t)
	token := nativePairedSourceToken(t)
	prepared := nativePairedSourceHTTP(t, "POST", "/api/v1/self-update/prepare", []byte(`{"confirm":"PREPARE_APP_UPDATE"}`), token, http.StatusAccepted, 30*time.Second)
	var job updatecheck.Job
	if json.Unmarshal(prepared, &job) != nil || job.ID == "" {
		t.Fatal("real prepare did not issue job")
	}
	deadline := time.Now().Add(4 * time.Minute)
	for job.State != "ready" && time.Now().Before(deadline) {
		if job.State == "failed" || job.State == "blocked" || job.State == "requires-review" {
			t.Fatal("real preparation refused", job.State, job.Stage, job.Code)
		}
		time.Sleep(100 * time.Millisecond)
		if json.Unmarshal(nativePairedSourceHTTP(t, "GET", "/api/v1/self-update/current", nil, token, http.StatusOK, 5*time.Second), &job) != nil {
			t.Fatal("job decode")
		}
	}
	if job.State != "ready" || job.ReviewToken == "" || !job.CanApply {
		t.Fatal("real preparation not ready", job.State, job.Stage, job.Code)
	}
	body, err := json.Marshal(map[string]any{"job_id": job.ID, "review_token": job.ReviewToken, "config_revision": job.ConfigRevision, "confirm": "INSTALL_APP_UPDATE"})
	if err != nil {
		t.Fatal(err)
	}
	installed := nativePairedSourceHTTP(t, "POST", "/api/v1/self-update/apply", body, token, http.StatusAccepted, 90*time.Second)
	clear(body)
	if json.Unmarshal(installed, &job) != nil || job.HelperPID <= 1 {
		t.Fatal("real public Apply did not launch its original helper")
	}
	helperPID := job.HelperPID
	candidateSeen := false
	candidatePID := 0
	deadline = time.Now().Add(20 * time.Minute)
	var status nativeModernPanelStatus
	for time.Now().Before(deadline) {
		if observed, ok := nativeModernTryStatus(); ok {
			status = observed
			if status.Version == "0.20.1" {
				if status.PID <= 1 || status.PID == before.PID || candidatePID != 0 && candidatePID != status.PID {
					t.Fatal("candidate original process identity changed")
				}
				candidatePID = status.PID
				candidateSeen = true
				nativeModernDaemonFD(t, status.PID)
			}
		}
		store, openErr := selfupdatejournal.Open("/opt", installpath.State+"/self-update-files")
		if openErr == nil {
			receipt, present, readErr := store.Current()
			store.Close()
			if readErr == nil && present && receipt.ID == job.ID && receipt.Phase == "rolled-back" && receipt.Rollback && status.Version == "0.20.0" && status.PID != before.PID {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	store, err := selfupdatejournal.Open("/opt", installpath.State+"/self-update-files")
	if err != nil {
		t.Fatal(err)
	}
	receipt, present, readErr := store.Current()
	store.Close()
	if readErr != nil || !present || receipt.ID != job.ID || receipt.Phase != "rolled-back" || !receipt.Rollback || !candidateSeen {
		t.Fatal("actual ordinary rollback not completed", candidateSeen, receipt.Phase, readErr)
	}
	var cut struct {
		ID        string `json:"id"`
		Candidate string `json:"candidate_sha256"`
		Checks    bool   `json:"post_live_and_stop_checks"`
	}
	data := nativeModernCutArtifact(t, filepath.Join(root, "modern-live-cut.json"))
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cut) != nil || decoder.Decode(new(any)) != io.EOF || cut.ID != job.ID || !cut.Checks || cut.Candidate != nativePairedRestoreFileHash(t, filepath.Join(root, "candidate")) {
		t.Fatal("real post-Live diagnostic not observed")
	}
	status = nativeModernStatus(t)
	if status.Version != "0.20.0" || status.PID == before.PID || nativePairedRestoreFileHash(t, "/opt/bin/razvilka") != sourceSHA || nativePairedRestoreFileHash(t, "/opt/etc/init.d/S99razvilka") != initSHA {
		t.Fatal("source binary/init/live panel not restored")
	}
	nativeModernDaemonFD(t, status.PID)
	if nativePairedRestoreFileHash(t, installpath.State+"/strategy-lab.json") != draft.stateSHA {
		t.Fatal("rollback changed original draft state")
	}
	var snapshot strategylab.Snapshot
	if json.Unmarshal(nativePairedSourceHTTP(t, "GET", "/api/v1/strategy-lab", nil, "", http.StatusOK, 5*time.Second), &snapshot) != nil {
		t.Fatal("restored actual source reader unavailable")
	}
	nativePairedDraftSnapshot(t, snapshot, draft.candidate)
	for _, pid := range []int{before.PID, helperPID, candidatePID} {
		end := time.Now().Add(10 * time.Second)
		for time.Now().Before(end) {
			if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); errors.Is(e, os.ErrNotExist) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("original exited owner not reaped", pid, e)
		}
	}
	nativeModernInit(t, root, "stop")
	if _, err := os.Stat("/proc/" + strconv.Itoa(status.PID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restored panel Stop not joined", err)
	}
	// A second actual unchanged init start must load the genuinely restored
	// pair after the original helper has exited. No Stop/guard is reset here.
	nativeModernInit(t, root, "start")
	restarted := nativeModernStatus(t)
	if restarted.Version != "0.20.0" || restarted.PID == status.PID || nativePairedRestoreFileHash(t, installpath.State+"/strategy-lab.json") != draft.stateSHA {
		t.Fatal("restored pair did not survive genuine init restart")
	}
	nativeModernDaemonFD(t, restarted.PID)
	if json.Unmarshal(nativePairedSourceHTTP(t, "GET", "/api/v1/strategy-lab", nil, "", http.StatusOK, 5*time.Second), &snapshot) != nil {
		t.Fatal("restarted source reader unavailable")
	}
	nativePairedDraftSnapshot(t, snapshot, draft.candidate)
	nativeModernInit(t, root, "stop")
	if _, err := os.Stat("/proc/" + strconv.Itoa(restarted.PID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restarted panel Stop not joined", err)
	}
	stopPeer()
	if nativePairedHistoryKernel(t, nil) != kernelBefore {
		t.Fatal("original kernel baseline not restored")
	}
	interfaces, err = net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("closing fixture interface isolation changed", err)
	}
	t.Log("actual_modern_public_pair rollback=true source_live_restored=true candidate_live_observed=true original_post_live_fault=true original_receipt=true draft_bytes_preserved=true all_panels_joined=true same_source_lab_versions=true official_release_provenance=false router_ready=false")
}

func nativeModernCutArtifact(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal("original cut artifact unavailable", err)
	}
	before, beforeErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, 513))
	after, afterErr := file.Stat()
	named, namedErr := os.Lstat(path)
	closeErr := file.Close()
	if beforeErr != nil || afterErr != nil || namedErr != nil || readErr != nil || closeErr != nil || len(data) > 512 || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		t.Fatal("cut artifact bounded original read refused")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		t.Fatal("cut artifact has foreign owner")
	}
	return data
}

type nativeModernPanelStatus struct {
	Version string `json:"version"`
	PID     int    `json:"process_id"`
}

func nativeModernTryStatus() (nativeModernPanelStatus, bool) {
	var status nativeModernPanelStatus
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("http://127.0.0.1:8787/api/v1/status")
	if err != nil {
		return status, false
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	closeErr := resp.Body.Close()
	ok := readErr == nil && closeErr == nil && resp.StatusCode == 200 && len(raw) <= 65536 && json.Unmarshal(raw, &status) == nil
	return status, ok
}
func nativeModernStatus(t *testing.T) nativeModernPanelStatus {
	t.Helper()
	status, ok := nativeModernTryStatus()
	if !ok {
		t.Fatal("actual modern panel status unavailable")
	}
	return status
}
func nativeModernDaemonFD(t *testing.T, pid int) {
	t.Helper()
	var original, actual unix.Stat_t
	if pid <= 1 || unix.Fstat(3, &original) != nil || unix.Stat("/proc/"+strconv.Itoa(pid)+"/fd/3", &actual) != nil || original.Dev != actual.Dev || original.Ino != actual.Ino {
		t.Fatal("actual daemon did not retain SAME original outer namespace")
	}
}
func nativeModernInit(t *testing.T, root, action string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	fd, err := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "original native namespace")
	defer f.Close()
	cmd := exec.CommandContext(ctx, "/opt/bin/sh", "/opt/etc/init.d/S99razvilka", action)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/opt/root", "LANG=C", "LC_ALL=C", "TMPDIR=" + root, "RAZVILKA_MODERN_PAIR_NATIVE=1", "RAZVILKA_RUNTIME_NATIVE_REVIEW=" + filepath.Join(root, "runtime-native-tool-review.json"), "RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3", "RAZVILKA_START_STOP_DAEMON=" + filepath.Join(root, "modern-daemon.py"), "RAZVILKA_MODERN_PAIR_FD_LAYOUT=initial3", "SSL_CERT_FILE=" + filepath.Join(root, "modern-ca.pem"), "SSL_CERT_DIR=" + filepath.Join(root, "empty-ca-dir")}
	out, stderr := &nativePairedRestoreOutput{}, &nativePairedRestoreOutput{}
	cmd.Stdout, cmd.Stderr = out, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		t.Fatalf("actual modern init %s failed: %v stdout=%q stderr=%q", action, err, out.Bytes()[:min(out.Len(), 256)], stderr.Bytes()[:min(stderr.Len(), 256)])
	}
}

func nativeModernReleasePeer(t *testing.T, root string) func() {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RAZVILKA isolated lab release"}, DNSNames: []string{"api.github.com", "github.com"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "modern-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty-ca-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	asset := func(id int, name, path string) map[string]any {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"id": id, "name": name, "size": info.Size(), "digest": "sha256:" + nativePairedRestoreFileHash(t, path), "browser_download_url": "https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.1/" + name, "state": "uploaded"}
	}
	metadata, err := json.Marshal(map[string]any{"id": 9112026, "tag_name": "v0.20.1", "published_at": "2026-11-09T00:00:00Z", "html_url": "https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.20.1", "draft": false, "prerelease": false, "assets": []any{asset(11, "RAZVILKA-0.20.1-entware.tar.gz", filepath.Join(root, "release.tar.gz")), asset(12, "razvilka-linux-amd64", filepath.Join(root, "candidate"))}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var active atomic.Int64
	requests := map[string]int{}
	unexpected := false
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		mu.Lock()
		requests[r.Host+r.URL.Path]++
		mu.Unlock()
		if r.Method != "GET" || r.URL.RawQuery != "" || r.TLS == nil || r.TLS.ServerName != r.Host {
			mu.Lock()
			unexpected = true
			mu.Unlock()
			http.Error(w, "refused", 400)
			return
		}
		if r.Host == "api.github.com" && (r.URL.Path == "/repos/ArtixSx/RAZVILKA/releases/latest" || r.URL.Path == "/repos/ArtixSx/RAZVILKA/releases/9112026") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(metadata)
			return
		}
		files := map[string]string{"/ArtixSx/RAZVILKA/releases/download/v0.20.1/RAZVILKA-0.20.1-entware.tar.gz": "release.tar.gz", "/ArtixSx/RAZVILKA/releases/download/v0.20.1/razvilka-linux-amd64": "candidate"}
		if name, ok := files[r.URL.Path]; r.Host == "github.com" && ok {
			http.ServeFile(w, r, filepath.Join(root, name))
			return
		}
		mu.Lock()
		unexpected = true
		mu.Unlock()
		http.Error(w, "refused", 404)
	})}
	listener, err := tls.Listen("tcp4", "93.184.216.34:443", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(ctx)
			if err != nil {
				err = errors.Join(err, server.Close())
			}
			var serveErr error
			select {
			case serveErr = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("release peer did not join after bounded shutdown/close")
			}
			if err != nil || !errors.Is(serveErr, http.ErrServerClosed) || active.Load() != 0 {
				t.Fatal("real release peer failed joined shutdown", err, serveErr)
			}
			mu.Lock()
			defer mu.Unlock()
			if unexpected || requests["api.github.com/repos/ArtixSx/RAZVILKA/releases/latest"] == 0 || requests["api.github.com/repos/ArtixSx/RAZVILKA/releases/9112026"] == 0 {
				t.Error("actual closed release transport request contract not observed")
			}
		})
	}
}
