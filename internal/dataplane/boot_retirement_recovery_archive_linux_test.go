package dataplane

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Preserve absolute receipt coordinates without touching the host's /opt.
// The child enters its private extracted root before constructing adapters.
func TestBootRetirementRecoverRetainedSuccessfulArchive(t *testing.T) {
	if root := os.Getenv("RAZVILKA_TEST_RETIRED_ARCHIVE_CHILD_ROOT"); root != "" {
		if err := syscall.Chroot(root); err != nil {
			t.Fatal("enter private archive root", err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		m := New("/opt/razvilka/state/dataplane")
		proxy, err := NewProxyTunnelAdapter("sing-box", nil, m.StateRoot)
		if err != nil {
			t.Fatal(err)
		}
		trap := retiredArchiveRuntimeTrap{t}
		proxy.Processes = trap
		nfq := NewNFQWS2Adapter()
		nfq.Runner = trap
		if err := m.Register(proxy); err != nil {
			t.Fatal(err)
		}
		if err := m.Register(nfq); err != nil {
			t.Fatal(err)
		}
		m.FreshProfile = func(context.Context) (string, error) { t.Fatal("retired history queried live network"); return "", nil }
		retired, planID, err := m.completedBootRetirement()
		if err != nil || !retired || !validPlanID(planID) {
			t.Fatal("real completed retirement proof rejected", err)
		}
		before := proxyRollbackRetryFiles(t, m.StateRoot)
		for i := 0; i < 2; i++ {
			recovery, err := m.Recover(context.Background())
			if err != nil || recovery.Guarded || recovery.State != "fresh-plan-required" || recovery.PlanID != planID {
				t.Fatal("real retired startup did not settle", recovery.State, err)
			}
		}
		changed, err := m.RefreshCommitted(context.Background())
		if err != nil || len(changed) != 0 {
			t.Fatal("retired refresh did not settle", err)
		}
		after := proxyRollbackRetryFiles(t, m.StateRoot)
		delete(before, "0/latest-recovery.json")
		delete(after, "0/latest-recovery.json")
		if len(before) != len(after) {
			t.Fatal("retired history file count changed")
		}
		for name, image := range before {
			if after[name] != image {
				t.Fatal("retired history changed")
			}
		}
		return
	}
	path := os.Getenv("RAZVILKA_TEST_RETIRED_BOOT_ARCHIVE")
	if path == "" {
		t.Skip("explicit private successful retirement archive replay only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("private archive replay requires root for isolated chroot")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open private archive", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal("open private gzip", err)
	}
	defer gz.Close()
	root := t.TempDir()
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	total := int64(0)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("read private archive", err)
		}
		const prefix = "razvilka/state/dataplane/"
		if !strings.HasPrefix(header.Name, prefix) {
			continue
		}
		name := strings.TrimPrefix(header.Name, prefix)
		if name == "" {
			continue
		}
		if !filepath.IsLocal(name) || seen[name] {
			t.Fatal("unsafe or duplicate archived metadata")
		}
		seen[name] = true
		target := filepath.Join(root, "opt/razvilka/state/dataplane", name)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > bootRetirementLimit {
			t.Fatal("unsupported archived metadata")
		}
		total += header.Size
		if total > 128<<20 {
			t.Fatal("private metadata archive exceeds bound")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(reader, bootRetirementLimit+1))
		if err != nil || int64(len(raw)) != header.Size {
			t.Fatal("read archived metadata")
		}
		if err := os.WriteFile(target, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(self, "-test.run=^TestBootRetirementRecoverRetainedSuccessfulArchive$", "-test.count=1")
	command.Env = append(os.Environ(), "RAZVILKA_TEST_RETIRED_ARCHIVE_CHILD_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("private chroot replay failed: %v\n%s", err, output)
	}
}

type retiredArchiveRuntimeTrap struct{ t *testing.T }

func (r retiredArchiveRuntimeTrap) Start(context.Context, ProcessSpec) error {
	r.t.Fatal("unexpected real process start")
	return nil
}
func (r retiredArchiveRuntimeTrap) Stop(context.Context, ProcessSpec) error {
	r.t.Fatal("unexpected real process stop")
	return nil
}
func (r retiredArchiveRuntimeTrap) Running(ProcessSpec) bool {
	r.t.Fatal("unexpected runtime process query")
	return false
}
func (r retiredArchiveRuntimeTrap) Run(context.Context, string, ...string) ([]byte, error) {
	r.t.Fatal("unexpected runtime command")
	return nil, nil
}
