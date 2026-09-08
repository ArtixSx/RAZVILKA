package privaterestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/warp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeSnapshot(t *testing.T, id string) nativeenrollment.Snapshot {
	t.Helper()
	d := nativeenrollment.Document{Schema: 1}
	dir := "attempt-" + strings.Repeat(id, 32)
	marker, _ := json.Marshal(map[string]any{"schema": 1, "directory": dir, "created_at": "2026-09-01T00:00:00Z", "fresh": false})
	d.Set("pending.json", marker)
	d.Set(dir+"/private-key.bin", []byte{0, 1, 0, 255})
	d.Set(dir+"/response.private.json", []byte("original private provider response"))
	s, err := nativeenrollment.SnapshotOf(d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func nativePayload(t *testing.T) privatebackup.Payload {
	t.Helper()
	p := testPayload(t)
	s := nativeSnapshot(t, "a")
	p.NativeEnrollment = &s
	if err := privatebackup.Seal(&p); err != nil {
		t.Fatal(err)
	}
	return p
}
func withWarp(l Layout) Layout { l.WarpRoot = filepath.Join(filepath.Dir(l.Config), "warp"); return l }
func seedNative(t *testing.T, l Layout, s nativeenrollment.Snapshot) {
	t.Helper()
	target, err := nativeenrollment.Open(l.WarpRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	before, _ := target.Read(context.Background())
	after, err := target.MergeImage(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
}
func TestNativeOnlineOfflineRestoreAndLease(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "online"}[online], func(t *testing.T) {
			l := withWarp(seedLayout(t, t.TempDir()))
			p := nativePayload(t)
			c, _, err := Open(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var out restorejournal.Outcome
			if online {
				s := liveStores(t, l)
				s.Warp = warp.New(l.WarpRoot, filepath.Join(filepath.Dir(l.Config), "warp-backup"), s.Engines)
				c.StartRuntime()
				c.beforeHandover = func() error {
					if other, err := s.Warp.BeginNativeRestore(context.Background()); err == nil {
						other.Close()
						t.Fatal("native lease released before commit handover")
					}
					return nil
				}
				out, err = c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
			} else {
				out, err = c.RestoreOffline(context.Background(), p, map[string]bool{"youtube": true})
			}
			if err != nil || out != restorejournal.Applied {
				t.Fatal(out, err)
			}
			image, err := nativeenrollment.ReadEffective(context.Background(), l.WarpRoot)
			if err != nil || !bytes.Equal(image.Data, p.NativeEnrollment.Content) {
				t.Fatal("journal restore lost original native material", err)
			}
		})
	}
}
func TestNativeConflictPreventsAllOtherWrites(t *testing.T) {
	l := withWarp(seedLayout(t, t.TempDir()))
	seedNative(t, l, nativeSnapshot(t, "b"))
	before := imagesOnDisk(t, l)
	nativeBefore, _ := nativeenrollment.ReadEffective(context.Background(), l.WarpRoot)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, err := c.RestoreOffline(context.Background(), nativePayload(t), map[string]bool{"youtube": true})
	if out != restorejournal.Clean || !errors.Is(err, nativeenrollment.ErrConflict) {
		t.Fatal("newer pending was overwritten", out, err)
	}
	requireImages(t, l, before)
	after, _ := nativeenrollment.ReadEffective(context.Background(), l.WarpRoot)
	if !bytes.Equal(after.Data, nativeBefore.Data) {
		t.Fatal("conflict modified private state")
	}
}
func TestNativeRollbackWithOtherTargetsPreservesBeforeImage(t *testing.T) {
	l := withWarp(seedLayout(t, t.TempDir()))
	p := nativePayload(t)
	before := imagesOnDisk(t, l)
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := liveStores(t, l)
	s.Warp = warp.New(l.WarpRoot, filepath.Join(filepath.Dir(l.Config), "warp-backup"), s.Engines)
	c.StartRuntime()
	failed := false
	c.beforeWrite = func(id string) error {
		if id == "provider_cloudflare" && !failed {
			failed = true
			return errors.New("injected after native write")
		}
		return nil
	}
	out, err := c.RestoreOnline(context.Background(), p, map[string]bool{"youtube": true}, s)
	if err == nil || out != restorejournal.RolledBack {
		t.Fatal(out, err)
	}
	requireImages(t, l, before)
	image, err := nativeenrollment.ReadEffective(context.Background(), l.WarpRoot)
	if err != nil || image.Exists {
		t.Fatal("native image survived rollback", err)
	}
}
func TestNativeRestoreMissingOrWrongBindingIsRejected(t *testing.T) {
	for _, mode := range []string{"missing", "wrong"} {
		t.Run(mode, func(t *testing.T) {
			l := seedLayout(t, t.TempDir())
			if mode == "wrong" {
				l = withWarp(l)
			}
			before := imagesOnDisk(t, l)
			c, _, err := Open(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := liveStores(t, l)
			s.Warp = warp.New(filepath.Join(filepath.Dir(l.Config), "unrelated-warp"), t.TempDir(), s.Engines)
			c.StartRuntime()
			out, err := c.RestoreOnline(context.Background(), nativePayload(t), map[string]bool{"youtube": true}, s)
			if err == nil || out != restorejournal.Clean {
				t.Fatal("native archive target was ignored", out, err)
			}
			requireImages(t, l, before)
		})
	}
}
func TestNativeRecoveryCrashChild(t *testing.T) {
	root := os.Getenv("RAZVILKA_NATIVE_RESTORE_CHILD")
	if root == "" {
		return
	}
	l := withWarp(testLayout(root))
	c, _, err := Open(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	c.afterWrite = func(id string) {
		if id == "native_warp" {
			os.Exit(93)
		}
	}
	c.RestoreOffline(context.Background(), nativePayload(t), map[string]bool{"youtube": true})
	t.Fatal("crash point not reached")
}
func TestNativeRecoveryAfterProcessCrashRestoresAllBeforeImages(t *testing.T) {
	l := withWarp(seedLayout(t, t.TempDir()))
	before := imagesOnDisk(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeRecoveryCrashChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_NATIVE_RESTORE_CHILD="+filepath.Dir(l.Config))
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 93 {
		t.Fatalf("child did not crash at native checkpoint: %v %s", err, output)
	}
	c, out, err := Open(context.Background(), l)
	if err != nil || out != restorejournal.RolledBack {
		t.Fatal(out, err)
	}
	defer c.Close()
	requireImages(t, l, before)
	image, err := nativeenrollment.ReadEffective(context.Background(), l.WarpRoot)
	if err != nil || image.Exists {
		t.Fatal("native pending imported by unfinished transaction survived recovery", err)
	}
}
