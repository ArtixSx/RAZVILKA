//go:build linux

package components

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMihomoProbeOriginActualKernelOwnerAndDeath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner, err := captureMihomoProbeOrigin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	origin := owner.reference()
	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := captureMihomoProbeOrigin(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("capture lost original cancellation", err)
	}
	if err := owner.current(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("current lost original cancellation", err)
	}
	if err := ObserveMihomoProbeParentGone(canceled, origin); !errors.Is(err, context.Canceled) {
		t.Fatal("absence lost original cancellation", err)
	}
	if err := owner.current(ctx); err != nil {
		t.Fatal(err)
	}
	if ObserveMihomoProbeParentGone(ctx, origin) == nil {
		t.Fatal("actual alive original parent accepted as dead")
	}
	changed := origin
	changed.ExecutableSHA256 = ""
	if ObserveMihomoProbeParentGone(ctx, changed) == nil {
		t.Fatal("missing source proof accepted")
	}
	changed = origin
	changed.PIDNamespaceInode++
	if ObserveMihomoProbeParentGone(ctx, changed) == nil {
		t.Fatal("foreign PID namespace accepted")
	}
	changed = origin
	changed.ProcInode++
	if ObserveMihomoProbeParentGone(ctx, changed) == nil {
		t.Fatal("different proc root accepted")
	}
	original := owner.(*mihomoProbeOriginLinux)
	copy := *original
	if copy.current(ctx) == nil {
		t.Fatal("copied source origin owner accepted")
	}
	original.origin.ExecutableSHA256 = "bad"
	if original.current(ctx) == nil {
		t.Fatal("mutated origin accepted")
	}
	original.origin = origin
	if dir := os.Getenv("RAZVILKA_MIHOMO_ORIGIN_CHILD"); dir != "" {
		raw, _ := json.Marshal(origin)
		if err := os.WriteFile(filepath.Join(dir, "origin.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	root := t.TempDir()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMihomoProbeOriginActualKernelOwnerAndDeath$")
	command.Env = append(os.Environ(), "RAZVILKA_MIHOMO_ORIGIN_CHILD="+root)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "origin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var dead MihomoProbeParentOrigin
	if json.Unmarshal(raw, &dead) != nil {
		t.Fatal("actual child origin missing")
	}
	if err := ObserveMihomoProbeParentGone(ctx, dead); err != nil {
		t.Fatal("actual original reaped parent not absent", err)
	}
}
