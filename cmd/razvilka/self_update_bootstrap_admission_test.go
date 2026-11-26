package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelfUpdateBootstrapWorkerUsesOriginalUnstoppedEpoch(t *testing.T) {
	base := t.TempDir()
	control := filepath.Join(base, "control")
	r, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	before := selfUpdateReadTree(t, base)
	id := strings.Repeat("a", 32)
	beginErr := errors.New("actual admitted effect model refused")
	called := 0
	err = selfUpdateEffectAdmissionAt(context.Background(), control, filepath.Join(base, "missing-config"), id, r.InstallationID, r.Sequence,
		"bootstrap-offline", "command-worker-stop-old-panel", func() error { called++; return beginErr })
	if !errors.Is(err, beginErr) || called != 1 {
		t.Fatal("offline worker missed actual original unstopped admission", called, err)
	}
	if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("worker changed original epoch or bootstrapped configuration")
	}
	for _, failure := range []string{"installation", "sequence", "action", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			installation, sequence, action := r.InstallationID, r.Sequence, "bootstrap-offline"
			ctx := context.Background()
			switch failure {
			case "installation":
				installation = strings.Repeat("f", 32)
			case "sequence":
				sequence++
			case "action":
				action = "bootstrap-live"
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			err := selfUpdateEffectAdmissionAt(ctx, control, filepath.Join(base, "missing-config"), id, installation, sequence, action,
				"command-worker-stop-old-panel", func() error { called++; return nil })
			if err == nil || called != 1 || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
				t.Fatal("worker used changed owner/epoch/action or canceled input", called, err)
			}
		})
	}
}

func TestSelfUpdateBootstrapWorkerCannotBorrowStoppedCompensation(t *testing.T) {
	base := t.TempDir()
	control := filepath.Join(base, "control")
	r, err := operationgate.InitializeSelfUpdateControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if _, err := operationgate.RequestSelfUpdateStop(context.Background(), control, id, 7); err != nil {
		t.Fatal(err)
	}
	before := selfUpdateReadTree(t, base)
	called := 0
	// Even an otherwise valid stopped cleanup effect cannot admit bootstrap.
	err = selfUpdateEffectAdmissionAt(context.Background(), control, filepath.Join(base, "missing-config"), id, r.InstallationID, r.Sequence,
		"bootstrap-offline", "command-worker-stop-old-panel", func() error { called++; return nil })
	if !errors.Is(err, operationgate.ErrSelfUpdateStopped) || called != 0 || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("offline bootstrap borrowed stopped cleanup or loaded config", called, err)
	}
}
