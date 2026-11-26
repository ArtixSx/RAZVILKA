package dataplane

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBootRetirementDiagnosticsClassifyRefusalsWithoutEffectsOrPrivateValues(t *testing.T) {
	for _, mode := range []string{"same-boot", "guard", "binding", "process", "interface", "selector", "read-error", "nfq-source", "closing-evidence"} {
		t.Run(mode, func(t *testing.T) {
			f := newMixedStopRetirementFixture(t)
			want := ""
			guard := func(Plan) error { return nil }
			absent := func(context.Context) error { return nil }
			private := errors.New("private-token /private/path command=secret")
			switch mode {
			case "same-boot":
				f.a.bootIdentity = func() (string, error) { return retirementOldBoot, nil }
				want = "old-boot"
			case "guard":
				guard = func(Plan) error { return private }
				want = "settings-guard"
			case "binding":
				inactiveWrite(t, f.a.policyBindingPath(), []byte("{}"))
				want = "manifest-collect"
			case "process":
				f.writeProcess(t, 456, "S", "0", "sing-box\x00run\x00")
				want = "proxy-processes"
			case "interface":
				f.proof.interfaces = func() ([]net.Interface, error) {
					return []net.Interface{{Index: 1, Name: "lo"}, {Index: 2, Name: f.a.Interface}}, nil
				}
				want = "proxy-interface-present"
			case "selector":
				f.runner.rules[4] += "64: from all lookup 254\n"
				want = "proxy-rules-owned"
			case "read-error":
				f.runner.err = private
				want = "proxy-default-references"
			case "nfq-source":
				absent = nil
				want = "nfq-source"
			case "closing-evidence":
				previous, _, _ := f.m.committedLocked()
				target := filepath.Join(f.m.StateRoot, "transactions", previous.PlanID, "execution.json")
				absent = func(context.Context) error { inactiveWrite(t, target, []byte("private-token")); return nil }
				want = "closing-evidence"
			}
			before := proxyRollbackRetryFiles(t, f.m.StateRoot)
			_, err := f.m.retireFailedRollbackAfterBoot(context.Background(), f.plan.PlanID, f.plan.Digest, f.settings, guard, bootRetirementOptions{proof: &f.proof, nfqAbsent: absent})
			if !errors.Is(err, ErrBootRetirement) || BootRetirementStage(err) != want {
				t.Fatalf("got stage=%q want=%q: %v", BootRetirementStage(err), want, err)
			}
			if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "/private/path") || strings.Contains(err.Error(), "command=secret") {
				t.Fatal("diagnostic exposed private cause")
			}
			after := proxyRollbackRetryFiles(t, f.m.StateRoot)
			if mode != "closing-evidence" && !reflect.DeepEqual(before, after) {
				t.Fatal("diagnostic refusal changed metadata")
			}
			if _, statErr := os.Stat(filepath.Join(f.m.StateRoot, "boot-retirements")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("preflight diagnostic published archive", statErr)
			}
			if f.processes.calls != 0 {
				t.Fatal("diagnostic invoked runtime controller")
			}
		})
	}
}

func TestBootRetirementDiagnosticsPreserveErrorIdentityAndClampStages(t *testing.T) {
	err := bootRetirementAt("private-token", context.Canceled)
	if !errors.Is(err, ErrBootRetirement) || !errors.Is(err, context.Canceled) || BootRetirementStage(err) != "unknown" || strings.Contains(err.Error(), "private-token") {
		t.Fatal("unsafe diagnostic or lost identity", err)
	}
	if BootRetirementStage(errors.New("stage=private-token")) != "" {
		t.Fatal("arbitrary error text became stage")
	}
	proxy := bootProxyRetirementAt("proxy-processes", context.DeadlineExceeded)
	if !errors.Is(proxy, ErrBootRetirement) || !errors.Is(proxy, ErrProxyRuntimeInactive) || !errors.Is(proxy, context.DeadlineExceeded) {
		t.Fatal("proxy error identity lost", proxy)
	}
}
