package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type lanAdmissionTestRunner struct {
	run policyEffectInvocationTestRunner
}

func (r *lanAdmissionTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.run(ctx, name, args...)
}

// Actual Gate/control files, registered LAN participant and COMMON writer;
// tools, network identity and kernel RPCs are explicit models, no native claim.
func TestLANPolicyCommandAdmissionOriginalAddDeleteAndDurableStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var operations operationgate.Gate
	ctx, release, err := operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := operations.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	b, model, root := lanReceiptBindingFixture(t)
	identity, _ := networkPolicyIdentityFixture()
	identity.provider = &netidentity.Provider{} // Pointer binding only; NI is explicitly modeled.
	starts, deletes, toolChecks := 0, 0, 0
	var escaped context.Context
	review := strings.Repeat("4", 64)
	b.Runtime.Runner = &lanAdmissionTestRunner{run: policyEffectInvocationTestRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
		mutation := false
		for _, effect := range model.effects {
			if name == effect.Tool && (reflect.DeepEqual(args, effect.Add) || reflect.DeepEqual(args, effect.Delete)) {
				mutation = true
			}
		}
		if !mutation {
			return model.Run(c, name, args...)
		}
		escaped = c
		before := toolChecks
		handled, err := WithLANPolicyCommandStart(c, name, args, review, func() error {
			starts++
			call := c.Value(lanPolicyCommandCallKey{}).(*lanPolicyCommandCall)
			if call.cleanup {
				deletes++
			}
			return nil
		})
		if !handled || err != nil || before != toolChecks {
			t.Fatal("original leaf or full-tool reentry", handled, err, before, toolChecks)
		}
		if _, err := WithLANPolicyCommandStart(c, name, args, review, func() error { t.Fatal("per-RPC Start replay"); return nil }); err == nil {
			t.Fatal("issuer replayed")
		}
		return model.Run(c, name, args...)
	})}
	gate, err := newNetworkPolicyIdentityAdapter(NetworkPolicyAssemblyOptions{Binding: b, InventoryCheck: func(context.Context, netidentity.Identity, *LANPolicyRuntimePlan) error { return nil }}, identity)
	if err != nil {
		t.Fatal(err)
	}
	manager := New(t.TempDir())
	if err := manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	inventory := &BackendInventory{review: review, reader: backendInventoryReader{Provider: identity.provider, IPTables: "iptables", IP6Tables: "ip6tables", CheckTools: func(c context.Context, _ backendInventoryScope) error { toolChecks++; return c.Err() }}}
	admission, err := manager.ReviewLANPolicyCommandAdmission(ctx, gate, inventory, control)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Binding.Apply(ctx, model.plan, root); err != nil {
		t.Fatal(err)
	}
	if handled, err := WithLANPolicyCommandStart(escaped, "ip", nil, review, func() error { t.Fatal("escaped LAN Start"); return nil }); !handled || err == nil {
		t.Fatal("escaped invocation revived", handled, err)
	}
	epoch := control.Reference()
	if _, err := operationgate.RequestSelfUpdateStop(ctx, controlRoot, epoch.InstallationID, epoch.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := control.Current(ctx); err == nil {
		t.Fatal("durable Stop preserved forward authority")
	}
	if err := gate.Binding.Remove(ctx, model.plan, root); err != nil {
		t.Fatal("preissued original cleanup after durable Stop", err)
	}
	if starts != 2*len(model.effects) || deletes != len(model.effects) {
		t.Fatal("command coverage", starts, deletes)
	}
	admission.Close()
	if _, err := WithLANPolicyCommandStart(escaped, "ip", nil, review, func() error { t.Fatal("closed issuer"); return nil }); err == nil {
		t.Fatal("closed owner admitted")
	}
}

func TestLANPolicyCommandAdmissionPresentInvalidDoesNotFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, value := range []any{true, (*lanPolicyCommandCall)(nil), &lanPolicyCommandCall{}} {
		c := context.WithValue(ctx, lanPolicyCommandCallKey{}, value)
		if handled, err := WithLANPolicyCommandStart(c, "ip", nil, strings.Repeat("4", 64), func() error { t.Fatal("invalid LAN command started"); return nil }); !handled || !errors.Is(err, ErrLANPolicyRuntime) {
			t.Fatal("invalid issuer fell through", handled, err)
		}
	}
}
