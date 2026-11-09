package dataplane

import (
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Local tuple comparisons with a real socket, never original source authority.
// Complete public Current must still refuse this deliberately incomplete model.
func coordinatorReadComparison(t *testing.T) (*syntheticBaselineCoordinatorRead, *domainCaptureReadComparisonFixture) {
	t.Helper()
	f := domainCaptureReadComparison(t)
	f.owner.backend = &BackendInventory{}
	c := &syntheticBaselineCoordinator{binding: f.binding, tools: &f.owner.tools,
		toolsFrozen: f.owner.tools, backend: f.owner.backend, capture: f.capture,
		control: &operationgate.ControlEpochReview{}}
	c.self = c
	r := &syntheticBaselineCoordinatorRead{coordinator: c, frozen: *c, owner: f.owner,
		xray: f.xray, process: f.process, material: f.material, listener: f.listener,
		source: f.owner.source}
	return r, f
}

func TestSyntheticBaselineCoordinatorReadRetainsOriginalTuple(t *testing.T) {
	for _, change := range []string{"coordinator-copy", "binding-copy", "tools-copy", "backend-copy", "capture-copy", "control-copy", "tools-and-frozen", "owner-backend", "owner-source", "owner-closed", "owner-capture", "process-material", "listener-close", "cancel"} {
		t.Run(change, func(t *testing.T) {
			r, f := coordinatorReadComparison(t)
			if err := r.association(f.ctx); err != nil {
				t.Fatal("initial comparison-only tuple", err)
			}
			// These changes model a late callback between the two full Currents.
			// Equal-valued replacement objects must not substitute original custody.
			c := r.coordinator
			switch change {
			case "coordinator-copy":
				c.self = &syntheticBaselineCoordinator{}
			case "binding-copy":
				copy := *c.binding
				c.binding = &copy
			case "tools-copy":
				copy := *c.tools
				c.tools = &copy
			case "backend-copy":
				copy := *c.backend
				c.backend = &copy
			case "capture-copy":
				c.capture = &DomainPolicyTCPCapture{self: f.capture}
			case "control-copy":
				c.control = &operationgate.ControlEpochReview{}
			case "tools-and-frozen":
				c.tools.IPTables = "/foreign/iptables"
				c.toolsFrozen = *c.tools
			case "owner-backend":
				f.owner.backend = &BackendInventory{}
			case "owner-source":
				f.owner.source = new(int)
			case "owner-closed":
				f.owner.closed = true
			case "owner-capture":
				f.owner.capture = &DomainPolicyTCPCapture{}
			case "process-material":
				f.process.material = &XrayDomainTCPOperationMaterial{}
			case "listener-close":
				_ = f.listener.Close()
			case "cancel":
				f.cancel()
			}
			if err := r.association(f.ctx); err == nil {
				t.Fatal("late changed association accepted")
			}
		})
	}
}

func TestSyntheticBaselineCoordinatorReadComparisonCannotMintCurrent(t *testing.T) {
	r, f := coordinatorReadComparison(t)
	if err := r.association(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.coordinator.Current(f.ctx); err == nil {
		t.Fatal("local comparisons minted full source Current")
	}
	if err := (*syntheticBaselineCoordinatorRead)(nil).association(f.ctx); err == nil {
		t.Fatal("missing frozen tuple accepted")
	}
}

func TestSyntheticBaselineCoordinatorReadKeepsCustomRefusal(t *testing.T) {
	r, f := coordinatorReadComparison(t)
	witness := errors.New("custom source refused before later coordinator callbacks")
	owner := &domainCaptureReadCustomOwner{syntheticTCPModelOwner: &syntheticTCPModelOwner{}, err: witness}
	f.capture.owner = owner
	// Exercise only the tail selection: incomplete coordinator binding would
	// panic in the later registry path if the first capture error were ignored.
	if err := r.coordinator.observeOriginalCapturePair(f.ctx); !errors.Is(err, witness) || owner.calls != 1 {
		t.Fatal("custom full-byte path or its original refusal changed", owner.calls, err)
	}
}
