package evidence

import "testing"

func TestFromProbeDoesNotPromoteCurrentPath(t *testing.T) {
	if got := FromProbe("pass", false); got != Runtime {
		t.Fatalf("current-path pass = %q, want %q", got, Runtime)
	}
	if Runtime.AtLeast(Service) {
		t.Fatal("runtime reachability was treated as service-route evidence")
	}
}

func TestFromProbeRequiresRouteAndServiceSuccess(t *testing.T) {
	if got := FromProbe("fail", true); got != Route {
		t.Fatalf("confirmed failed route = %q, want %q", got, Route)
	}
	if got := FromProbe("partial", true); got != Service {
		t.Fatalf("confirmed partial response = %q, want %q", got, Service)
	}
	if !Service.AtLeast(Route) || Route.AtLeast(Service) {
		t.Fatal("assurance ordering is invalid")
	}
}

func TestNotReadyHasNoEvidence(t *testing.T) {
	if got := FromProbe("not-ready", true); got != None {
		t.Fatalf("not-ready = %q, want %q", got, None)
	}
}

func TestStrongerIgnoresInvalidLevel(t *testing.T) {
	if got := Stronger(Level("invented"), Route); got != Route {
		t.Fatalf("stronger level = %q, want %q", got, Route)
	}
}
