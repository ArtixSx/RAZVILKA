package app

import (
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestAutopilotCannotChangeCommittedTargetScope(t *testing.T) {
	before := dataplane.Route{ServiceID: "telegram", Selected: "auto", Resolved: "usque", Domains: []string{"telegram.org", "t.me"}, CIDRs: []string{"149.154.160.0/20"}, Sources: []string{"192.168.1.10/32"}, SourceRefs: []string{"telegram-cidrs"}, ProbeURL: "https://telegram.org/"}
	previous := []dataplane.Route{before}
	after := before
	after.Resolved = "sing-box"
	after.Domains = []string{"t.me", "telegram.org"}
	if !autopilotTargetsUnchanged(previous, []dataplane.Route{after}) {
		t.Fatal("engine-only failover or address reordering was blocked")
	}
	changes := map[string]func(*dataplane.Route){
		"service":    func(r *dataplane.Route) { r.ServiceID = "youtube" },
		"domains":    func(r *dataplane.Route) { r.Domains = []string{"new.example"} },
		"networks":   func(r *dataplane.Route) { r.CIDRs = []string{"0.0.0.0/0"} },
		"devices":    func(r *dataplane.Route) { r.Sources = nil },
		"provenance": func(r *dataplane.Route) { r.SourceRefs = []string{"different-source"} },
		"probe":      func(r *dataplane.Route) { r.ProbeURL = "https://different.example/" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			next := before
			change(&next)
			if autopilotTargetsUnchanged(previous, []dataplane.Route{next}) {
				t.Fatal("background scope change accepted")
			}
		})
	}
	if autopilotTargetsUnchanged(previous, nil) || autopilotTargetsUnchanged(previous, []dataplane.Route{before, before}) {
		t.Fatal("background service addition/removal accepted")
	}
	other := before
	other.ServiceID = "other"
	if autopilotTargetsUnchanged([]dataplane.Route{before, other}, []dataplane.Route{before, before}) {
		t.Fatal("duplicate service hid removed service")
	}
}
