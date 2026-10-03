package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// Regression: 0.19.3's third key application-install is rejected by its own
// strict decoder. Use the existing slot; do not weaken unknown-key validation.
func TestResearchMaintenanceReceiptsRoundTripExistingSchema(t *testing.T) {
	for _, values := range []map[string]string{
		{"application": autoInstallAttemptPrefix + "0.19.4", "components": componentPendingPrefix + "xray"},
		{"application": "legacy-window", "components": "legacy-component-window"},
	} {
		d := newAutonomyDocument()
		d.Maintenance = values
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeAutonomy(b)
		if err != nil {
			t.Fatalf("supported receipts failed roundtrip: %v", err)
		}
		for k, v := range values {
			if got.Maintenance[k] != v {
				t.Fatal("receipt changed")
			}
		}
	}
	d := newAutonomyDocument()
	d.Maintenance["unexpected-foreign-key"] = "x"
	b, _ := json.Marshal(d)
	if _, err := decodeAutonomy(b); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestResearchComponentMaintenanceSafetyAndWindow(t *testing.T) {
	now := time.Date(2026, 9, 30, 4, 15, 0, 0, time.UTC)
	p := autonomy.Default()
	p.SetupComplete = true
	p.AllLAN = true
	cfg := config.Config{Revision: 42}
	slot, open := autonomy.WindowKey(p.Components, p.Timezone, now)
	if !open {
		t.Fatal("fixture window")
	}
	if !componentMaintenanceAllowed(p, cfg, false, 42, slot, now) {
		t.Fatal("valid window refused")
	}
	for _, name := range []string{"safe", "stopped", "dirty", "revision", "closed", "changed-slot", "manual"} {
		c := cfg
		dirty := false
		rev := uint64(42)
		at := now
		s := slot
		switch name {
		case "safe":
			c.SafeMode = true
		case "stopped":
			c.ServiceControl.Stopped = true
		case "dirty":
			dirty = true
		case "revision":
			rev++
		case "closed":
			at = at.Add(2 * time.Hour)
		case "changed-slot":
			s = "different"
		case "manual":
			c.ServiceControl.Mode = "manual"
		}
		if componentMaintenanceAllowed(p, c, dirty, rev, s, at) {
			t.Fatalf("%s accepted", name)
		}
	}
}
