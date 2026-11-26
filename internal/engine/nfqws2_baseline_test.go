package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readNFQWS2Fixture(t *testing.T, name string) Status {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "nfqws2", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("decode %s fixture: %v", name, err)
	}
	return status
}

func TestNFQWS2PresentationBaselinesAreTruthful(t *testing.T) {
	native := readNFQWS2Fixture(t, "native-managed")
	if native.ID != "nfqws2" || !native.Installed || !native.Configured || !native.RuntimeReady || !native.Running || native.External || native.ManagedBy != "razvilka" {
		t.Fatalf("native baseline is not a ready RAZVILKA engine: %#v", native)
	}

	external := readNFQWS2Fixture(t, "external-z2k")
	if external.ID != "z2k" || !external.External || !external.Running || external.ManagedBy != "z2k" || len(Visible([]Status{external})) != 0 {
		t.Fatalf("external baseline became a selectable bypass: %#v", external)
	}

	missing := readNFQWS2Fixture(t, "missing")
	if missing.ID != "nfqws2" || missing.Installed || missing.Configured || missing.RuntimeReady || missing.Running || missing.NativeCheck {
		t.Fatalf("missing baseline claims capabilities it cannot prove: %#v", missing)
	}
}
