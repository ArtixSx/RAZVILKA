package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"testing"
)

func TestNetworkTimingReportRequiresOriginalResultIdentity(t *testing.T) {
	for _, changed := range []bool{false, true} {
		store := privateStoreFixture(t, 1)
		checker := &checkerFixture{engine: "xray", check: func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
			finish := probecheck.BeginLocalServiceDNS(ctx)
			finish(nil)
			result := positiveFixture(r, "xray")
			if changed {
				result.ServiceID = "another-service"
			}
			return result, nil
		}}
		var output bytes.Buffer
		evaluate(context.Background(), context.Background(), store, checker, func(context.Context) (string, error) { return "wan-0123456789ab", nil }, 1, json.NewEncoder(&output))
		reports := decodeReports(t, output.Bytes())
		found := false
		for _, r := range reports {
			if r.Kind == "candidate" {
				found = true
				if (len(r.NetworkTimings) == 1) == changed {
					t.Fatal("network timeline escaped original result identity", changed, r.NetworkTimings)
				}
			}
		}
		if !found {
			t.Fatal("no candidate report")
		}
	}
}
