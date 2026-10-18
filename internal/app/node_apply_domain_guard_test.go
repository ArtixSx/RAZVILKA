package app

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestNodeApplyPreviewDomainCaptureRemainsClosed(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "domain-only", true: "domain-and-cidr"}[mixed], func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			a.Catalog.Services[0].Domains = []string{"telegram.org"}
			if !mixed {
				a.Catalog.Services[0].CIDRs = nil
			}
			before := a.Store.Get()
			w := nodeRouteRequest(a, id, "preview", map[string]any{"service_id": "telegram"}, "owner-a", context.Background())
			var response struct {
				Ready       bool            `json:"ready"`
				Review      nodeRouteReview `json:"review"`
				Transaction dataplane.Plan  `json:"transaction"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
				t.Fatal("preview unavailable", w.Code)
			}
			blocked := false
			for _, issue := range response.Transaction.Blockers {
				blocked = blocked || issue.Code == "DOMAIN_FLOW_AUTHORITY_REQUIRED"
			}
			if response.Ready || response.Transaction.Ready || response.Review.Token != "" || !blocked || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("domain intent issued apply authority or effects", response, adapter.calls)
			}
		})
	}
}
