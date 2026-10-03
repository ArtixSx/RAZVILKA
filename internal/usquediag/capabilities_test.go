package usquediag

import (
	"strings"
	"testing"
	"time"
)

func TestCanaryCapabilitiesRequireFreshExactEnvironmentAndEndpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	digest := strings.Repeat("a", 64)
	binding := CanaryBinding(digest, digest, digest, digest)
	endpoints := Endpoints{IPv4: "162.159.198.2", H2IPv4: "162.159.198.3"}
	good := CanaryEvidence{CheckedAt: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339), BindingID: binding, Endpoint: "162.159.198.3:443", Transport: "HTTP/2", Warp: "on"}
	h2 := EvaluateCanaryCapabilities(good, endpoints, binding, now)
	if !h2.Fresh || h2.HTTP2 != "confirmed" || h2.HTTP3 != "unknown" || h2.UDP != "unknown" {
		t.Fatalf("H2 granted UDP proof: %+v", h2)
	}
	quic := good
	quic.Transport, quic.Endpoint = "QUIC", "162.159.198.2:443"
	h3 := EvaluateCanaryCapabilities(quic, endpoints, binding, now)
	if !h3.Fresh || h3.HTTP2 != "unknown" || h3.HTTP3 != "confirmed" || h3.UDP != "confirmed" {
		t.Fatalf("QUIC capabilities: %+v", h3)
	}
	for _, change := range []string{"expired", "future", "long-ttl", "endpoint", "transport-endpoint", "binding", "legacy", "warp", "unknown-transport"} {
		t.Run(change, func(t *testing.T) {
			receipt := good
			switch change {
			case "expired":
				receipt.ValidUntil = now.Format(time.RFC3339)
			case "future":
				receipt.CheckedAt = now.Add(time.Second).Format(time.RFC3339)
			case "long-ttl":
				receipt.ValidUntil = now.Add(time.Hour).Format(time.RFC3339)
			case "endpoint":
				receipt.Endpoint = "162.159.198.4:443"
			case "transport-endpoint":
				receipt.Endpoint = "162.159.198.2:443"
			case "binding":
				receipt.BindingID = strings.Repeat("b", 64)
			case "legacy":
				receipt.BindingID, receipt.ValidUntil = "", ""
			case "warp":
				receipt.Warp = "off"
			case "unknown-transport":
				receipt.Transport = "TCP"
			}
			got := EvaluateCanaryCapabilities(receipt, endpoints, binding, now)
			if got.Fresh || got.HTTP2 != "unknown" || got.HTTP3 != "unknown" || got.UDP != "unknown" {
				t.Fatalf("invalid receipt confirmed: %+v", got)
			}
		})
	}
	if CanaryBinding(digest, digest, digest, "") != "" {
		t.Fatal("missing network epoch accepted")
	}
}
