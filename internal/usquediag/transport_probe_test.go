package usquediag

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNativeTransportProbeRequiresTrustedOptInAndExactOptions(t *testing.T) {
	good := TransportProbeOptions{Enabled: true, URL: "https://proof.example/proof", Endpoint: netip.MustParseAddrPort("1.1.1.1:443"), Transport: "HTTP/2", Environment: func(context.Context) (string, error) { t.Fatal("invalid option reached callback"); return "", nil }}
	for _, mutation := range []string{"disabled", "private", "loopback", "wrong-port", "scheme", "query", "userinfo", "protocol", "timeout", "missing-environment"} {
		t.Run(mutation, func(t *testing.T) {
			options := good
			switch mutation {
			case "disabled":
				options.Enabled = false
			case "private":
				options.Endpoint = netip.MustParseAddrPort("192.168.1.1:443")
			case "loopback":
				options.Endpoint = netip.MustParseAddrPort("127.0.0.1:443")
			case "wrong-port":
				options.Endpoint = netip.MustParseAddrPort("1.1.1.1:8443")
			case "scheme":
				options.URL = "http://proof.example/proof"
			case "query":
				options.URL += "?private-token-marker=value"
			case "userinfo":
				options.URL = "https://private-token-marker@proof.example/proof"
			case "protocol":
				options.Transport = "auto"
			case "timeout":
				options.Timeout = time.Minute
			case "missing-environment":
				options.Environment = nil
			}
			result, err := ProbeNativeTransport(context.Background(), options)
			if err == nil || result.HTTP2 || result.HTTP3 || result.QUICUDP || result.verified || strings.Contains(err.Error(), "private-") {
				t.Fatal("invalid request allowed or secret leaked", result, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeNativeTransport(ctx, good); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	if TransportChallengeResponse("private-token-marker") != "" {
		t.Fatal("arbitrary challenge accepted")
	}
	declared := TransportProbeEvidence{HTTP2: true, HTTP3: true, QUICUDP: true, Endpoint: good.Endpoint.String(), EnvironmentID: strings.Repeat("a", 64), CheckedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute)}
	if declared.Fresh(time.Now(), good.Endpoint, declared.EnvironmentID) {
		t.Fatal("declared result became native evidence")
	}
}
