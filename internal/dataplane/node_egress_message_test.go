package dataplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNodeEgressFailureMessageExplainsOnlyClosedCategory(t *testing.T) {
	for _, category := range []string{"socks_connect", "tcp_connect", "tls_handshake", "certificate", "http_status", "timeout", "body_parse", "http_transport", "dial_timeout", "tls_timeout", "response_timeout"} {
		t.Run(category, func(t *testing.T) {
			c := fakeExactNodeChecker(t)
			c.proxyEgress = func(context.Context, string) (string, error) { return "", nodeEgressFailure(category) }
			result, err := c.Check(context.Background(), checkedNodeRequest())
			if err != nil || result.Available || result.ErrorCode != "node-egress-failed" || result.Stage != "egress" || result.TestLevel != "protocol" || result.DirectControl != "measured" || result.ProxyEgressError != category {
				t.Fatalf("explanation changed refusal: %+v %v", result, err)
			}
			if result.Message == "Точный выход через узел не подтвердился." || utf8.RuneCountInString(result.Message) > 240 {
				t.Fatal("closed category was not safely explained", result.Message)
			}
			if result.Message != nodeEgressFailureMessage(category, "sing-box") {
				t.Fatal("Sing-box check did not explain its own engine's category", result.Message)
			}
		})
	}
	for _, engine := range []string{"sing-box", "xray", ""} {
		for _, category := range []string{"", "unavailable", "canceled", "private-profile-marker https://user:secret@private.example/"} {
			message := nodeEgressFailureMessage(category, engine)
			data, _ := json.Marshal(message)
			if message != "Точный выход через узел не подтвердился." || strings.Contains(string(data), "private") || strings.Contains(string(data), "secret") {
				t.Fatal("unknown diagnostic escaped closed message boundary")
			}
		}
	}
}
