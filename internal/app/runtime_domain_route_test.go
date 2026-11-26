package app

import (
	"strings"
	"testing"
)

// A saved route that sends a domain service through a VPN is refused for
// good; the durable job says why and what to choose instead.
func TestRuntimeDomainRouteRefusalSaysWhatToDo(t *testing.T) {
	if !validRuntimeJobCode(serviceRuntimeDomainRoute) {
		t.Fatal("the domain-route refusal is not a durable runtime code")
	}
	j := durableServiceJob{State: "failed", RuntimeCode: serviceRuntimeDomainRoute}
	j.Request.Kind = "resume"
	message := runtimeJobMessage(j)
	for _, want := range []string{"задан доменами", "NFQWS2", "Telegram · через VPN или прокси", "Применить"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message lacks %q: %s", want, message)
		}
	}
}
