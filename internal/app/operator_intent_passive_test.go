package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A page load reads the plan passively; only a click on Apply/Install is
// intent. On the owner's router the passive read cancelled a running
// node recovery mid-activation and fenced the router.
func TestPassivePlanReadIsNotOperatorIntent(t *testing.T) {
	click := httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil)
	passive := httptest.NewRequest(http.MethodGet, "/api/v1/plan", nil)
	passive.Header.Set("X-Razvilka-Read", "passive")
	write := httptest.NewRequest(http.MethodPost, "/api/v1/apply", nil)
	write.Header.Set("X-Razvilka-Read", "passive")
	if !operatorIntent(click) || operatorIntent(passive) || !operatorIntent(write) {
		t.Fatal(operatorIntent(click), operatorIntent(passive), operatorIntent(write))
	}
}
