package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelectorReadsHonorCanceledHTTPRequest(t *testing.T) {
	for _, path := range []string{"/api/v1/routes/options", "/api/v1/services"} {
		t.Run(path, func(t *testing.T) {
			a, _, _ := nodeApplyFixture(t)
			probed := false
			a.FreshProfile = func(context.Context) (string, error) {
				probed = true
				return "", errors.New("canceled request must not start network observation")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
			w := httptest.NewRecorder()
			if path == "/api/v1/services" {
				a.services(w, r)
			} else {
				a.routeOptions(w, r)
			}
			if probed {
				t.Fatal("selector discarded request cancellation before reading node eligibility")
			}
		})
	}
}
